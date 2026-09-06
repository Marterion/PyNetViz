from __future__ import annotations

import logging
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Optional

import requests

from pynetviz.utils.netaddrs import is_non_public_ip

logger = logging.getLogger(__name__)


class GeoIPService:
    """GeoIP lookup via MaxMind GeoLite2 database or ip-api.com fallback."""

    def __init__(self, db_path: Optional[str] = None, cache_size: int = 512) -> None:
        self._reader = None
        self._lock = threading.Lock()
        self._cache: OrderedDict[str, dict] = OrderedDict()
        self._cache_size = cache_size
        self.allow_external = True  # privacy mode can disable API fallback
        self._init_reader(db_path)

    def _init_reader(self, db_path: Optional[str]) -> None:
        candidates = []
        if db_path:
            candidates.append(Path(db_path))
        candidates.extend(
            [
                Path.home() / ".pynetviz" / "GeoLite2-City.mmdb",
                Path("data") / "GeoLite2-City.mmdb",
            ]
        )
        for path in candidates:
            if path.exists():
                try:
                    import geoip2.database

                    self._reader = geoip2.database.Reader(str(path))
                    logger.info("GeoIP database loaded: %s", path)
                    return
                except Exception as exc:
                    logger.warning("Failed to load GeoIP DB %s: %s", path, exc)

    def lookup(self, ip: str) -> dict:
        if is_non_public_ip(ip):
            return {"ip": ip, "country": "Local", "city": "Localhost", "source": "local"}

        with self._lock:
            cached = self._cache.get(ip)
            if cached is not None:
                self._cache.move_to_end(ip)
                return cached

        result = self._lookup_uncached(ip)
        with self._lock:
            self._cache[ip] = result
            self._cache.move_to_end(ip)
            while len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)
        return result

    def _lookup_uncached(self, ip: str) -> dict:
        with self._lock:
            reader = self._reader
            if reader:
                try:
                    response = reader.city(ip)
                    return {
                        "ip": ip,
                        "country": response.country.name or "Unknown",
                        "city": response.city.name or "Unknown",
                        "source": "maxmind",
                    }
                except Exception:
                    pass

        if not self.allow_external:
            return {
                "ip": ip,
                "country": "Unavailable",
                "city": "Strict privacy mode",
                "source": "blocked",
            }
        return self._lookup_api(ip)

    def _lookup_api(self, ip: str) -> dict:
        try:
            resp = requests.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,country,city,query"},
                timeout=4,
            )
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "ip": ip,
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "source": "ip-api",
                }
        except Exception as exc:
            logger.debug("GeoIP API fallback failed for %s: %s", ip, exc)

        return {"ip": ip, "country": "Unknown", "city": "Unknown", "source": "none"}

    def lookup_async(self, ip: str, callback) -> None:
        def worker() -> None:
            callback(self.lookup(ip))

        threading.Thread(target=worker, daemon=True).start()