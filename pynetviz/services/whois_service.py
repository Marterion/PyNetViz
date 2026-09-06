from __future__ import annotations

import logging
import threading
from collections import OrderedDict

import requests

from pynetviz.utils.netaddrs import is_non_public_ip

logger = logging.getLogger(__name__)


class WhoisService:
    """WHOIS lookup via public API."""

    def __init__(self, cache_size: int = 256) -> None:
        self.allow_external = True  # privacy mode can disable remote API
        self._lock = threading.Lock()
        self._cache: OrderedDict[str, dict] = OrderedDict()
        self._cache_size = cache_size

    def lookup(self, ip: str) -> dict:
        if is_non_public_ip(ip):
            return {"ip": ip, "org": "Localhost", "country": "N/A", "source": "local"}

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

        if not self.allow_external:
            return {
                "ip": ip,
                "org": "Blocked (strict privacy)",
                "country": "N/A",
                "source": "blocked",
            }

        try:
            resp = requests.get(
                f"https://ipwho.is/{ip}",
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json()
            if data.get("success", True):
                return {
                    "ip": ip,
                    "org": data.get("org") or data.get("isp") or "Unknown",
                    "country": data.get("country") or "Unknown",
                    "asn": data.get("asn", ""),
                    "source": "ipwho.is",
                }
        except Exception as exc:
            logger.debug("WHOIS lookup failed for %s: %s", ip, exc)

        return {"ip": ip, "org": "Unknown", "country": "Unknown", "source": "none"}

    def lookup_async(self, ip: str, callback) -> None:
        def worker() -> None:
            callback(self.lookup(ip))

        threading.Thread(target=worker, daemon=True).start()