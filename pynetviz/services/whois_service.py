from __future__ import annotations

import logging
import threading

import requests

logger = logging.getLogger(__name__)


class WhoisService:
    """WHOIS lookup via public API."""

    def __init__(self) -> None:
        self.allow_external = True  # privacy mode can disable remote API

    def lookup(self, ip: str) -> dict:
        if not ip or ip.startswith("127.") or ip == "::1":
            return {"ip": ip, "org": "Localhost", "country": "N/A", "source": "local"}

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