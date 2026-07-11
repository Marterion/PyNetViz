from __future__ import annotations

import socket
import threading
from collections import OrderedDict
from typing import Callable, Optional

_LOCAL_IPS = frozenset({"0.0.0.0", "::", "*", "127.0.0.1", "::1"})


class DNSResolver:
    """Reverse DNS resolver with LRU cache and non-blocking background resolution."""

    def __init__(self, cache_size: int = 4096, timeout: float = 2.0) -> None:
        self._cache: OrderedDict[str, str] = OrderedDict()
        self._pending: set[str] = set()
        self._lock = threading.Lock()
        self._cache_size = cache_size
        self._timeout = timeout

    def _store(self, ip: str, hostname: str) -> None:
        with self._lock:
            self._cache[ip] = hostname
            self._cache.move_to_end(ip)
            while len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)

    def _resolve_blocking(self, ip: str) -> str:
        if not ip or ip in _LOCAL_IPS:
            return ip
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(self._timeout)
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                return hostname
            finally:
                socket.setdefaulttimeout(old_timeout)
        except (socket.herror, socket.gaierror, OSError, socket.timeout):
            return ip

    def _resolve_worker(self, ip: str) -> None:
        hostname = self._resolve_blocking(ip)
        with self._lock:
            self._pending.discard(ip)
        self._store(ip, hostname)

    def get(self, ip: str) -> str:
        """Return cached hostname immediately, or IP while resolving in background."""
        if not ip or ip in _LOCAL_IPS:
            return ip
        with self._lock:
            if ip in self._cache:
                self._cache.move_to_end(ip)
                return self._cache[ip]
            if ip not in self._pending:
                self._pending.add(ip)
                threading.Thread(
                    target=self._resolve_worker,
                    args=(ip,),
                    name=f"dns-{ip}",
                    daemon=True,
                ).start()
        return ip

    def resolve(self, ip: str) -> str:
        """Blocking resolve — use sparingly; prefer get() in hot paths."""
        if not ip or ip in _LOCAL_IPS:
            return ip
        with self._lock:
            if ip in self._cache:
                self._cache.move_to_end(ip)
                return self._cache[ip]
        hostname = self._resolve_blocking(ip)
        self._store(ip, hostname)
        return hostname

    def resolve_async(self, ip: str, callback: Callable[[str, str], None]) -> None:
        def worker() -> None:
            result = self.resolve(ip)
            callback(ip, result)

        threading.Thread(target=worker, daemon=True).start()

    def clear_cache(self) -> None:
        with self._lock:
            self._cache.clear()
            self._pending.clear()

    def cached_hostname(self, ip: str) -> Optional[str]:
        with self._lock:
            hostname = self._cache.get(ip)
            if hostname and hostname != ip:
                return hostname
        return None