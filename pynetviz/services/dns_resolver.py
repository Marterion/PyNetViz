from __future__ import annotations

import atexit
import socket
import threading
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

from pynetviz.utils.netaddrs import LOOPBACK_ADDRS, is_unspecified_addr


def _is_local_ip(ip: str) -> bool:
    return is_unspecified_addr(ip) or ip in LOOPBACK_ADDRS


class DNSResolver:
    """Reverse DNS resolver with LRU cache and a bounded worker pool."""

    def __init__(self, cache_size: int = 4096, timeout: float = 2.0) -> None:
        self._cache: OrderedDict[str, str] = OrderedDict()
        self._pending: set[str] = set()
        self._lock = threading.Lock()
        self._cache_size = cache_size
        self._timeout = timeout
        self._pool: Optional[ThreadPoolExecutor] = ThreadPoolExecutor(
            max_workers=6,
            thread_name_prefix="pynetviz-dns",
        )
        atexit.register(self.shutdown)

    def shutdown(self) -> None:
        pool = self._pool
        if pool is None:
            return
        self._pool = None
        try:
            pool.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass

    def _store(self, ip: str, hostname: str) -> None:
        with self._lock:
            self._cache[ip] = hostname
            self._cache.move_to_end(ip)
            while len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)

    def _resolve_blocking(self, ip: str) -> str:
        if _is_local_ip(ip):
            return ip
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(self._timeout)
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                return hostname
            finally:
                socket.setdefaulttimeout(old_timeout)
        except (socket.herror, socket.gaierror, OSError, socket.timeout, TimeoutError):
            return ip

    def _resolve_worker(self, ip: str) -> None:
        try:
            hostname = self._resolve_blocking(ip)
            self._store(ip, hostname)
        finally:
            with self._lock:
                self._pending.discard(ip)

    def get(self, ip: str) -> str:
        """Return cached hostname immediately, or IP while resolving in background."""
        if _is_local_ip(ip):
            return ip
        with self._lock:
            if ip in self._cache:
                self._cache.move_to_end(ip)
                return self._cache[ip]
            if ip in self._pending or self._pool is None:
                return ip
            self._pending.add(ip)
            self._pool.submit(self._resolve_worker, ip)
        return ip

    def resolve(self, ip: str) -> str:
        """Blocking resolve — use sparingly; prefer get() in hot paths."""
        if _is_local_ip(ip):
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

        pool = self._pool
        if pool is None:
            threading.Thread(target=worker, daemon=True).start()
            return
        pool.submit(worker)

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
