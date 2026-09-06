from __future__ import annotations

import logging
import socket
import threading
import time
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from typing import Callable, Optional

import psutil

from pynetviz.collector.bandwidth_tracker import BandwidthTracker
from pynetviz.models.connection import (
    ConnectionDirection,
    ConnectionRecord,
    DashboardStats,
    ProcessSummary,
    RowHighlight,
)
from pynetviz.services.dns_resolver import DNSResolver
from pynetviz.utils.netaddrs import is_unspecified_addr

logger = logging.getLogger(__name__)

# How long to keep disconnected rows visible (CLOSING highlight) before drop.
CLOSING_TTL_S = 3.0
_HOST_IP_TTL_S = 30.0

_cached_host_ip = ""
_cached_host_ip_at = 0.0


def _host_ipv4() -> str:
    """Cached local IPv4 used to replace 0.0.0.0 / :: on listen sockets."""
    global _cached_host_ip, _cached_host_ip_at
    now = time.monotonic()
    if _cached_host_ip and (now - _cached_host_ip_at) < _HOST_IP_TTL_S:
        return _cached_host_ip
    try:
        _cached_host_ip = socket.gethostbyname(socket.gethostname())
        _cached_host_ip_at = now
    except OSError:
        pass
    return _cached_host_ip


def _format_addr(addr) -> tuple[str, int]:
    if not addr:
        return "", 0
    ip = addr.ip if hasattr(addr, "ip") else str(addr[0])
    port = addr.port if hasattr(addr, "port") else int(addr[1])
    if ip in ("0.0.0.0", "::"):
        host_ip = _host_ipv4()
        if host_ip:
            ip = host_ip
    return ip, port


def _infer_direction(
    local_port: int, remote_addr: str, remote_port: int, state: str
) -> ConnectionDirection:
    state_upper = (state or "").upper()
    if state_upper == "LISTEN" or is_unspecified_addr(remote_addr) or remote_port == 0:
        return ConnectionDirection.LISTEN
    if local_port < remote_port and state_upper in {"ESTABLISHED", "SYN_SENT"}:
        return ConnectionDirection.OUTBOUND
    if remote_port < local_port and state_upper == "ESTABLISHED":
        return ConnectionDirection.INBOUND
    if state_upper in {"SYN_RECV", "ESTABLISHED"}:
        return ConnectionDirection.INBOUND
    return ConnectionDirection.UNKNOWN


class ConnectionCollector:
    """Background collector polling psutil for live network connections."""

    def __init__(
        self,
        poll_interval: float = 0.4,
        on_update: Optional[
            Callable[[list[ConnectionRecord], DashboardStats, list[ProcessSummary]], None]
        ] = None,
    ) -> None:
        self.poll_interval = poll_interval
        self.on_update = on_update
        self.dns = DNSResolver()
        self.bandwidth = BandwidthTracker()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._connections: dict[str, ConnectionRecord] = {}
        self._connection_bytes: dict[str, tuple[int, int]] = {}
        self._process_cache: dict[int, tuple[str, str]] = {}
        self._ps_procs: dict[int, psutil.Process] = {}
        self._connection_history: deque[tuple[datetime, int]] = deque(maxlen=300)
        self._permission_warning: Optional[str] = None
        self._closing_since: dict[str, datetime] = {}

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="ConnectionCollector", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        self.dns.shutdown()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                records, stats, processes = self._collect()
                if self.on_update:
                    self.on_update(records, stats, processes)
            except Exception:
                logger.exception("Collector poll failed")
            self._stop.wait(self.poll_interval)

    def _psutil_proc(self, pid: int) -> Optional[psutil.Process]:
        if pid <= 0:
            return None
        proc = self._ps_procs.get(pid)
        if proc is not None:
            return proc
        try:
            proc = psutil.Process(pid)
            self._ps_procs[pid] = proc
            return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

    def _get_process_info(self, pid: int) -> tuple[str, str, bool]:
        if pid <= 0:
            return "System", "", True
        cached = self._process_cache.get(pid)
        if cached is not None:
            return cached[0], cached[1], False
        proc = self._psutil_proc(pid)
        if proc is None:
            return f"PID {pid}", "", True
        try:
            name = proc.name()
            try:
                path = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                path = ""
            self._process_cache[pid] = (name, path)
            return name, path, False
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            self._ps_procs.pop(pid, None)
            return f"PID {pid}", "", True

    def _collect(self) -> tuple[list[ConnectionRecord], DashboardStats, list[ProcessSummary]]:
        now = datetime.now()
        self.bandwidth.update()
        current_keys: set[str] = set()
        permission_errors = 0
        raw_connections = []

        try:
            raw_connections.extend(psutil.net_connections(kind="inet"))
        except psutil.AccessDenied:
            permission_errors += 1
        except Exception as exc:
            logger.warning("net_connections failed: %s", exc)

        self._permission_warning = (
            "Limited visibility: run as administrator/root for full connection data."
            if permission_errors
            else None
        )

        active_pids: set[int] = set()
        process_conn_counts: Counter[int] = Counter()
        process_byte_totals: dict[int, list[int]] = defaultdict(lambda: [0, 0])
        pid_io_delta: dict[int, tuple[int, int]] = {}

        for conn in raw_connections:
            pid = conn.pid or 0
            active_pids.add(pid)
            process_conn_counts[pid] += 1

        for pid in active_pids:
            proc = self._psutil_proc(pid)
            if proc is None:
                pid_io_delta[pid] = (0, 0)
                continue
            try:
                io = proc.io_counters()
                pid_io_delta[pid] = self.bandwidth.update_process_io(
                    pid, io.write_bytes, io.read_bytes
                )
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                pid_io_delta[pid] = (0, 0)
                self._ps_procs.pop(pid, None)

        for conn in raw_connections:
            pid = conn.pid or 0
            local_addr, local_port = _format_addr(conn.laddr)
            remote_addr, remote_port = _format_addr(conn.raddr)
            protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            state = conn.status if conn.status else ("NONE" if protocol == "UDP" else "UNKNOWN")
            direction = _infer_direction(local_port, remote_addr, remote_port, state)

            # 5-tuple only — state changes update the same row instead of duplicating it.
            key = f"{pid}|{protocol}|{local_addr}:{local_port}|{remote_addr}:{remote_port}"
            current_keys.add(key)

            process_name, executable_path, is_unknown = self._get_process_info(pid)

            prev_bytes = self._connection_bytes.get(key, (0, 0))
            if pid > 0:
                delta_sent, delta_recv = pid_io_delta.get(pid, (0, 0))
                share = 1 / max(process_conn_counts[pid], 1)
                sent = prev_bytes[0] + int(delta_sent * share)
                recv = prev_bytes[1] + int(delta_recv * share)
            else:
                sent, recv = prev_bytes

            self._connection_bytes[key] = (sent, recv)
            process_byte_totals[pid][0] += sent
            process_byte_totals[pid][1] += recv

            hostname = self.dns.get(remote_addr) if remote_addr else ""

            prev = self._connections.get(key)
            highlight = RowHighlight.NEW if prev is None else RowHighlight.NONE

            record = ConnectionRecord(
                pid=pid,
                process_name=process_name,
                executable_path=executable_path,
                local_addr=local_addr,
                local_port=local_port,
                remote_addr=remote_addr,
                remote_port=remote_port,
                protocol=protocol,
                state=state,
                direction=direction,
                hostname=hostname,
                last_seen=now,
                bytes_sent=sent,
                bytes_recv=recv,
                is_unknown_process=is_unknown,
                highlight=highlight,
                connection_key=key,
            )
            record.row_color = record.compute_row_color()
            self._connections[key] = record

        for key in current_keys:
            self._closing_since.pop(key, None)

        stale_keys = set(self._connections) - current_keys
        for key in stale_keys:
            record = self._connections[key]
            first = self._closing_since.get(key)
            if first is None:
                self._closing_since[key] = now
                record.highlight = RowHighlight.CLOSING
                record.last_seen = now
            elif (now - first).total_seconds() >= CLOSING_TTL_S:
                del self._connections[key]
                self._closing_since.pop(key, None)
                self._connection_bytes.pop(key, None)
            else:
                record.highlight = RowHighlight.CLOSING

        self.bandwidth.prune_processes(active_pids)
        stale_byte_keys = set(self._connection_bytes) - set(self._connections)
        for key in stale_byte_keys:
            del self._connection_bytes[key]
        if len(self._process_cache) > len(active_pids) + 16:
            for pid in list(self._process_cache.keys()):
                if pid not in active_pids:
                    del self._process_cache[pid]
            for pid in list(self._ps_procs.keys()):
                if pid not in active_pids:
                    del self._ps_procs[pid]

        records = list(self._connections.values())
        records.sort(key=lambda r: r.last_seen, reverse=True)

        self._connection_history.append((now, len(current_keys)))
        cutoff = now - timedelta(seconds=300)
        while self._connection_history and self._connection_history[0][0] < cutoff:
            self._connection_history.popleft()
        self.bandwidth.trim_history()

        listening = 0
        established = 0
        proc_counter: Counter[str] = Counter()
        for k in current_keys:
            rec = self._connections[k]
            state_u = rec.state.upper()
            if state_u == "LISTEN":
                listening += 1
            elif state_u == "ESTABLISHED":
                established += 1
            proc_counter[rec.process_name] += 1

        stats = DashboardStats(
            total_connections=len(current_keys),
            listening_ports=listening,
            established_connections=established,
            upload_bps=self.bandwidth.upload_bps,
            download_bps=self.bandwidth.download_bps,
            top_processes=proc_counter.most_common(10),
            connection_history=list(self._connection_history),
            bandwidth_history=list(self.bandwidth.bandwidth_history),
            permission_warning=self._permission_warning,
        )

        processes: list[ProcessSummary] = []
        ranked_pids = sorted(
            process_conn_counts.items(), key=lambda x: x[1], reverse=True
        )
        rich_metric_pids = {pid for pid, _ in ranked_pids[:40] if pid > 0}
        for pid, count in ranked_pids:
            name, path, _ = self._get_process_info(pid)
            cpu = 0.0
            mem_mb = 0.0
            if pid in rich_metric_pids:
                proc = self._psutil_proc(pid)
                if proc is not None:
                    try:
                        with proc.oneshot():
                            cpu = proc.cpu_percent(interval=None)
                            mem_mb = proc.memory_info().rss / (1024 * 1024)
                    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                        self._ps_procs.pop(pid, None)
            totals = process_byte_totals[pid]
            processes.append(
                ProcessSummary(
                    pid=pid,
                    name=name,
                    executable_path=path,
                    connection_count=count,
                    bytes_sent=totals[0],
                    bytes_recv=totals[1],
                    cpu_percent=cpu,
                    memory_mb=mem_mb,
                )
            )

        return records, stats, processes

    def get_process_detail(self, pid: int) -> dict:
        if pid <= 0:
            return {"pid": 0, "name": "System", "path": "", "cpu": 0.0, "memory_mb": 0.0}
        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                return {
                    "pid": pid,
                    "name": proc.name(),
                    "path": proc.exe() if hasattr(proc, "exe") else "",
                    "cpu": proc.cpu_percent(interval=None),
                    "memory_mb": proc.memory_info().rss / (1024 * 1024),
                    "status": proc.status(),
                    "username": proc.username() if hasattr(proc, "username") else "",
                    "create_time": datetime.fromtimestamp(proc.create_time()).isoformat(),
                    "num_threads": proc.num_threads(),
                }
        except (psutil.AccessDenied, psutil.NoSuchProcess) as exc:
            return {"pid": pid, "error": str(exc)}
