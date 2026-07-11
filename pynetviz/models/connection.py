from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class ConnectionDirection(str, Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    LISTEN = "listen"
    UNKNOWN = "unknown"


class RowHighlight(str, Enum):
    NONE = "none"
    NEW = "new"
    CLOSING = "closing"


SUSPICIOUS_PORTS = frozenset(
    {
        4444, 5555, 6666, 6667, 31337, 12345, 27374, 1337, 9001, 9050,
        3389, 5900, 23, 135, 139, 445,
    }
)


@dataclass
class ConnectionRecord:
    pid: int
    process_name: str
    executable_path: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    protocol: str
    state: str
    direction: ConnectionDirection
    hostname: str
    last_seen: datetime
    bytes_sent: int
    bytes_recv: int
    is_unknown_process: bool = False
    highlight: RowHighlight = RowHighlight.NONE
    row_color: str = ""
    connection_key: str = ""

    @property
    def local_endpoint(self) -> str:
        return f"{self.local_addr}:{self.local_port}"

    @property
    def remote_endpoint(self) -> str:
        if self.remote_addr in ("", "0.0.0.0", "::", "*"):
            return "*:*"
        return f"{self.remote_addr}:{self.remote_port}"

    @property
    def is_suspicious(self) -> bool:
        ports = {self.local_port, self.remote_port}
        return bool(ports & SUSPICIOUS_PORTS)

    def compute_row_color(self) -> str:
        if self.is_suspicious or self.is_unknown_process:
            return "#E53935"
        state_upper = self.state.upper()
        if state_upper == "LISTEN":
            return "#42A5F5"
        if self.direction == ConnectionDirection.INBOUND:
            return "#FB8C00"
        if state_upper in {"ESTABLISHED", "SYN_SENT", "SYN_RECV"}:
            return "#66BB6A"
        return "#B0BEC5"


@dataclass
class ProcessSummary:
    pid: int
    name: str
    executable_path: str
    connection_count: int
    bytes_sent: int
    bytes_recv: int
    cpu_percent: float = 0.0
    memory_mb: float = 0.0


@dataclass
class DashboardStats:
    total_connections: int = 0
    listening_ports: int = 0
    established_connections: int = 0
    upload_bps: float = 0.0
    download_bps: float = 0.0
    top_processes: list[tuple[str, int]] = field(default_factory=list)
    connection_history: list[tuple[datetime, int]] = field(default_factory=list)
    bandwidth_history: list[tuple[datetime, float, float]] = field(default_factory=list)
    permission_warning: Optional[str] = None