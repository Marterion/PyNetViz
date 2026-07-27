"""Dashboard / insights aggregates derived from live connection snapshots."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Optional, Sequence

from pynetviz.models.connection import (
    ConnectionDirection,
    ConnectionRecord,
    DashboardStats,
    ProcessSummary,
)


@dataclass
class ProtocolMix:
    tcp: int = 0
    udp: int = 0
    other: int = 0

    @property
    def total(self) -> int:
        return self.tcp + self.udp + self.other

    def as_pairs(self) -> list[tuple[str, int]]:
        pairs = [("TCP", self.tcp), ("UDP", self.udp)]
        if self.other:
            pairs.append(("Other", self.other))
        return [(n, c) for n, c in pairs if c > 0]


@dataclass
class DirectionMix:
    outbound: int = 0
    inbound: int = 0
    listen: int = 0
    unknown: int = 0

    def as_pairs(self) -> list[tuple[str, int]]:
        return [
            (n, c)
            for n, c in (
                ("Outbound", self.outbound),
                ("Inbound", self.inbound),
                ("Listen", self.listen),
                ("Unknown", self.unknown),
            )
            if c > 0
        ]


@dataclass
class RiskBucket:
    low: int = 0  # 0-39
    medium: int = 0  # 40-54
    elevated: int = 0  # 55-74
    high: int = 0  # 75+

    def as_pairs(self) -> list[tuple[str, int]]:
        return [
            (n, c)
            for n, c in (
                ("Low", self.low),
                ("Medium", self.medium),
                ("Elevated", self.elevated),
                ("High", self.high),
            )
            if c > 0
        ]


@dataclass
class NetworkAggregates:
    protocol: ProtocolMix = field(default_factory=ProtocolMix)
    direction: DirectionMix = field(default_factory=DirectionMix)
    risk: RiskBucket = field(default_factory=RiskBucket)
    unique_remotes: int = 0
    unique_processes: int = 0
    top_remotes: list[tuple[str, int]] = field(default_factory=list)
    top_ports: list[tuple[int, int]] = field(default_factory=list)
    suspicious_count: int = 0
    established: int = 0
    listening: int = 0


def _dir_bucket(record: ConnectionRecord) -> str:
    d = record.direction
    if d == ConnectionDirection.OUTBOUND or getattr(d, "value", "") == "outbound":
        return "outbound"
    if d == ConnectionDirection.INBOUND or getattr(d, "value", "") == "inbound":
        return "inbound"
    if d == ConnectionDirection.LISTEN or getattr(d, "value", "") == "listen":
        return "listen"
    return "unknown"


def build_aggregates(
    records: Sequence[ConnectionRecord],
    *,
    top_n: int = 8,
) -> NetworkAggregates:
    agg = NetworkAggregates()
    remotes: Counter[str] = Counter()
    ports: Counter[int] = Counter()
    processes: set[str] = set()
    remote_set: set[str] = set()

    for r in records:
        proto = (r.protocol or "").upper()
        if proto == "TCP":
            agg.protocol.tcp += 1
        elif proto == "UDP":
            agg.protocol.udp += 1
        else:
            agg.protocol.other += 1

        bucket = _dir_bucket(r)
        if bucket == "outbound":
            agg.direction.outbound += 1
        elif bucket == "inbound":
            agg.direction.inbound += 1
        elif bucket == "listen":
            agg.direction.listen += 1
        else:
            agg.direction.unknown += 1

        try:
            score = int(r.risk_score or 0)
        except (TypeError, ValueError):
            score = 0
        if score >= 75:
            agg.risk.high += 1
        elif score >= 55:
            agg.risk.elevated += 1
        elif score >= 40:
            agg.risk.medium += 1
        else:
            agg.risk.low += 1

        if r.is_suspicious:
            agg.suspicious_count += 1

        state = (r.state or "").upper()
        if state == "LISTEN" or bucket == "listen":
            agg.listening += 1
        if state in {"ESTABLISHED", "SYN_SENT", "SYN_RECV"}:
            agg.established += 1

        processes.add((r.process_name or f"pid:{r.pid}").lower())
        if r.remote_addr and r.remote_addr not in ("", "0.0.0.0", "::", "*"):
            key = f"{r.remote_addr}:{r.remote_port}"
            remotes[key] += 1
            remote_set.add(r.remote_addr)
            if r.remote_port:
                ports[int(r.remote_port)] += 1

    agg.unique_remotes = len(remote_set)
    agg.unique_processes = len(processes)
    agg.top_remotes = remotes.most_common(top_n)
    agg.top_ports = ports.most_common(top_n)
    return agg


def merge_stats_headline(
    stats: DashboardStats,
    agg: Optional[NetworkAggregates] = None,
) -> str:
    """One-line status for header / tray."""
    parts = [f"{stats.total_connections} conn"]
    if agg and agg.suspicious_count:
        parts.append(f"{agg.suspicious_count} risk")
    return " · ".join(parts)
