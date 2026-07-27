"""Template network digest: “what is my PC doing?”"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from pynetviz.models.connection import ConnectionRecord, DashboardStats, ProcessSummary


@dataclass
class NetworkDigest:
    generated_at: datetime
    headline: str
    bullets: list[str] = field(default_factory=list)
    top_processes: list[tuple[str, int]] = field(default_factory=list)
    high_risk: list[tuple[str, int, str]] = field(default_factory=list)  # name, score, reason
    new_processes: list[str] = field(default_factory=list)
    new_remotes: list[str] = field(default_factory=list)
    listening: int = 0
    established: int = 0
    total: int = 0

    def as_text(self) -> str:
        lines = [self.headline, ""]
        lines.extend(f"• {b}" for b in self.bullets)
        return "\n".join(lines)


def build_digest(
    records: list[ConnectionRecord],
    stats: DashboardStats,
    processes: list[ProcessSummary],
    *,
    new_process_names: Optional[list[str]] = None,
    new_remotes: Optional[list[str]] = None,
    now: Optional[datetime] = None,
) -> NetworkDigest:
    now = now or datetime.now()
    new_process_names = new_process_names or []
    new_remotes = new_remotes or []

    active = [
        r
        for r in records
        if (r.state or "").upper() not in {"", "NONE"} or r.protocol.upper() == "UDP"
    ]
    by_proc = Counter(r.process_name for r in active if r.process_name)
    top = by_proc.most_common(5)
    if not top and stats.top_processes:
        top = list(stats.top_processes[:5])

    high = sorted(
        [r for r in records if r.risk_score >= 55],
        key=lambda r: r.risk_score,
        reverse=True,
    )[:5]
    high_tuples = [
        (
            r.process_name,
            r.risk_score,
            (r.risk_reasons[0] if r.risk_reasons else "elevated"),
        )
        for r in high
    ]

    talker = top[0][0] if top else "—"
    talker_n = top[0][1] if top else 0
    headline = (
        f"{stats.total_connections} connections · {len(processes)} processes online · "
        f"top talker {talker} ({talker_n})"
    )

    bullets: list[str] = []
    if top:
        bullets.append(
            "Top: " + ", ".join(f"{n} ({c})" for n, c in top[:4])
        )
    bullets.append(
        f"Established {stats.established_connections} · listening {stats.listening_ports} · "
        f"↑ {stats.upload_bps / 1024:.1f} KB/s ↓ {stats.download_bps / 1024:.1f} KB/s"
    )
    if new_process_names:
        bullets.append(
            "New on network: " + ", ".join(new_process_names[:5])
        )
    if new_remotes:
        bullets.append("New remotes: " + ", ".join(new_remotes[:5]))
    if high_tuples:
        bullets.append(
            "Elevated risk: "
            + ", ".join(f"{n} ({s})" for n, s, _ in high_tuples[:3])
        )
    if not bullets:
        bullets.append("Waiting for network activity…")

    return NetworkDigest(
        generated_at=now,
        headline=headline,
        bullets=bullets,
        top_processes=top,
        high_risk=high_tuples,
        new_processes=list(new_process_names[:10]),
        new_remotes=list(new_remotes[:10]),
        listening=stats.listening_ports,
        established=stats.established_connections,
        total=stats.total_connections,
    )
