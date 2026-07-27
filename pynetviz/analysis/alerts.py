"""Alert manager: produces tray-visible alerts from analysis events."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Callable, Optional

from pynetviz.analysis.store import AnalysisStore
from pynetviz.models.connection import ConnectionRecord

logger = logging.getLogger(__name__)


class AlertLevel(str, Enum):
    INFO = "info"
    WARN = "warn"
    HIGH = "high"


@dataclass
class Alert:
    id: Optional[int]
    ts: str
    level: str
    title: str
    body: str
    fingerprint: str = ""
    read: bool = False

    @classmethod
    def from_row(cls, row: dict) -> "Alert":
        return cls(
            id=row.get("id"),
            ts=str(row.get("ts", "")),
            level=str(row.get("level", "info")),
            title=str(row.get("title", "")),
            body=str(row.get("body", "")),
            fingerprint=str(row.get("fingerprint") or ""),
            read=bool(row.get("read")),
        )


class AlertManager:
    def __init__(
        self,
        store: AnalysisStore,
        *,
        enabled: bool = True,
        min_score: int = 55,
        on_alert: Optional[Callable[[Alert], None]] = None,
    ) -> None:
        self.store = store
        self.enabled = enabled
        self.min_score = min_score
        self.on_alert = on_alert

    def configure(self, *, enabled: Optional[bool] = None, min_score: Optional[int] = None) -> None:
        if enabled is not None:
            self.enabled = enabled
        if min_score is not None:
            self.min_score = int(min_score)

    def emit(
        self,
        level: AlertLevel,
        title: str,
        body: str,
        fingerprint: str,
    ) -> Optional[Alert]:
        """Public alert insert (deduped by fingerprint in the store)."""
        return self._emit(level, title, body, fingerprint)

    def _emit(
        self,
        level: AlertLevel,
        title: str,
        body: str,
        fingerprint: str,
    ) -> Optional[Alert]:
        if not self.enabled:
            return None
        new_id = self.store.add_alert(
            level=level.value,
            title=title,
            body=body,
            fingerprint=fingerprint,
        )
        if new_id is None:
            return None
        alert = Alert(
            id=new_id,
            ts=datetime.now().isoformat(timespec="seconds"),
            level=level.value,
            title=title,
            body=body,
            fingerprint=fingerprint,
            read=False,
        )
        if self.on_alert:
            try:
                self.on_alert(alert)
            except Exception:
                logger.debug("on_alert callback failed", exc_info=True)
        return alert

    def on_new_process(self, name: str, pid: int) -> Optional[Alert]:
        return self._emit(
            AlertLevel.INFO,
            "New process on network",
            f"{name} (PID {pid}) opened network connections for the first time.",
            fingerprint=f"new_proc:{name.lower()}",
        )

    def on_new_remote(self, process_name: str, remote: str, port: int) -> Optional[Alert]:
        return self._emit(
            AlertLevel.WARN,
            "New remote host",
            f"{process_name} connected to {remote}:{port} (first seen).",
            fingerprint=f"new_remote:{remote}:{port}",
        )

    def on_high_risk(self, record: ConnectionRecord) -> Optional[Alert]:
        if record.risk_score < self.min_score:
            return None
        reasons = ", ".join(record.risk_reasons[:3]) or "elevated score"
        level = AlertLevel.HIGH if record.risk_score >= 75 else AlertLevel.WARN
        return self._emit(
            level,
            f"Risk {record.risk_score}: {record.process_name}",
            f"{record.remote_endpoint} · {reasons}",
            fingerprint=f"risk:{record.process_name}:{record.remote_addr}:{record.remote_port}:{record.risk_score // 10}",
        )

    def list_recent(self, limit: int = 40) -> list[Alert]:
        return [Alert.from_row(r) for r in self.store.recent_alerts(limit=limit)]

    def unread_count(self) -> int:
        return self.store.unread_alert_count()

    def mark_all_read(self) -> None:
        self.store.mark_alerts_read()
