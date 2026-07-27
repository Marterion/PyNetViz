"""Security monitoring engine — orchestrates 8 ops-center detectors."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from pynetviz.analysis.alerts import Alert, AlertLevel, AlertManager
from pynetviz.models.connection import ConnectionRecord, DashboardStats, ProcessSummary
from pynetviz.security import detectors

logger = logging.getLogger(__name__)

# How often expensive OS probes run (ARP/WiFi/files/proxy).
PROBE_INTERVAL_S = 4.0


@dataclass
class MonitorSnapshot:
    """UI-facing status for one detector."""

    id: str
    name: str
    description: str
    enabled: bool
    status: str  # ok | watch | alert | idle | error
    summary: str
    last_check: str
    findings: list[dict[str, str]] = field(default_factory=list)


class SecurityEngine:
    """Runs security detectors on a throttled schedule."""

    def __init__(
        self,
        alerts: Optional[AlertManager] = None,
        *,
        enabled: bool = True,
    ) -> None:
        self.alerts = alerts
        self.enabled = enabled
        self._last_probe = 0.0
        self._detectors = detectors.build_all()
        self._snapshots: dict[str, MonitorSnapshot] = {
            d.id: MonitorSnapshot(
                id=d.id,
                name=d.name,
                description=d.description,
                enabled=True,
                status="idle",
                summary="Waiting for first scan…",
                last_check="—",
                findings=[],
            )
            for d in self._detectors
        }
        self._enabled_map: dict[str, bool] = {d.id: True for d in self._detectors}
        self.latest_findings: list[dict[str, Any]] = []
        self.session_alerts: list[Alert] = []

    def configure(
        self,
        *,
        enabled: Optional[bool] = None,
        monitor_flags: Optional[dict[str, bool]] = None,
    ) -> None:
        if enabled is not None:
            self.enabled = bool(enabled)
        if monitor_flags:
            for mid, on in monitor_flags.items():
                if mid in self._enabled_map:
                    self._enabled_map[mid] = bool(on)

    def snapshots(self) -> list[MonitorSnapshot]:
        return [self._snapshots[d.id] for d in self._detectors]

    def tick(
        self,
        records: list[ConnectionRecord],
        stats: DashboardStats,
        processes: list[ProcessSummary],
        *,
        force: bool = False,
        store=None,
    ) -> list[Alert]:
        """Run detectors; returns newly emitted alerts."""
        if not self.enabled:
            return []

        mono = time.monotonic()
        if not force and (mono - self._last_probe) < PROBE_INTERVAL_S:
            # Still run connection-only detectors every collector tick (cheap).
            cheap_only = True
        else:
            cheap_only = False
            self._last_probe = mono

        new_alerts: list[Alert] = []
        now = datetime.now()
        ts = now.strftime("%H:%M:%S")
        # Prefer explicit store; fall back to alert manager's store for time machine.
        db = store
        if db is None and self.alerts is not None:
            db = getattr(self.alerts, "store", None)
        ctx = detectors.MonitorContext(
            records=records,
            stats=stats,
            processes=processes,
            now=now,
            run_expensive=not cheap_only,
            store=db,
        )

        for det in self._detectors:
            snap = self._snapshots[det.id]
            snap.enabled = self._enabled_map.get(det.id, True)
            if not snap.enabled:
                snap.status = "idle"
                snap.summary = "Disabled in settings"
                continue
            if cheap_only and det.expensive:
                continue
            try:
                result = det.scan(ctx)
            except Exception as exc:
                logger.debug("monitor %s failed: %s", det.id, exc, exc_info=True)
                snap.status = "error"
                snap.summary = f"Scan error: {exc}"
                snap.last_check = ts
                continue

            snap.last_check = ts
            snap.status = result.status
            snap.summary = result.summary
            snap.findings = [
                {
                    "level": f.level,
                    "title": f.title,
                    "body": f.body,
                    "ts": ts,
                }
                for f in result.findings[:12]
            ]

            for f in result.findings:
                if f.fingerprint.startswith("ui_only:"):
                    continue
                alert = self._emit_finding(det.id, f)
                if alert:
                    new_alerts.append(alert)
                    self.session_alerts.append(alert)

        return new_alerts

    def _emit_finding(self, monitor_id: str, finding: detectors.Finding) -> Optional[Alert]:
        if not self.alerts:
            return None
        level = {
            "info": AlertLevel.INFO,
            "warn": AlertLevel.WARN,
            "high": AlertLevel.HIGH,
        }.get(finding.level, AlertLevel.WARN)
        fp = finding.fingerprint or f"sec:{monitor_id}:{finding.title}"
        # Prefer public helpers when present; fall back to store insert.
        emit = getattr(self.alerts, "emit", None) or getattr(self.alerts, "_emit", None)
        if callable(emit):
            return emit(
                level,
                f"[{monitor_id}] {finding.title}",
                finding.body,
                fp,
            )
        new_id = self.alerts.store.add_alert(
            level=level.value,
            title=f"[{monitor_id}] {finding.title}",
            body=finding.body,
            fingerprint=fp,
        )
        if new_id is None:
            return None
        return Alert(
            id=new_id,
            ts=datetime.now().isoformat(timespec="seconds"),
            level=level.value,
            title=f"[{monitor_id}] {finding.title}",
            body=finding.body,
            fingerprint=fp,
            read=False,
        )
