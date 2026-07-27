"""Analysis pipeline: first-seen + risk + samples + alerts on each collector tick."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from pynetviz.analysis.alerts import Alert, AlertManager
from pynetviz.analysis.digest import NetworkDigest, build_digest
from pynetviz.analysis.risk import RiskEngine
from pynetviz.analysis.settings import SettingsStore
from pynetviz.analysis.store import AnalysisStore
from pynetviz.models.connection import ConnectionRecord, DashboardStats, ProcessSummary

logger = logging.getLogger(__name__)


@dataclass
class AnalysisTickResult:
    records: list[ConnectionRecord]
    digest: NetworkDigest
    new_alerts: list[Alert] = field(default_factory=list)
    new_process_names: list[str] = field(default_factory=list)
    new_remotes: list[str] = field(default_factory=list)


class AnalysisPipeline:
    """Runs on collector thread after each snapshot (kept cheap)."""

    def __init__(
        self,
        store: Optional[AnalysisStore] = None,
        settings: Optional[SettingsStore] = None,
        risk: Optional[RiskEngine] = None,
        alerts: Optional[AlertManager] = None,
    ) -> None:
        self.settings = settings or SettingsStore()
        self.store = store or AnalysisStore()
        self.risk = risk or RiskEngine(
            elevated_threshold=self.settings.settings.alert_min_score
        )
        self.alerts = alerts or AlertManager(
            self.store,
            enabled=self.settings.settings.alerts_enabled,
            min_score=self.settings.settings.alert_min_score,
        )
        self._last_hourly = 0.0
        self._last_sample = 0.0
        self._last_digest_at = 0.0
        self.latest_digest: Optional[NetworkDigest] = None
        self.session_new_processes: list[str] = []
        self.session_new_remotes: list[str] = []

    def reload_settings(self) -> None:
        self.settings.load()
        s = self.settings.settings
        self.alerts.configure(enabled=s.alerts_enabled, min_score=s.alert_min_score)
        self.risk.elevated_threshold = s.alert_min_score

    def process(
        self,
        records: list[ConnectionRecord],
        stats: DashboardStats,
        processes: list[ProcessSummary],
    ) -> AnalysisTickResult:
        now = datetime.now()
        mono = time.monotonic()
        new_alerts: list[Alert] = []
        tick_new_procs: list[str] = []
        tick_new_remotes: list[str] = []

        # Pre-scan first-seen for processes/remotes (batch)
        proc_new: dict[str, bool] = {}
        remote_new: dict[str, bool] = {}
        pair_new: dict[str, bool] = {}

        for rec in records:
            pname = rec.process_name or f"pid:{rec.pid}"
            if pname not in proc_new:
                hit = self.store.observe_first_seen(
                    "process",
                    pname.lower(),
                    process_name=pname,
                    now=now,
                )
                proc_new[pname] = hit.is_new
                if hit.is_new:
                    tick_new_procs.append(pname)
                    if pname not in self.session_new_processes:
                        self.session_new_processes.append(pname)
                    a = self.alerts.on_new_process(pname, rec.pid)
                    if a:
                        new_alerts.append(a)

            rkey = f"{rec.remote_addr}:{rec.remote_port}"
            if rec.remote_addr and rec.remote_addr not in ("", "0.0.0.0", "::", "*"):
                if rkey not in remote_new:
                    hit = self.store.observe_first_seen(
                        "remote",
                        rkey,
                        process_name=pname,
                        remote_addr=rec.remote_addr,
                        remote_port=rec.remote_port,
                        now=now,
                    )
                    remote_new[rkey] = hit.is_new
                    if hit.is_new:
                        tick_new_remotes.append(rkey)
                        if rkey not in self.session_new_remotes:
                            self.session_new_remotes.append(rkey)
                        a = self.alerts.on_new_remote(pname, rec.remote_addr, rec.remote_port)
                        if a:
                            new_alerts.append(a)

            pair_key = f"{pname.lower()}|{rkey}"
            if pair_key not in pair_new:
                hit = self.store.observe_first_seen(
                    "pair",
                    pair_key,
                    process_name=pname,
                    remote_addr=rec.remote_addr,
                    remote_port=rec.remote_port,
                    now=now,
                )
                pair_new[pair_key] = hit.is_new

        # Risk score every record
        for rec in records:
            pname = rec.process_name or f"pid:{rec.pid}"
            rkey = f"{rec.remote_addr}:{rec.remote_port}"
            pair_key = f"{pname.lower()}|{rkey}"
            self.risk.apply_to_record(
                rec,
                first_seen_process=proc_new.get(pname, False),
                first_seen_remote=remote_new.get(rkey, False),
                first_seen_pair=pair_new.get(pair_key, False),
            )
            a = self.alerts.on_high_risk(rec)
            if a:
                new_alerts.append(a)

        # Hourly rollup (~once per 60s check)
        if mono - self._last_hourly >= 60.0:
            self._last_hourly = mono
            remotes = {
                r.remote_addr
                for r in records
                if r.remote_addr and r.remote_addr not in ("", "0.0.0.0", "::", "*")
            }
            try:
                self.store.record_hourly_snapshot(
                    total_connections=stats.total_connections,
                    established=stats.established_connections,
                    unique_remotes=len(remotes),
                    upload_bps=stats.upload_bps,
                    download_bps=stats.download_bps,
                    now=now,
                )
            except Exception:
                logger.debug("hourly snapshot failed", exc_info=True)

        # Sample high-risk + top rows occasionally
        if (
            self.settings.settings.sample_connections
            and mono - self._last_sample >= 30.0
        ):
            self._last_sample = mono
            ranked = sorted(records, key=lambda r: r.risk_score, reverse=True)[:25]
            try:
                self.store.sample_connections(
                    [
                        {
                            "process_name": r.process_name,
                            "pid": r.pid,
                            "remote_addr": r.remote_addr,
                            "remote_port": r.remote_port,
                            "protocol": r.protocol,
                            "state": r.state,
                            "risk_score": r.risk_score,
                            "risk_reasons": r.risk_reasons,
                        }
                        for r in ranked
                    ]
                )
            except Exception:
                logger.debug("sample_connections failed", exc_info=True)

        digest = build_digest(
            records,
            stats,
            processes,
            new_process_names=list(self.session_new_processes[-10:]),
            new_remotes=list(self.session_new_remotes[-10:]),
            now=now,
        )
        self.latest_digest = digest
        self._last_digest_at = mono

        return AnalysisTickResult(
            records=records,
            digest=digest,
            new_alerts=new_alerts,
            new_process_names=tick_new_procs,
            new_remotes=tick_new_remotes,
        )
