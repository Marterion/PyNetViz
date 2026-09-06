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

        observations: list[tuple[str, str, str, str, int]] = []
        proc_first: dict[str, ConnectionRecord] = {}
        remote_first: dict[str, ConnectionRecord] = {}
        pair_keys: set[str] = set()

        for rec in records:
            pname = rec.process_name or f"pid:{rec.pid}"
            if pname not in proc_first:
                proc_first[pname] = rec
                observations.append(("process", pname.lower(), pname, "", 0))
            rkey = f"{rec.remote_addr}:{rec.remote_port}"
            if rec.has_remote and rkey not in remote_first:
                remote_first[rkey] = rec
                observations.append(
                    ("remote", rkey, pname, rec.remote_addr, rec.remote_port)
                )
            pair_key = f"{pname.lower()}|{rkey}"
            if pair_key not in pair_keys:
                pair_keys.add(pair_key)
                observations.append(
                    ("pair", pair_key, pname, rec.remote_addr, rec.remote_port)
                )

        hits = self.store.observe_first_seen_batch(observations, now=now)

        proc_new: dict[str, bool] = {}
        for pname, rec in proc_first.items():
            hit = hits.get(("process", pname.lower()))
            is_new = bool(hit and hit.is_new)
            proc_new[pname] = is_new
            if is_new:
                tick_new_procs.append(pname)
                if pname not in self.session_new_processes:
                    self.session_new_processes.append(pname)
                alert = self.alerts.on_new_process(pname, rec.pid)
                if alert:
                    new_alerts.append(alert)

        remote_new: dict[str, bool] = {}
        for rkey, rec in remote_first.items():
            hit = hits.get(("remote", rkey))
            is_new = bool(hit and hit.is_new)
            remote_new[rkey] = is_new
            if is_new:
                tick_new_remotes.append(rkey)
                if rkey not in self.session_new_remotes:
                    self.session_new_remotes.append(rkey)
                alert = self.alerts.on_new_remote(
                    rec.process_name, rec.remote_addr, rec.remote_port
                )
                if alert:
                    new_alerts.append(alert)

        pair_new: dict[str, bool] = {}
        for pair_key in pair_keys:
            hit = hits.get(("pair", pair_key))
            pair_new[pair_key] = bool(hit and hit.is_new)

        if len(self.session_new_processes) > 40:
            self.session_new_processes = self.session_new_processes[-40:]
        if len(self.session_new_remotes) > 40:
            self.session_new_remotes = self.session_new_remotes[-40:]

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
            alert = self.alerts.on_high_risk(rec)
            if alert:
                new_alerts.append(alert)

        # Hourly rollup (~once per 60s check)
        if mono - self._last_hourly >= 60.0:
            self._last_hourly = mono
            remotes = {r.remote_addr for r in records if r.has_remote}
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
