"""Individual security detectors for the ops-center suite."""

from __future__ import annotations

import hashlib
import logging
import os
import platform
import re
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from collections import deque
from typing import Any, Optional

from pynetviz.models.connection import ConnectionRecord, DashboardStats, ProcessSummary

logger = logging.getLogger(__name__)

IS_WINDOWS = platform.system() == "Windows"


@dataclass
class Finding:
    level: str  # info | warn | high
    title: str
    body: str
    fingerprint: str = ""


@dataclass
class ScanResult:
    status: str  # ok | watch | alert
    summary: str
    findings: list[Finding] = field(default_factory=list)


@dataclass
class MonitorContext:
    records: list[ConnectionRecord]
    stats: DashboardStats
    processes: list[ProcessSummary]
    now: datetime
    run_expensive: bool = True
    store: Any = None  # Optional AnalysisStore for time machine
    _arp_rows: Optional[list[tuple[str, str, str]]] = field(
        default=None, repr=False, compare=False
    )

    def arp_table(self) -> list[tuple[str, str, str]]:
        """Parse ARP once per expensive tick and reuse across detectors."""
        if self._arp_rows is None:
            self._arp_rows = _parse_arp_table()
        return self._arp_rows


class BaseDetector(ABC):
    id: str = "base"
    name: str = "Base"
    description: str = ""
    expensive: bool = False  # OS probes (ARP/WiFi/files)

    @abstractmethod
    def scan(self, ctx: MonitorContext) -> ScanResult:
        ...


# ── helpers ──────────────────────────────────────────────────────────────────


def _run_cmd(args: list[str], timeout: float = 3.0) -> str:
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0,
        )
        return (completed.stdout or "") + (completed.stderr or "")
    except Exception as exc:
        logger.debug("cmd failed %s: %s", args, exc)
        return ""


def _parse_arp_table() -> list[tuple[str, str, str]]:
    """Return list of (ip, mac, type)."""
    rows: list[tuple[str, str, str]] = []
    if IS_WINDOWS:
        out = _run_cmd(["arp", "-a"])
        #  192.168.1.1           00-11-22-33-44-55     dynamic
        for line in out.splitlines():
            m = re.search(
                r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{11,17})\s+(\w+)",
                line,
            )
            if m:
                ip, mac, typ = m.group(1), m.group(2).lower().replace("-", ":"), m.group(3)
                if mac.count(":") == 5 and not mac.startswith("ff:"):
                    rows.append((ip, mac, typ))
    else:
        out = _run_cmd(["ip", "neigh"]) or _run_cmd(["arp", "-n"])
        for line in out.splitlines():
            m = re.search(
                r"(\d+\.\d+\.\d+\.\d+).+?lladdr\s+([0-9a-fA-F:]{11,17})",
                line,
            )
            if not m:
                m = re.search(
                    r"(\d+\.\d+\.\d+\.\d+)\s+ether\s+([0-9a-fA-F:]{11,17})",
                    line,
                )
            if m:
                rows.append((m.group(1), m.group(2).lower(), "dynamic"))
    return rows


def _file_fingerprint(path: Path) -> Optional[str]:
    try:
        if not path.exists() or not path.is_file():
            return None
        st = path.stat()
        h = hashlib.sha256()
        with path.open("rb") as fh:
            # Cap read for large binaries
            remaining = min(st.st_size, 2 * 1024 * 1024)
            while remaining > 0:
                chunk = fh.read(min(65536, remaining))
                if not chunk:
                    break
                h.update(chunk)
                remaining -= len(chunk)
        return f"{st.st_mtime_ns}:{st.st_size}:{h.hexdigest()[:16]}"
    except OSError:
        return None


# ── 1. Suspicious Host monitoring ────────────────────────────────────────────


class SuspiciousHostMonitor(BaseDetector):
    id = "suspicious_hosts"
    name = "Suspicious Host monitoring"
    description = "Tracks elevated-risk remotes, LOLBins, and suspicious ports"
    expensive = False

    def __init__(self) -> None:
        self._seen_high: set[str] = set()

    def scan(self, ctx: MonitorContext) -> ScanResult:
        findings: list[Finding] = []
        hot: list[str] = []
        for r in ctx.records:
            if r.risk_score < 55 and not r.is_suspicious:
                continue
            if not r.has_remote:
                continue
            key = f"{r.remote_addr}:{r.remote_port}"
            label = f"{r.process_name} → {key}"
            if r.hostname:
                label += f" ({r.hostname})"
            hot.append(f"{label} risk={r.risk_score}")
            if key not in self._seen_high:
                self._seen_high.add(key)
                reasons = ", ".join(r.risk_reasons[:3]) if r.risk_reasons else "elevated score"
                level = "high" if r.risk_score >= 75 else "warn"
                findings.append(
                    Finding(
                        level=level,
                        title="Suspicious remote activity",
                        body=f"{label} — {reasons}",
                        fingerprint=f"sus_host:{key}:{r.process_name}",
                    )
                )
        if not hot:
            return ScanResult("ok", "No elevated-risk hosts in the current snapshot", [])
        status = "alert" if any(f.level == "high" for f in findings) else "watch"
        summary = f"{len(hot)} elevated link(s) · {len(findings)} new this scan"
        return ScanResult(status, summary, findings[:8])


# ── 2. New Device Connection ─────────────────────────────────────────────────


class NewDeviceMonitor(BaseDetector):
    id = "new_device"
    name = "New Device Connection"
    description = "Alerts when a new LAN device (MAC) appears on the network"
    expensive = True

    def __init__(self) -> None:
        self._known_macs: set[str] = set()
        self._primed = False

    def scan(self, ctx: MonitorContext) -> ScanResult:
        if not ctx.run_expensive:
            return ScanResult("ok", "Deferred (interval)", [])
        rows = ctx.arp_table()
        macs = {mac for _, mac, _ in rows}
        findings: list[Finding] = []
        if not self._primed:
            self._known_macs = set(macs)
            self._primed = True
            return ScanResult(
                "ok",
                f"Baseline set · {len(self._known_macs)} device(s) on LAN",
                [],
            )
        new_macs = macs - self._known_macs
        for mac in sorted(new_macs):
            ips = [ip for ip, m, _ in rows if m == mac]
            ip_s = ", ".join(ips) or "?"
            findings.append(
                Finding(
                    level="warn",
                    title="New device on network",
                    body=f"MAC {mac} joined · IP {ip_s}",
                    fingerprint=f"new_dev:{mac}",
                )
            )
            self._known_macs.add(mac)
        if findings:
            return ScanResult(
                "watch",
                f"{len(findings)} new device(s) · inventory {len(self._known_macs)}",
                findings,
            )
        return ScanResult("ok", f"No new devices · inventory {len(self._known_macs)}", [])


# ── 3. Evil Twin Detection ───────────────────────────────────────────────────


class EvilTwinMonitor(BaseDetector):
    id = "evil_twin"
    name = "Evil Twin Detection"
    description = "Detects same Wi‑Fi SSID advertised by multiple BSSIDs"
    expensive = True

    def __init__(self) -> None:
        self._last_ssid_map: dict[str, set[str]] = {}

    def scan(self, ctx: MonitorContext) -> ScanResult:
        if not ctx.run_expensive:
            return ScanResult("ok", "Deferred (interval)", [])
        if not IS_WINDOWS:
            return ScanResult("ok", "Wi‑Fi BSSID scan available on Windows", [])

        out = _run_cmd(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=5.0)
        if not out.strip():
            return ScanResult("ok", "No Wi‑Fi networks visible (adapter off?)", [])

        ssid_bssids: dict[str, set[str]] = {}
        current_ssid = ""
        for line in out.splitlines():
            line = line.strip()
            m_ssid = re.match(r"SSID\s+\d+\s*:\s*(.+)$", line, re.I)
            if m_ssid:
                current_ssid = m_ssid.group(1).strip()
                ssid_bssids.setdefault(current_ssid, set())
                continue
            m_bssid = re.match(r"BSSID\s+\d+\s*:\s*([0-9a-fA-F:\-]+)$", line, re.I)
            if m_bssid and current_ssid:
                bssid = m_bssid.group(1).lower().replace("-", ":")
                ssid_bssids[current_ssid].add(bssid)

        findings: list[Finding] = []
        twins = {s: b for s, b in ssid_bssids.items() if s and len(b) > 1}
        for ssid, bssids in twins.items():
            prev = self._last_ssid_map.get(ssid, set())
            # Alert when multi-BSSID first observed or BSSID set grows
            if len(bssids) > 1 and (not prev or bssids - prev):
                findings.append(
                    Finding(
                        level="high",
                        title="Possible evil twin / multi-BSSID SSID",
                        body=f"SSID “{ssid}” seen on {len(bssids)} BSSID(s): {', '.join(sorted(bssids)[:4])}",
                        fingerprint=f"evil_twin:{ssid}:{len(bssids)}",
                    )
                )
        self._last_ssid_map = ssid_bssids
        if findings:
            return ScanResult(
                "alert",
                f"{len(twins)} multi-BSSID SSID(s) · {len(findings)} alert(s)",
                findings,
            )
        multi = len(twins)
        if multi:
            return ScanResult(
                "watch",
                f"{multi} SSID(s) with multiple BSSIDs (stable)",
                [],
            )
        return ScanResult("ok", f"Scanned {len(ssid_bssids)} SSID(s) · no multi-BSSID twins", [])


# ── 4. System File Monitor ───────────────────────────────────────────────────


class SystemFileMonitor(BaseDetector):
    id = "system_files"
    name = "System File Monitor"
    description = "Watches critical OS/network config files for unexpected changes"
    expensive = True

    def __init__(self) -> None:
        self._baseline: dict[str, str] = {}
        self._primed = False

    def _watch_paths(self) -> list[Path]:
        paths: list[Path] = []
        if IS_WINDOWS:
            windir = Path(os.environ.get("WINDIR", r"C:\Windows"))
            paths.extend(
                [
                    windir / "System32" / "drivers" / "etc" / "hosts",
                    windir / "System32" / "drivers" / "etc" / "networks",
                ]
            )
        else:
            paths.extend(
                [
                    Path("/etc/hosts"),
                    Path("/etc/resolv.conf"),
                    Path("/etc/nsswitch.conf"),
                ]
            )
        return paths

    def scan(self, ctx: MonitorContext) -> ScanResult:
        if not ctx.run_expensive:
            return ScanResult("ok", "Deferred (interval)", [])
        findings: list[Finding] = []
        current: dict[str, str] = {}
        for path in self._watch_paths():
            key = str(path)
            fp = _file_fingerprint(path)
            if fp is None:
                current[key] = "missing"
            else:
                current[key] = fp

        if not self._primed:
            self._baseline = dict(current)
            self._primed = True
            return ScanResult("ok", f"Baseline locked · {len(current)} path(s)", [])

        for key, fp in current.items():
            prev = self._baseline.get(key)
            if prev is None:
                findings.append(
                    Finding(
                        level="warn",
                        title="New watched path appeared",
                        body=key,
                        fingerprint=f"sysfile_new:{key}",
                    )
                )
            elif prev != fp:
                findings.append(
                    Finding(
                        level="high",
                        title="Critical file changed",
                        body=f"{key} fingerprint changed",
                        fingerprint=f"sysfile_chg:{key}:{fp}",
                    )
                )
                self._baseline[key] = fp
        # update baseline for new keys
        for key, fp in current.items():
            self._baseline.setdefault(key, fp)

        if findings:
            return ScanResult("alert", f"{len(findings)} critical file change(s)", findings)
        return ScanResult("ok", f"All {len(current)} watched path(s) stable", [])


# ── 5. Device List Monitor ───────────────────────────────────────────────────


class DeviceListMonitor(BaseDetector):
    id = "device_list"
    name = "Device List Monitor"
    description = "Maintains a live inventory of LAN devices from the ARP table"
    expensive = True

    def __init__(self) -> None:
        self._inventory: list[tuple[str, str, str]] = []

    def scan(self, ctx: MonitorContext) -> ScanResult:
        if not ctx.run_expensive:
            # Keep last inventory summary without re-probing
            n = len(self._inventory)
            return ScanResult(
                "ok" if n else "idle",
                f"Inventory {n} device(s) (cached)",
                [],
            )
        rows = ctx.arp_table()
        self._inventory = rows
        # Surface as findings for UI list (info only, no alert spam)
        findings = [
            Finding(
                level="info",
                title=f"{ip}",
                body=f"MAC {mac} · {typ}",
                fingerprint=f"devlist:{mac}:{ip}",
            )
            for ip, mac, typ in sorted(rows, key=lambda r: r[0])[:40]
        ]
        return ScanResult(
            "ok",
            f"{len(rows)} device(s) on local network",
            findings,  # info findings — engine still emits via alerts with dedupe
        )


class DeviceListMonitorQuiet(DeviceListMonitor):
    """Same inventory as DeviceListMonitor, but findings are UI-only (no alert emit)."""

    def scan(self, ctx: MonitorContext) -> ScanResult:
        result = super().scan(ctx)
        # Prefix fingerprints so the engine treats them as UI-only inventory.
        return ScanResult(
            result.status,
            result.summary,
            [
                Finding(
                    level="info",
                    title=f.title,
                    body=f.body,
                    fingerprint=f"ui_only:{f.fingerprint}",
                )
                for f in result.findings
            ],
        )


# ── 6. Summarized Activity While Idle ────────────────────────────────────────


class IdleActivityMonitor(BaseDetector):
    id = "idle_summary"
    name = "Summarized Activity While Idle"
    description = "Summarizes network activity during user idle periods"
    expensive = False

    def __init__(self, idle_threshold_s: float = 120.0) -> None:
        self.idle_threshold_s = idle_threshold_s
        self._was_idle = False
        self._idle_started: Optional[float] = None
        self._idle_procs: set[str] = set()
        self._idle_remotes: set[str] = set()
        self._idle_bytes = 0
        self._idle_peak_conns = 0
        self._idle_bytes_baseline: Optional[int] = None

    def _idle_seconds(self) -> float:
        if IS_WINDOWS:
            try:
                import ctypes
                from ctypes import wintypes

                class LASTINPUTINFO(ctypes.Structure):
                    _fields_ = [
                        ("cbSize", wintypes.UINT),
                        ("dwTime", wintypes.DWORD),
                    ]

                lii = LASTINPUTINFO()
                lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
                if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)):
                    tick = ctypes.windll.kernel32.GetTickCount()
                    idle_ms = tick - lii.dwTime
                    return max(0.0, idle_ms / 1000.0)
            except Exception:
                pass
        # Fallback: never idle (no summary) on unsupported platforms
        return 0.0

    def scan(self, ctx: MonitorContext) -> ScanResult:
        idle_s = self._idle_seconds()
        findings: list[Finding] = []

        if idle_s >= self.idle_threshold_s:
            if not self._was_idle:
                self._was_idle = True
                self._idle_started = time.monotonic()
                self._idle_procs.clear()
                self._idle_remotes.clear()
                self._idle_bytes = 0
                self._idle_peak_conns = 0
                self._idle_bytes_baseline = None
            attributed = 0
            for r in ctx.records:
                self._idle_procs.add(r.process_name or f"pid:{r.pid}")
                if r.has_remote:
                    self._idle_remotes.add(f"{r.remote_addr}:{r.remote_port}")
                attributed += int(r.bytes_sent or 0) + int(r.bytes_recv or 0)
            if self._idle_bytes_baseline is None:
                self._idle_bytes_baseline = attributed
            self._idle_bytes = max(0, attributed - self._idle_bytes_baseline)
            self._idle_peak_conns = max(
                self._idle_peak_conns, int(ctx.stats.total_connections or 0)
            )
            mins = int(idle_s // 60)
            return ScanResult(
                "watch",
                f"User idle {mins}m · tracking {len(self._idle_procs)} procs · "
                f"{len(self._idle_remotes)} remotes",
                [],
            )

        # Transition: idle → active → emit summary
        if self._was_idle:
            self._was_idle = False
            duration = 0
            if self._idle_started is not None:
                duration = int(time.monotonic() - self._idle_started)
            body = (
                f"Idle window ~{duration}s · peak {self._idle_peak_conns} links · "
                f"{len(self._idle_procs)} processes · {len(self._idle_remotes)} remotes · "
                f"~{self._idle_bytes} bytes attributed"
            )
            top_procs = ", ".join(sorted(self._idle_procs)[:8]) or "—"
            findings.append(
                Finding(
                    level="info",
                    title="Activity while you were idle",
                    body=f"{body}. Processes: {top_procs}",
                    fingerprint=f"idle_sum:{int(time.time()) // 300}",  # 5-min bucket
                )
            )
            return ScanResult("ok", "Idle summary generated", findings)

        return ScanResult("ok", "User active · idle summary armed", [])


# ── 7. ARP Spoofing Detection ────────────────────────────────────────────────


class ArpSpoofMonitor(BaseDetector):
    id = "arp_spoof"
    name = "ARP Spoofing Detecting"
    description = "Detects IP↔MAC binding changes and conflicting MACs for one IP"
    expensive = True

    def __init__(self) -> None:
        self._ip_to_mac: dict[str, str] = {}
        self._primed = False

    def scan(self, ctx: MonitorContext) -> ScanResult:
        if not ctx.run_expensive:
            return ScanResult("ok", "Deferred (interval)", [])
        rows = ctx.arp_table()
        findings: list[Finding] = []
        current: dict[str, str] = {}
        for ip, mac, _ in rows:
            # Last wins if duplicates in table
            if ip in current and current[ip] != mac:
                findings.append(
                    Finding(
                        level="high",
                        title="Conflicting ARP entries",
                        body=f"IP {ip} maps to both {current[ip]} and {mac}",
                        fingerprint=f"arp_conflict:{ip}:{mac}",
                    )
                )
            current[ip] = mac

        if not self._primed:
            self._ip_to_mac = dict(current)
            self._primed = True
            return ScanResult("ok", f"ARP baseline · {len(current)} binding(s)", [])

        for ip, mac in current.items():
            prev = self._ip_to_mac.get(ip)
            if prev and prev != mac:
                findings.append(
                    Finding(
                        level="high",
                        title="ARP binding changed",
                        body=f"IP {ip}: MAC {prev} → {mac} (possible spoof)",
                        fingerprint=f"arp_change:{ip}:{prev}:{mac}",
                    )
                )
            self._ip_to_mac[ip] = mac

        if findings:
            return ScanResult("alert", f"{len(findings)} ARP anomaly(ies)", findings)
        return ScanResult("ok", f"ARP stable · {len(current)} binding(s)", [])


# ── 8. Proxy Settings Monitor ────────────────────────────────────────────────


class ProxySettingsMonitor(BaseDetector):
    id = "proxy_settings"
    name = "Proxy Settings Monitor"
    description = "Watches system HTTP(S) proxy configuration for unexpected changes"
    expensive = True

    def __init__(self) -> None:
        self._baseline: Optional[str] = None

    def _read_proxy(self) -> str:
        if IS_WINDOWS:
            try:
                import winreg

                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                )
                try:
                    enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
                except FileNotFoundError:
                    enable = 0
                try:
                    server, _ = winreg.QueryValueEx(key, "ProxyServer")
                except FileNotFoundError:
                    server = ""
                try:
                    override, _ = winreg.QueryValueEx(key, "ProxyOverride")
                except FileNotFoundError:
                    override = ""
                winreg.CloseKey(key)
                return f"enable={int(enable)};server={server};override={override}"
            except Exception as exc:
                return f"error={exc}"
        # Linux/macOS: env + common config snippets
        parts = [
            f"http_proxy={os.environ.get('http_proxy') or os.environ.get('HTTP_PROXY') or ''}",
            f"https_proxy={os.environ.get('https_proxy') or os.environ.get('HTTPS_PROXY') or ''}",
            f"all_proxy={os.environ.get('all_proxy') or os.environ.get('ALL_PROXY') or ''}",
            f"no_proxy={os.environ.get('no_proxy') or os.environ.get('NO_PROXY') or ''}",
        ]
        return ";".join(parts)

    def scan(self, ctx: MonitorContext) -> ScanResult:
        if not ctx.run_expensive:
            return ScanResult("ok", "Deferred (interval)", [])
        current = self._read_proxy()
        findings: list[Finding] = []
        if self._baseline is None:
            self._baseline = current
            enabled = "enable=1" in current or "http_proxy=http" in current.lower()
            return ScanResult(
                "watch" if enabled else "ok",
                f"Baseline proxy · {current[:80]}",
                [],
            )
        if current != self._baseline:
            findings.append(
                Finding(
                    level="high",
                    title="Proxy settings changed",
                    body=f"Was: {self._baseline[:120]} → Now: {current[:120]}",
                    fingerprint=f"proxy:{hashlib.sha256(current.encode()).hexdigest()[:12]}",
                )
            )
            self._baseline = current
            return ScanResult("alert", "Proxy configuration modified", findings)
        enabled = "enable=1" in current
        return ScanResult(
            "watch" if enabled else "ok",
            "Proxy enabled" if enabled else "System proxy off / unchanged",
            [],
        )


# ── 9. Traffic Monitoring ────────────────────────────────────────────────────


class TrafficMonitor(BaseDetector):
    """Watch live throughput, connection volume, and per-process traffic share."""

    id = "traffic"
    name = "Traffic Monitoring"
    description = "Live bandwidth & link-volume watch with spike and top-talker alerts"
    expensive = False

    def __init__(
        self,
        *,
        spike_ratio: float = 3.0,
        min_spike_bps: float = 50_000.0,  # 50 KB/s floor
        high_conn_threshold: int = 400,
    ) -> None:
        self.spike_ratio = spike_ratio
        self.min_spike_bps = min_spike_bps
        self.high_conn_threshold = high_conn_threshold
        self._up_hist: deque[float] = deque(maxlen=30)
        self._down_hist: deque[float] = deque(maxlen=30)
        self._conn_hist: deque[int] = deque(maxlen=30)

    def scan(self, ctx: MonitorContext) -> ScanResult:
        up = float(ctx.stats.upload_bps or 0)
        down = float(ctx.stats.download_bps or 0)
        total = int(ctx.stats.total_connections or 0)
        findings: list[Finding] = []

        avg_up = (sum(self._up_hist) / len(self._up_hist)) if self._up_hist else 0.0
        avg_down = (sum(self._down_hist) / len(self._down_hist)) if self._down_hist else 0.0

        def _spike(label: str, now: float, avg: float) -> None:
            if avg <= 0:
                return
            if now >= self.min_spike_bps and now >= avg * self.spike_ratio:
                findings.append(
                    Finding(
                        level="warn",
                        title=f"{label} traffic spike",
                        body=(
                            f"{label} now {now / 1024:.1f} KB/s vs avg "
                            f"{avg / 1024:.1f} KB/s ({now / avg:.1f}×)"
                        ),
                        fingerprint=f"traffic_spike:{label}:{int(time.time()) // 60}",
                    )
                )

        if len(self._up_hist) >= 5:
            _spike("Upload", up, avg_up)
            _spike("Download", down, avg_down)

        if total >= self.high_conn_threshold:
            findings.append(
                Finding(
                    level="warn",
                    title="High connection volume",
                    body=f"{total} active links (threshold {self.high_conn_threshold})",
                    fingerprint=f"traffic_conn:{total // 50}",
                )
            )

        # Top talkers by attributed bytes this snapshot
        talkers: list[tuple[str, int]] = []
        for p in ctx.processes[:12]:
            b = int(p.bytes_sent or 0) + int(p.bytes_recv or 0)
            if b > 0:
                talkers.append((p.name or f"pid:{p.pid}", b))
        talkers.sort(key=lambda x: x[1], reverse=True)

        self._up_hist.append(up)
        self._down_hist.append(down)
        self._conn_hist.append(total)

        ui_rows = [
            Finding(
                level="info",
                title=f"↑ {up / 1024:.1f} KB/s  ↓ {down / 1024:.1f} KB/s",
                body=f"{total} links · samples {len(self._up_hist)}",
                fingerprint=f"ui_only:traffic_now",
            )
        ]
        for name, b in talkers[:6]:
            ui_rows.append(
                Finding(
                    level="info",
                    title=name,
                    body=f"~{b} bytes attributed",
                    fingerprint=f"ui_only:talker:{name}",
                )
            )

        status = "alert" if any(f.level == "high" for f in findings) else (
            "watch" if findings else "ok"
        )
        summary = (
            f"↑ {up / 1024:.1f} / ↓ {down / 1024:.1f} KB/s · {total} links"
            + (f" · {len(findings)} event(s)" if findings else "")
        )
        return ScanResult(status, summary, findings + ui_rows)


# ── 10. Network Time Machine ─────────────────────────────────────────────────


class NetworkTimeMachineMonitor(BaseDetector):
    """Surface historical hourly stats + samples for rewind-style inspection."""

    id = "time_machine"
    name = "Network Time Machine"
    description = "Rewind recent network history from stored hourly stats and samples"
    expensive = True  # DB reads; throttle with expensive interval

    def __init__(self) -> None:
        self._last_hour_key: str = ""

    def scan(self, ctx: MonitorContext) -> ScanResult:
        if not ctx.run_expensive:
            return ScanResult("ok", "History refresh deferred", [])
        store = ctx.store
        if store is None:
            # Fallback: use in-memory bandwidth/connection history from stats
            hist = list(ctx.stats.connection_history or [])[-8:]
            bw = list(ctx.stats.bandwidth_history or [])[-8:]
            findings = [
                Finding(
                    level="info",
                    title="Live buffer only",
                    body="SQLite store not attached — showing live chart buffers",
                    fingerprint="ui_only:tm_nostore",
                )
            ]
            for ts, count in hist[-6:]:
                findings.append(
                    Finding(
                        level="info",
                        title=f"links @ {ts.strftime('%H:%M:%S') if hasattr(ts, 'strftime') else ts}",
                        body=f"{count} connections",
                        fingerprint=f"ui_only:tm_live:{ts}:{count}",
                    )
                )
            for row in bw[-4:]:
                if len(row) >= 3:
                    findings.append(
                        Finding(
                            level="info",
                            title=f"bw @ {row[0].strftime('%H:%M:%S') if hasattr(row[0], 'strftime') else row[0]}",
                            body=f"↑ {float(row[1])/1024:.1f} ↓ {float(row[2])/1024:.1f} KB/s",
                            fingerprint=f"ui_only:tm_bw:{row[0]}",
                        )
                    )
            return ScanResult(
                "ok",
                f"Live history · {len(hist)} conn pts · {len(bw)} bw pts",
                findings,
            )

        findings: list[Finding] = []
        try:
            hourly = store.recent_hourly(hours=24)
        except Exception:
            hourly = []
        try:
            samples = store.recent_samples(limit=16)
        except Exception:
            samples = []

        for h in hourly[:8]:
            hour = str(h.get("hour_ts") or h.get("hour") or "?")
            total = int(h.get("total_connections") or 0)
            est = int(h.get("established") or 0)
            rem = int(h.get("unique_remotes") or 0)
            up = float(h.get("upload_bps") or 0)
            down = float(h.get("download_bps") or 0)
            findings.append(
                Finding(
                    level="info",
                    title=f"Hour {hour}",
                    body=(
                        f"{total} links · est {est} · remotes {rem} · "
                        f"↑ {up/1024:.1f} ↓ {down/1024:.1f} KB/s"
                    ),
                    fingerprint=f"ui_only:tm_hour:{hour}",
                )
            )

        for s in samples[:10]:
            findings.append(
                Finding(
                    level="info",
                    title=f"{s.get('process_name') or '?'} → {s.get('remote_addr')}:{s.get('remote_port')}",
                    body=f"{s.get('ts')} · {s.get('protocol')} {s.get('state')} · risk {s.get('risk_score')}",
                    fingerprint=f"ui_only:tm_sample:{s.get('id')}",
                )
            )

        # Alert if latest hour is a large jump vs previous
        if len(hourly) >= 2:
            a = int(hourly[0].get("total_connections") or 0)
            b = int(hourly[1].get("total_connections") or 0)
            hour_key = str(hourly[0].get("hour_ts") or "")
            if b > 0 and a >= b * 2.5 and a - b >= 50 and hour_key != self._last_hour_key:
                self._last_hour_key = hour_key
                findings.insert(
                    0,
                    Finding(
                        level="warn",
                        title="Historical traffic jump",
                        body=f"Latest hour {a} links vs previous {b} ({a/max(b,1):.1f}×)",
                        fingerprint=f"tm_jump:{hour_key}:{a}",
                    ),
                )

        status = "watch" if any(f.level == "warn" for f in findings) else "ok"
        return ScanResult(
            status,
            f"{len(hourly)} hour(s) · {len(samples)} sample(s) in store",
            findings,
        )


# ── 11. First Network Activity ───────────────────────────────────────────────


class FirstNetworkActivityMonitor(BaseDetector):
    """Detect first-ever network activity for processes and remotes this session."""

    id = "first_activity"
    name = "First Network Activity"
    description = "Alerts when a process or remote endpoint appears for the first time"
    expensive = False

    def __init__(self) -> None:
        self._seen_procs: set[str] = set()
        self._seen_remotes: set[str] = set()
        self._seen_listens: set[str] = set()
        self._primed = False

    def scan(self, ctx: MonitorContext) -> ScanResult:
        findings: list[Finding] = []
        procs_now: set[str] = set()
        remotes_now: set[str] = set()
        listens_now: set[str] = set()

        for r in ctx.records:
            pname = (r.process_name or f"pid:{r.pid}").lower()
            procs_now.add(pname)
            if r.has_remote:
                remotes_now.add(f"{r.remote_addr}:{r.remote_port}")
            if (r.state or "").upper() == "LISTEN" or (
                hasattr(r.direction, "value") and r.direction.value == "listen"
            ):
                listens_now.add(f"{pname}:{r.local_port}")

        if not self._primed:
            self._seen_procs = set(procs_now)
            self._seen_remotes = set(remotes_now)
            self._seen_listens = set(listens_now)
            self._primed = True
            return ScanResult(
                "ok",
                f"Baseline · {len(procs_now)} procs · {len(remotes_now)} remotes · "
                f"{len(listens_now)} listeners",
                [
                    Finding(
                        level="info",
                        title="First-activity baseline locked",
                        body="Subsequent new processes/remotes/listeners will be reported",
                        fingerprint="ui_only:first_baseline",
                    )
                ],
            )

        new_procs = procs_now - self._seen_procs
        new_remotes = remotes_now - self._seen_remotes
        new_listens = listens_now - self._seen_listens

        for p in sorted(new_procs)[:12]:
            findings.append(
                Finding(
                    level="info",
                    title="First network activity — process",
                    body=f"{p} opened network connections for the first time this session",
                    fingerprint=f"first_proc:{p}",
                )
            )
            self._seen_procs.add(p)
        for remote in sorted(new_remotes)[:12]:
            findings.append(
                Finding(
                    level="warn",
                    title="First network activity — remote",
                    body=f"New remote endpoint {remote}",
                    fingerprint=f"first_remote:{remote}",
                )
            )
            self._seen_remotes.add(remote)
        for listen in sorted(new_listens)[:8]:
            findings.append(
                Finding(
                    level="info",
                    title="First network activity — listener",
                    body=f"New listening socket {listen}",
                    fingerprint=f"first_listen:{listen}",
                )
            )
            self._seen_listens.add(listen)

        # UI roster of current first-seen session counts
        findings.append(
            Finding(
                level="info",
                title="Session inventory",
                body=(
                    f"{len(self._seen_procs)} procs · {len(self._seen_remotes)} remotes · "
                    f"{len(self._seen_listens)} listeners known this session"
                ),
                fingerprint="ui_only:first_inventory",
            )
        )

        if new_procs or new_remotes or new_listens:
            status = "watch" if new_remotes else "ok"
            return ScanResult(
                status,
                f"+{len(new_procs)} proc · +{len(new_remotes)} remote · +{len(new_listens)} listen",
                findings,
            )
        return ScanResult(
            "ok",
            f"No first-seen events · tracking {len(self._seen_procs)} procs",
            findings,
        )


def build_all() -> list[BaseDetector]:
    return [
        SuspiciousHostMonitor(),
        NewDeviceMonitor(),
        EvilTwinMonitor(),
        SystemFileMonitor(),
        DeviceListMonitorQuiet(),
        IdleActivityMonitor(),
        ArpSpoofMonitor(),
        ProxySettingsMonitor(),
        TrafficMonitor(),
        NetworkTimeMachineMonitor(),
        FirstNetworkActivityMonitor(),
    ]
