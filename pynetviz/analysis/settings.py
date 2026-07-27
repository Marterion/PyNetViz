"""App settings and privacy modes — JSON file under ~/.pynetviz/."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class PrivacyMode(str, Enum):
    """Controls whether remote enrichment APIs may run."""

    STRICT = "strict"  # no external GeoIP/WHOIS; local MaxMind OK if present
    ENRICH = "enrich"  # APIs allowed


class UiDensity(str, Enum):
    COMFORTABLE = "comfortable"
    COMPACT = "compact"


DEFAULT_SETTINGS_PATH = Path.home() / ".pynetviz" / "settings.json"


@dataclass
class AppSettings:
    privacy_mode: PrivacyMode = PrivacyMode.ENRICH
    alerts_enabled: bool = True
    alert_min_score: int = 55
    digest_interval_s: float = 60.0
    sample_connections: bool = True
    # v2
    poll_interval_s: float = 0.5
    max_table_rows: int = 100
    ui_density: UiDensity = UiDensity.COMFORTABLE
    show_port_labels: bool = True
    auto_export_dir: str = ""
    # Security suite
    security_enabled: bool = True
    mon_suspicious_hosts: bool = True
    mon_new_device: bool = True
    mon_evil_twin: bool = True
    mon_system_files: bool = True
    mon_device_list: bool = True
    mon_idle_summary: bool = True
    mon_arp_spoof: bool = True
    mon_proxy_settings: bool = True
    mon_traffic: bool = True
    mon_time_machine: bool = True
    mon_first_activity: bool = True

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["privacy_mode"] = self.privacy_mode.value
        d["ui_density"] = self.ui_density.value
        return d

    def security_flags(self) -> dict[str, bool]:
        return {
            "suspicious_hosts": self.mon_suspicious_hosts,
            "new_device": self.mon_new_device,
            "evil_twin": self.mon_evil_twin,
            "system_files": self.mon_system_files,
            "device_list": self.mon_device_list,
            "idle_summary": self.mon_idle_summary,
            "arp_spoof": self.mon_arp_spoof,
            "proxy_settings": self.mon_proxy_settings,
            "traffic": self.mon_traffic,
            "time_machine": self.mon_time_machine,
            "first_activity": self.mon_first_activity,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AppSettings":
        mode = data.get("privacy_mode", PrivacyMode.ENRICH.value)
        try:
            privacy = PrivacyMode(mode)
        except ValueError:
            privacy = PrivacyMode.ENRICH
        density_raw = data.get("ui_density", UiDensity.COMFORTABLE.value)
        try:
            density = UiDensity(density_raw)
        except ValueError:
            density = UiDensity.COMFORTABLE
        poll = float(data.get("poll_interval_s", 0.5))
        poll = max(0.25, min(5.0, poll))
        max_rows = int(data.get("max_table_rows", 100))
        max_rows = max(20, min(500, max_rows))
        return cls(
            privacy_mode=privacy,
            alerts_enabled=bool(data.get("alerts_enabled", True)),
            alert_min_score=int(data.get("alert_min_score", 55)),
            digest_interval_s=float(data.get("digest_interval_s", 60.0)),
            sample_connections=bool(data.get("sample_connections", True)),
            poll_interval_s=poll,
            max_table_rows=max_rows,
            ui_density=density,
            show_port_labels=bool(data.get("show_port_labels", True)),
            auto_export_dir=str(data.get("auto_export_dir", "") or ""),
            security_enabled=bool(data.get("security_enabled", True)),
            mon_suspicious_hosts=bool(data.get("mon_suspicious_hosts", True)),
            mon_new_device=bool(data.get("mon_new_device", True)),
            mon_evil_twin=bool(data.get("mon_evil_twin", True)),
            mon_system_files=bool(data.get("mon_system_files", True)),
            mon_device_list=bool(data.get("mon_device_list", True)),
            mon_idle_summary=bool(data.get("mon_idle_summary", True)),
            mon_arp_spoof=bool(data.get("mon_arp_spoof", True)),
            mon_proxy_settings=bool(data.get("mon_proxy_settings", True)),
            mon_traffic=bool(data.get("mon_traffic", True)),
            mon_time_machine=bool(data.get("mon_time_machine", True)),
            mon_first_activity=bool(data.get("mon_first_activity", True)),
        )


class SettingsStore:
    """Load/save AppSettings; in-memory default if file missing."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path or DEFAULT_SETTINGS_PATH
        self.settings = AppSettings()
        self.load()

    def load(self) -> AppSettings:
        try:
            if self.path.exists():
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    self.settings = AppSettings.from_dict(raw)
        except Exception:
            logger.exception("Failed to load settings from %s", self.path)
            self.settings = AppSettings()
        return self.settings

    def save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(
                json.dumps(self.settings.to_dict(), indent=2),
                encoding="utf-8",
            )
        except Exception:
            logger.exception("Failed to save settings to %s", self.path)

    def update(self, **kwargs: Any) -> AppSettings:
        for key, value in kwargs.items():
            if not hasattr(self.settings, key):
                continue
            if key == "privacy_mode" and not isinstance(value, PrivacyMode):
                value = PrivacyMode(str(value))
            if key == "ui_density" and not isinstance(value, UiDensity):
                value = UiDensity(str(value))
            setattr(self.settings, key, value)
        self.save()
        return self.settings

    @property
    def allow_external_lookups(self) -> bool:
        return self.settings.privacy_mode == PrivacyMode.ENRICH
