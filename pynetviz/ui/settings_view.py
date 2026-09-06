"""Settings tab v2: privacy, alerts, poll interval, density, table limits."""

from __future__ import annotations

from typing import Callable, Optional

import flet as ft

from pynetviz.analysis.settings import AppSettings, PrivacyMode, UiDensity
from pynetviz.ui.theme import (
    ACCENT,
    BORDER,
    SURFACE,
    SURFACE_ELEVATED,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    section_title,
)

SCORE_MIN = 30
SCORE_MAX = 90
SCORE_STEP = 5


def snap_alert_score(value) -> int:
    try:
        raw = float(value)
    except (TypeError, ValueError):
        raw = 55.0
    steps = round((raw - SCORE_MIN) / SCORE_STEP)
    snapped = int(SCORE_MIN + steps * SCORE_STEP)
    return max(SCORE_MIN, min(SCORE_MAX, snapped))


def snap_poll_interval(value) -> float:
    try:
        raw = float(value)
    except (TypeError, ValueError):
        raw = 0.5
    # Snap to 0.25 steps
    steps = round(raw / 0.25)
    return max(0.25, min(5.0, steps * 0.25))


class SettingsView:
    def __init__(
        self,
        *,
        on_save: Optional[Callable[[AppSettings], None]] = None,
    ) -> None:
        self.on_save = on_save
        self._settings = AppSettings()
        self._dirty = False

        self.privacy_dd = ft.Dropdown(
            label="Privacy mode",
            options=[
                ft.DropdownOption(
                    key=PrivacyMode.STRICT.value,
                    text="Strict local — no external GeoIP/WHOIS APIs",
                ),
                ft.DropdownOption(
                    key=PrivacyMode.ENRICH.value,
                    text="Enrich — allow GeoIP/WHOIS API lookups",
                ),
            ],
            value=PrivacyMode.ENRICH.value,
            border_color=BORDER,
            focused_border_color=ACCENT,
            bgcolor=SURFACE_ELEVATED,
            color=TEXT_PRIMARY,
            text_size=13,
            border_radius=10,
            on_select=self._on_privacy_select,
        )

        self.alerts_switch = ft.Switch(
            label="Enable alerts",
            value=True,
            active_color=ACCENT,
            on_change=self._on_alerts_toggle,
        )

        self.min_score = ft.Slider(
            min=SCORE_MIN,
            max=SCORE_MAX,
            divisions=(SCORE_MAX - SCORE_MIN) // SCORE_STEP,
            value=float(55),
            label="{value}",
            active_color=ACCENT,
            on_change=self._on_score_change,
            on_change_end=self._on_score_change_end,
        )
        self.min_score_label = ft.Text(
            "Alert min risk score: 55", size=12, color=TEXT_SECONDARY
        )

        self.poll_slider = ft.Slider(
            min=0.25,
            max=5.0,
            divisions=19,
            value=0.5,
            label="{value}s",
            active_color=ACCENT,
            on_change=self._on_poll_change,
            on_change_end=self._on_poll_change_end,
        )
        self.poll_label = ft.Text("Collector poll interval: 0.50s", size=12, color=TEXT_SECONDARY)

        self.max_rows_field = ft.TextField(
            label="Max table rows",
            value="100",
            width=160,
            border_color=BORDER,
            focused_border_color=ACCENT,
            bgcolor=SURFACE_ELEVATED,
            color=TEXT_PRIMARY,
            text_size=13,
            border_radius=10,
            on_change=self._on_rows_change,
            on_blur=self._on_rows_blur,
        )

        self.density_dd = ft.Dropdown(
            label="UI density",
            options=[
                ft.DropdownOption(key=UiDensity.COMFORTABLE.value, text="Comfortable"),
                ft.DropdownOption(key=UiDensity.COMPACT.value, text="Compact"),
            ],
            value=UiDensity.COMFORTABLE.value,
            border_color=BORDER,
            focused_border_color=ACCENT,
            bgcolor=SURFACE_ELEVATED,
            color=TEXT_PRIMARY,
            text_size=13,
            border_radius=10,
            on_select=self._on_density_select,
        )

        self.port_labels_switch = ft.Switch(
            label="Show well-known port labels",
            value=True,
            active_color=ACCENT,
            on_change=self._on_port_labels_toggle,
        )

        self.security_master = ft.Switch(
            label="Enable security monitor suite",
            value=True,
            active_color=ACCENT,
            on_change=self._on_security_toggle,
        )
        self.mon_switches: dict[str, ft.Switch] = {}
        mon_defs = [
            ("mon_suspicious_hosts", "Suspicious Host monitoring"),
            ("mon_new_device", "New Device Connection"),
            ("mon_evil_twin", "Evil Twin Detection"),
            ("mon_system_files", "System File Monitor"),
            ("mon_device_list", "Device List Monitor"),
            ("mon_idle_summary", "Summarized Activity While Idle"),
            ("mon_arp_spoof", "ARP Spoofing Detecting"),
            ("mon_proxy_settings", "Proxy Settings Monitor"),
            ("mon_traffic", "Traffic Monitoring"),
            ("mon_time_machine", "Network Time Machine"),
            ("mon_first_activity", "First Network Activity"),
        ]
        mon_controls: list[ft.Control] = []
        for key, label in mon_defs:
            sw = ft.Switch(
                label=label,
                value=True,
                active_color=ACCENT,
                on_change=self._on_security_toggle,
            )
            self.mon_switches[key] = sw
            mon_controls.append(sw)

        self.status = ft.Text("", size=12, color=ACCENT)

        save_btn = ft.FilledButton(
            content="Save settings",
            icon=ft.Icons.SAVE_OUTLINED,
            on_click=lambda _: self._save(explicit=True),
        )

        self.root = ft.Container(
            content=ft.Column(
                [
                    section_title("Privacy & analysis"),
                    ft.Text(
                        "Strict mode blocks remote enrichment so connection IPs stay on-device. "
                        "Local MaxMind GeoLite2 still works if installed.",
                        size=12,
                        color=TEXT_MUTED,
                    ),
                    self.privacy_dd,
                    ft.Container(height=8),
                    section_title("Alerts"),
                    self.alerts_switch,
                    self.min_score_label,
                    self.min_score,
                    ft.Container(height=8),
                    section_title("Security monitors"),
                    ft.Text(
                        "Ops-center detectors for LAN devices, ARP, Wi‑Fi twins, proxy, "
                        "critical files, and idle activity. See the Security tab.",
                        size=12,
                        color=TEXT_MUTED,
                    ),
                    self.security_master,
                    *mon_controls,
                    ft.Container(height=8),
                    section_title("Performance & display"),
                    self.poll_label,
                    self.poll_slider,
                    ft.Row([self.max_rows_field, self.density_dd], spacing=16),
                    self.port_labels_switch,
                    ft.Container(height=12),
                    ft.Row([save_btn, self.status], spacing=16),
                    ft.Container(height=8),
                    ft.Text(
                        "Shortcuts: 1–6 tabs · P pause · B sidebar · Ctrl+E export snapshot\n"
                        "Data: ~/.pynetviz/analysis.db · Settings: ~/.pynetviz/settings.json · Exports: ~/.pynetviz/exports/",
                        size=11,
                        color=TEXT_MUTED,
                    ),
                ],
                spacing=12,
                scroll=ft.ScrollMode.AUTO,
            ),
            expand=True,
            bgcolor=SURFACE,
            border=ft.Border.all(1, BORDER),
            border_radius=14,
            padding=16,
        )

    def load(self, settings: AppSettings) -> None:
        self._settings = settings
        self._dirty = False
        score = snap_alert_score(settings.alert_min_score)
        self.privacy_dd.value = settings.privacy_mode.value
        self.alerts_switch.value = settings.alerts_enabled
        self.min_score.value = float(score)
        self.min_score_label.value = f"Alert min risk score: {score}"
        poll = snap_poll_interval(settings.poll_interval_s)
        self.poll_slider.value = poll
        self.poll_label.value = f"Collector poll interval: {poll:.2f}s"
        self.max_rows_field.value = str(settings.max_table_rows)
        self.density_dd.value = settings.ui_density.value
        self.port_labels_switch.value = settings.show_port_labels
        self.security_master.value = settings.security_enabled
        for key, sw in self.mon_switches.items():
            sw.value = bool(getattr(settings, key, True))
        self.status.value = ""

    def _score_from_event(self, e=None) -> int:
        if e is not None:
            ctrl = getattr(e, "control", None)
            if ctrl is not None and getattr(ctrl, "value", None) is not None:
                return snap_alert_score(ctrl.value)
        return snap_alert_score(self.min_score.value)

    def _poll_from_event(self, e=None) -> float:
        if e is not None:
            ctrl = getattr(e, "control", None)
            if ctrl is not None and getattr(ctrl, "value", None) is not None:
                return snap_poll_interval(ctrl.value)
        return snap_poll_interval(self.poll_slider.value)

    def _parse_max_rows(self) -> int:
        try:
            n = int(str(self.max_rows_field.value or "100").strip())
        except ValueError:
            n = 100
        return max(20, min(500, n))

    def _current(
        self,
        score: Optional[int] = None,
        poll: Optional[float] = None,
    ) -> AppSettings:
        mode_val = self.privacy_dd.value or PrivacyMode.ENRICH.value
        try:
            mode = PrivacyMode(mode_val)
        except ValueError:
            mode = PrivacyMode.ENRICH
        dens_val = self.density_dd.value or UiDensity.COMFORTABLE.value
        try:
            density = UiDensity(dens_val)
        except ValueError:
            density = UiDensity.COMFORTABLE
        if score is None:
            score = snap_alert_score(self.min_score.value)
        if poll is None:
            poll = snap_poll_interval(self.poll_slider.value)
        return AppSettings(
            privacy_mode=mode,
            alerts_enabled=bool(self.alerts_switch.value),
            alert_min_score=int(score),
            digest_interval_s=self._settings.digest_interval_s,
            sample_connections=self._settings.sample_connections,
            poll_interval_s=float(poll),
            max_table_rows=self._parse_max_rows(),
            ui_density=density,
            show_port_labels=bool(self.port_labels_switch.value),
            auto_export_dir=self._settings.auto_export_dir,
            security_enabled=bool(self.security_master.value),
            **{key: bool(sw.value) for key, sw in self.mon_switches.items()},
        )

    def _on_privacy_select(self, e=None) -> None:
        self._dirty = True
        self.status.value = "Unsaved changes…"
        self._save(explicit=False)

    def _on_alerts_toggle(self, e=None) -> None:
        self._dirty = True
        self.status.value = "Unsaved changes…"
        self._save(explicit=False)

    def _on_density_select(self, e=None) -> None:
        self._dirty = True
        self.status.value = "Unsaved changes…"
        self._save(explicit=False)

    def _on_port_labels_toggle(self, e=None) -> None:
        self._dirty = True
        self.status.value = "Unsaved changes…"
        self._save(explicit=False)

    def _on_security_toggle(self, e=None) -> None:
        self._dirty = True
        self.status.value = "Unsaved changes…"
        self._save(explicit=False)

    def _on_score_change(self, e=None) -> None:
        score = self._score_from_event(e)
        self.min_score.value = float(score)
        self.min_score_label.value = f"Alert min risk score: {score}"
        self._dirty = True
        self.status.value = "Unsaved changes…"

    def _on_score_change_end(self, e=None) -> None:
        score = self._score_from_event(e)
        self.min_score.value = float(score)
        self.min_score_label.value = f"Alert min risk score: {score}"
        self._save(explicit=False, score=score)

    def _on_poll_change(self, e=None) -> None:
        poll = self._poll_from_event(e)
        self.poll_slider.value = poll
        self.poll_label.value = f"Collector poll interval: {poll:.2f}s"
        self._dirty = True
        self.status.value = "Unsaved changes…"

    def _on_poll_change_end(self, e=None) -> None:
        poll = self._poll_from_event(e)
        self.poll_slider.value = poll
        self.poll_label.value = f"Collector poll interval: {poll:.2f}s"
        self._save(explicit=False, poll=poll)

    def _on_rows_change(self, e=None) -> None:
        self._dirty = True
        self.status.value = "Unsaved changes…"

    def _on_rows_blur(self, e=None) -> None:
        self.max_rows_field.value = str(self._parse_max_rows())
        self._save(explicit=False)

    def _save(
        self,
        *,
        explicit: bool = True,
        score: Optional[int] = None,
        poll: Optional[float] = None,
    ) -> None:
        s = self._current(score=score, poll=poll)
        self.min_score.value = float(s.alert_min_score)
        self.min_score_label.value = f"Alert min risk score: {s.alert_min_score}"
        self.poll_slider.value = s.poll_interval_s
        self.poll_label.value = f"Collector poll interval: {s.poll_interval_s:.2f}s"
        self.max_rows_field.value = str(s.max_table_rows)
        self._settings = s
        self._dirty = False
        if self.on_save:
            self.on_save(s)
        self.status.value = "Saved." if explicit else "Saved (auto)."
