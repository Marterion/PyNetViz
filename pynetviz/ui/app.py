"""PyNetViz application shell — sidebar navigation, live loop, and shortcuts."""

from __future__ import annotations

import logging
import time
from typing import Optional

import flet as ft

from pynetviz import __app_name__, __version__
from pynetviz.analysis.aggregates import build_aggregates
from pynetviz.analysis.alerts import Alert
from pynetviz.analysis.pipeline import AnalysisPipeline
from pynetviz.analysis.settings import AppSettings, SettingsStore
from pynetviz.collector.connection_collector import ConnectionCollector
from pynetviz.models.connection import ConnectionRecord, DashboardStats, ProcessSummary
from pynetviz.services.geoip_service import GeoIPService
from pynetviz.services.whois_service import WhoisService
from pynetviz.security.engine import SecurityEngine
from pynetviz.ui.dashboard import DashboardView
from pynetviz.ui.history_view import HistoryView
from pynetviz.ui.insights_view import InsightsView
from pynetviz.ui.navigation import (
    TAB_COUNT,
    TAB_DASHBOARD,
    TAB_HISTORY,
    TAB_ICONS,
    TAB_INSIGHTS,
    TAB_NAMES,
    TAB_PROCESSES,
    TAB_SECURITY,
    TAB_SETTINGS,
    NavigationState,
)
from pynetviz.ui.process_view import ProcessView
from pynetviz.ui.security_view import SecurityView
from pynetviz.ui.settings_view import SettingsView
from pynetviz.ui.theme import (
    ACCENT,
    ACCENT_GREEN,
    ACCENT_ORANGE,
    BORDER,
    DARK_BG,
    SIDEBAR_BG,
    SIDEBAR_COLLAPSED,
    SIDEBAR_WIDTH,
    SURFACE,
    SURFACE_ELEVATED,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    apply_dark_theme,
    badge,
    sidebar_item,
)
from pynetviz.ui.tray import SystemTray
from pynetviz.utils.export import ExportFormat, default_export_path, export_records
from pynetviz.utils.platform import get_platform_label, needs_elevation_hint

logger = logging.getLogger(__name__)

# Dashboard/ops paints are heavier — cap UI rebuild rate (~1.5–2 Hz).
UI_MIN_INTERVAL_S = 0.55


class _TabsIndex:
    """Lightweight stand-in for a tab control selected_index."""

    __slots__ = ("selected_index",)

    def __init__(self) -> None:
        self.selected_index = 0

_ICON_MAP = {
    "DASHBOARD_OUTLINED": ft.Icons.DASHBOARD_OUTLINED,
    "APPS_OUTLINED": ft.Icons.APPS_OUTLINED,
    "SHIELD_OUTLINED": getattr(ft.Icons, "SECURITY_OUTLINED", None)
    or getattr(ft.Icons, "SHIELD_OUTLINED", None)
    or ft.Icons.SHIELD,
    "SECURITY_OUTLINED": getattr(ft.Icons, "SECURITY_OUTLINED", None) or ft.Icons.SHIELD,
    "INSIGHTS_OUTLINED": ft.Icons.INSIGHTS_OUTLINED,
    "HISTORY_OUTLINED": ft.Icons.HISTORY_OUTLINED,
    "SETTINGS_OUTLINED": ft.Icons.SETTINGS_OUTLINED,
}


def _safe_page_update(page: Optional[ft.Page]) -> None:
    if not page:
        return
    try:
        page.update()
    except Exception:
        logger.debug("page.update() failed", exc_info=True)


class PyNetVizApp:
    def __init__(self) -> None:
        self.page: Optional[ft.Page] = None
        self.nav = NavigationState()
        self.settings_store = SettingsStore()
        self.analysis = AnalysisPipeline(settings=self.settings_store)
        self.security = SecurityEngine(
            alerts=self.analysis.alerts,
            enabled=self.settings_store.settings.security_enabled,
        )
        self.security.configure(
            enabled=self.settings_store.settings.security_enabled,
            monitor_flags=self.settings_store.settings.security_flags(),
        )
        poll = float(self.settings_store.settings.poll_interval_s or 0.5)
        self.collector = ConnectionCollector(
            poll_interval=poll,
            on_update=self._on_collector_update,
        )
        self.geoip = GeoIPService()
        self.whois = WhoisService()
        self._apply_privacy_to_services()
        self.tray = SystemTray(on_show=self._show_window, on_quit=self._quit)
        self._latest_stats = DashboardStats()
        self._latest_records: list[ConnectionRecord] = []
        self._latest_processes: list[ProcessSummary] = []
        self._updating = False
        self._pending_ui = False
        self._last_ui_paint = 0.0
        self._last_header_key: str = ""
        self._unread_alerts = 0
        self._pending_tray_alerts: list[Alert] = []

    def _apply_privacy_to_services(self) -> None:
        allow = self.settings_store.allow_external_lookups
        self.geoip.allow_external = allow
        self.whois.allow_external = allow

    def _on_settings_saved(self, settings: AppSettings) -> None:
        self.settings_store.settings = settings
        self.settings_store.save()
        self.analysis.reload_settings()
        self._apply_privacy_to_services()
        try:
            self.collector.poll_interval = float(settings.poll_interval_s)
        except Exception:
            pass
        if getattr(self, "process_view", None) is not None:
            try:
                self.process_view.max_rows = max(20, min(500, int(settings.max_table_rows)))
            except Exception:
                pass
        try:
            self.security.configure(
                enabled=settings.security_enabled,
                monitor_flags=settings.security_flags(),
            )
        except Exception:
            logger.debug("security configure failed", exc_info=True)
        mode = settings.privacy_mode.value
        self._toast(f"Settings saved · privacy={mode} · poll={settings.poll_interval_s:.2f}s")

    def _on_mark_alerts_read(self) -> None:
        self.analysis.alerts.mark_all_read()
        self._unread_alerts = 0
        try:
            self.insights_view.update(
                self.analysis.latest_digest,
                high_risk_records=[r for r in self._latest_records if r.risk_score >= 55][:8],
                first_seen_rows=self.analysis.store.recent_first_seen(limit=12),
                alerts=self.analysis.alerts.list_recent(40),
                unread=0,
            )
        except Exception:
            logger.debug("insights refresh after mark-read failed", exc_info=True)
        self.tray.update_stats(
            self._latest_stats.total_connections,
            unread_alerts=0,
        )
        self._refresh_sidebar()
        _safe_page_update(self.page)

    # ── window / tray ────────────────────────────────────────────────────────

    def _show_window(self) -> None:
        if not self.page:
            return

        async def show() -> None:
            self.page.window.visible = True
            await self.page.window.to_front()
            _safe_page_update(self.page)

        self.page.run_task(show)

    def _quit(self) -> None:
        self.collector.stop()
        try:
            self.analysis.store.prune_old(days=14)
        except Exception:
            pass
        try:
            self.analysis.store.close()
        except Exception:
            pass
        self.tray.stop()
        if self.page:

            async def destroy() -> None:
                await self.page.window.destroy()

            self.page.run_task(destroy)

    def _toast(self, message: str) -> None:
        if not self.page:
            return
        try:
            self.page.show_dialog(ft.SnackBar(ft.Text(message)))
            _safe_page_update(self.page)
        except Exception:
            logger.debug("toast failed", exc_info=True)

    def _on_export(self, records: list[ConnectionRecord], fmt: str) -> None:
        if not records:
            self._toast("Nothing to export — wait for live data")
            return
        try:
            export_fmt = ExportFormat.JSON if fmt == "json" else ExportFormat.CSV
            path = default_export_path(export_fmt)
            export_records(records, path, fmt=export_fmt)
            self._toast(f"Exported {len(records)} rows → {path}")
        except Exception as exc:
            logger.exception("export failed")
            self._toast(f"Export failed: {exc}")

    def _on_process_select(self, name: str, pid: int) -> None:
        self.nav.select_process(pid, name)

    # ── tabs / sidebar ───────────────────────────────────────────────────────

    def switch_tab(self, index: int) -> bool:
        changed = self.nav.switch_tab(index)
        if not changed and getattr(self, "tabs_control", None) is not None:
            if self.tabs_control.selected_index != index:
                self.tabs_control.selected_index = index
                changed = True
            else:
                return False
        if not changed:
            return False

        if getattr(self, "tabs_control", None) is not None:
            self.tabs_control.selected_index = index

        self._apply_tab_visibility(index)
        self._refresh_sidebar()

        if index == TAB_SETTINGS and getattr(self, "settings_view", None) is not None:
            try:
                self.settings_view.load(self.settings_store.settings)
            except Exception:
                logger.debug("settings load on tab enter failed", exc_info=True)

        self._paint_active_tab()
        self._last_ui_paint = time.monotonic()
        _safe_page_update(self.page)
        return True

    def _on_tabs_change(self, e=None) -> None:
        idx: Optional[int] = None
        if e is not None:
            data = getattr(e, "data", None)
            if data is not None and str(data).strip() != "":
                try:
                    idx = int(data)
                except (TypeError, ValueError):
                    idx = None
        if idx is None:
            idx = int(getattr(self.tabs_control, "selected_index", 0) or 0)
        if not self.switch_tab(idx):
            return
        logger.info("Tabs change -> %s (%s)", idx, self.nav.tab_name)

    def _apply_tab_visibility(self, index: int) -> None:
        panels = getattr(self, "_tab_panels", None)
        if not panels:
            return
        for i, panel in enumerate(panels):
            try:
                panel.visible = i == index
            except Exception:
                pass

    def _refresh_sidebar(self) -> None:
        """Rebuild the whole sidebar so brand + all tabs (incl. Security) stay visible."""
        shell = getattr(self, "sidebar_shell", None)
        if shell is None:
            return
        shell.width = SIDEBAR_COLLAPSED if self.nav.sidebar_collapsed else SIDEBAR_WIDTH
        shell.content = self._build_sidebar_shell_content()

    def _nav_icon(self, icon_name: str):
        icon = _ICON_MAP.get(icon_name)
        if icon is None:
            icon = getattr(ft.Icons, icon_name, None)
        return icon or ft.Icons.CIRCLE_OUTLINED

    def _build_sidebar_nav_items(self) -> list[ft.Control]:
        active = self.nav.tab_index
        collapsed = self.nav.sidebar_collapsed
        items: list[ft.Control] = []
        # Explicit enumeration — never drop Security if constants change order.
        for idx, name in enumerate(TAB_NAMES):
            icon_name = TAB_ICONS[idx] if idx < len(TAB_ICONS) else "CIRCLE_OUTLINED"
            icon = self._nav_icon(icon_name)
            badge_text = None
            if idx in (TAB_INSIGHTS, TAB_SECURITY) and self._unread_alerts:
                badge_text = str(min(self._unread_alerts, 99))
            # Emphasize Security so it is hard to miss in the rail.
            label = name
            if idx == TAB_SECURITY and not collapsed:
                label = "Security"
            items.append(
                sidebar_item(
                    label,
                    icon,
                    selected=(idx == active),
                    on_click=lambda _e, i=idx: self.switch_tab(i),
                    badge_text=badge_text,
                    collapsed=collapsed,
                )
            )
        return items

    def _build_sidebar_nav(self) -> ft.Column:
        """Nav list as a flex Column (must be direct child of a Column/Row for expand)."""
        return ft.Column(
            self._build_sidebar_nav_items(),
            spacing=4,
            expand=True,
            scroll=ft.ScrollMode.AUTO,
            tight=False,
        )

    def _build_sidebar_shell_content(self) -> ft.Column:
        collapsed = self.nav.sidebar_collapsed
        brand_icon = ft.Container(
            content=ft.Icon(ft.Icons.RADAR, color=ACCENT, size=20),
            bgcolor=f"{ACCENT}18",
            border_radius=10,
            padding=10,
            border=ft.Border.all(1, f"{ACCENT}44"),
        )
        if collapsed:
            brand = brand_icon
        else:
            brand = ft.Row(
                [
                    brand_icon,
                    ft.Column(
                        [
                            ft.Text(
                                __app_name__,
                                size=14,
                                weight=ft.FontWeight.W_700,
                                color=TEXT_PRIMARY,
                            ),
                            ft.Text(
                                f"v{__version__} · OPS",
                                size=10,
                                color=TEXT_MUTED,
                                font_family="Consolas",
                            ),
                        ],
                        spacing=0,
                    ),
                ],
                spacing=10,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            )

        # Keep nav as a direct Column child so expand/scroll work correctly.
        return ft.Column(
            [
                ft.Container(
                    content=brand,
                    padding=ft.Padding.symmetric(horizontal=12, vertical=14),
                ),
                ft.Divider(height=1, color=BORDER),
                ft.Container(
                    content=ft.Text(
                        "NAV" if not collapsed else "·",
                        size=9,
                        color=TEXT_MUTED,
                        font_family="Consolas",
                        weight=ft.FontWeight.W_700,
                    ),
                    padding=ft.Padding.only(left=14, top=8, bottom=4)
                    if not collapsed
                    else ft.Padding.only(top=4, bottom=2),
                ),
                self._build_sidebar_nav(),
                ft.Container(
                    content=ft.IconButton(
                        icon=ft.Icons.MENU_OPEN if not collapsed else ft.Icons.MENU,
                        tooltip="Toggle sidebar (B)",
                        icon_color=TEXT_SECONDARY,
                        on_click=self._toggle_sidebar,
                    ),
                    alignment=ft.Alignment.CENTER,
                    padding=8,
                ),
            ],
            spacing=0,
            expand=True,
        )

    def _toggle_sidebar(self, _e=None) -> None:
        self.nav.toggle_sidebar()
        self._refresh_sidebar()
        _safe_page_update(self.page)

    def _toggle_pause(self, _e=None) -> None:
        paused = self.nav.toggle_pause()
        self._update_pause_chrome()
        self._toast("Live updates paused" if paused else "Live updates resumed")
        _safe_page_update(self.page)

    def _update_pause_chrome(self) -> None:
        paused = self.nav.live_paused
        if getattr(self, "pause_btn", None) is not None:
            self.pause_btn.icon = ft.Icons.PLAY_ARROW if paused else ft.Icons.PAUSE
            self.pause_btn.tooltip = "Resume live (P)" if paused else "Pause live (P)"
            self.pause_btn.icon_color = ACCENT_ORANGE if paused else TEXT_SECONDARY
        if getattr(self, "live_label", None) is not None:
            self.live_label.value = "PAUSED" if paused else "LIVE"
            self.live_label.color = ACCENT_ORANGE if paused else TEXT_SECONDARY
        if getattr(self, "live_dot", None) is not None:
            self.live_dot.bgcolor = ACCENT_ORANGE if paused else ACCENT_GREEN

    def _paint_insights(self) -> None:
        high = sorted(
            [r for r in self._latest_records if r.risk_score >= 55],
            key=lambda r: r.risk_score,
            reverse=True,
        )[:8]
        try:
            first_seen = self.analysis.store.recent_first_seen(limit=12)
        except Exception:
            first_seen = []
        try:
            alerts = self.analysis.alerts.list_recent(40)
            unread = self.analysis.alerts.unread_count()
        except Exception:
            alerts = []
            unread = 0
        prev_unread = self._unread_alerts
        self._unread_alerts = unread
        if unread != prev_unread:
            self._refresh_sidebar()
        digest = self.analysis.latest_digest
        if digest is None:
            from pynetviz.analysis.digest import build_digest

            digest = build_digest(
                self._latest_records,
                self._latest_stats,
                self._latest_processes,
            )
        self.insights_view.update(
            digest,
            high_risk_records=high,
            first_seen_rows=first_seen,
            alerts=alerts,
            unread=unread,
        )

    def _paint_history(self) -> None:
        try:
            hourly = self.analysis.store.recent_hourly(hours=48)
        except Exception:
            hourly = []
        try:
            samples = self.analysis.store.recent_samples(limit=40)
        except Exception:
            samples = []
        self.history_view.update(hourly=hourly, samples=samples)

    def _paint_security(self) -> None:
        if getattr(self, "security_view", None) is None:
            return
        try:
            self.security_view.update(self.security.snapshots())
        except Exception:
            logger.debug("security view paint failed", exc_info=True)

    def _paint_active_tab(self) -> None:
        tab = self.nav.tab_index
        try:
            if tab == TAB_DASHBOARD and getattr(self, "dashboard", None) is not None:
                agg = build_aggregates(self._latest_records)
                self.dashboard.update(self._latest_stats, self._latest_records, agg)
            elif tab == TAB_PROCESSES and getattr(self, "process_view", None) is not None:
                self.process_view.update(self._latest_processes, self._latest_records)
            elif tab == TAB_SECURITY:
                self._paint_security()
            elif tab == TAB_INSIGHTS and getattr(self, "insights_view", None) is not None:
                self._paint_insights()
            elif tab == TAB_HISTORY and getattr(self, "history_view", None) is not None:
                self._paint_history()
            elif tab == TAB_SETTINGS:
                pass
        except Exception:
            logger.exception("paint active tab failed")

    def _on_keyboard(self, e: ft.KeyboardEvent) -> None:
        if not e:
            return
        key = (e.key or "").lower()
        ctrl = bool(getattr(e, "ctrl", False) or getattr(e, "meta", False))

        # Digit keys 1–6 → tabs
        if key in {str(i) for i in range(1, TAB_COUNT + 1)} and not ctrl:
            self.switch_tab(int(key) - 1)
            return
        if key in {"escape", "esc"}:
            return
        if key == " " or key == "space":
            return
        if key == "p" and not ctrl:
            self._toggle_pause()
            return
        if key == "b" and not ctrl:
            self._toggle_sidebar()
            return
        if ctrl and key == "e":
            self._on_export(list(self._latest_records), "csv")
            return

    # ── collector → UI ───────────────────────────────────────────────────────

    def _on_collector_update(
        self,
        records: list[ConnectionRecord],
        stats: DashboardStats,
        processes: list[ProcessSummary],
    ) -> None:
        try:
            result = self.analysis.process(records, stats, processes)
            records = result.records
            for alert in result.new_alerts:
                self._pending_tray_alerts.append(alert)
        except Exception:
            logger.exception("analysis pipeline failed")

        try:
            sec_alerts = self.security.tick(
                records,
                stats,
                processes,
                store=self.analysis.store,
            )
            for alert in sec_alerts:
                self._pending_tray_alerts.append(alert)
        except Exception:
            logger.exception("security engine failed")

        self._latest_stats = stats
        self._latest_records = records
        self._latest_processes = processes

        if not self.page:
            return

        if self.nav.live_paused:
            if getattr(self, "process_view", None) is not None:
                self.process_view.ingest(processes, records)
            return

        if getattr(self, "process_view", None) is not None:
            self.process_view.ingest(processes, records)
        self._pending_ui = True

        if self._updating:
            return

        self._updating = True
        self.page.run_task(self._update_ui_loop)

    async def _update_ui_loop(self) -> None:
        try:
            while self._pending_ui:
                self._pending_ui = False
                now = time.monotonic()

                s = self._latest_stats
                header_changed = False
                painted = False

                try:
                    unread = 0
                    try:
                        unread = self.analysis.alerts.unread_count()
                    except Exception:
                        unread = self._unread_alerts
                    prev_unread = self._unread_alerts
                    self._unread_alerts = unread
                    if unread != prev_unread:
                        self._refresh_sidebar()
                        header_changed = True
                    new_badge = f"{s.total_connections} conn"
                    if unread:
                        new_badge = f"{s.total_connections} conn · {unread}!"
                    new_up = f"↑ {s.upload_bps / 1024:.1f} KB/s"
                    new_down = f"↓ {s.download_bps / 1024:.1f} KB/s"
                    paused_flag = "1" if self.nav.live_paused else "0"
                    header_key = f"{new_badge}|{new_up}|{new_down}|{unread}|{paused_flag}"
                    if header_key != self._last_header_key:
                        header_changed = True
                        self._last_header_key = header_key
                        self.tray.update_stats(s.total_connections, unread_alerts=unread)
                        if not self.nav.live_paused:
                            self.live_dot.bgcolor = ACCENT_GREEN
                        self.header_conn_badge.content = badge(new_badge, color=ACCENT)
                        self.header_up.value = new_up
                        self.header_down.value = new_down
                except Exception:
                    logger.debug("header update failed", exc_info=True)
                    header_changed = True

                if self._pending_tray_alerts:
                    for alert in self._pending_tray_alerts[:5]:
                        try:
                            self.tray.notify_alert(alert.title, alert.body)
                        except Exception:
                            pass
                    self._pending_tray_alerts.clear()
                    header_changed = True

                if (now - self._last_ui_paint) >= UI_MIN_INTERVAL_S:
                    self._last_ui_paint = now
                    painted = True
                    self._paint_active_tab()

                if painted or header_changed:
                    _safe_page_update(self.page)
        except Exception:
            logger.exception("UI update failed")
        finally:
            self._updating = False
            if self._pending_ui and self.page:
                self._updating = True
                self.page.run_task(self._update_ui_loop)

    # ── bootstrap ────────────────────────────────────────────────────────────

    def main(self, page: ft.Page) -> None:
        self.page = page
        apply_dark_theme(page)
        page.title = f"{__app_name__} v{__version__}"
        page.window.width = 1480
        page.window.height = 940
        page.window.min_width = 1080
        page.window.min_height = 700
        page.window.prevent_close = True
        page.window.on_event = self._on_window_event
        page.on_keyboard_event = self._on_keyboard

        if needs_elevation_hint():
            logger.info("Running without elevation; some connections may be hidden.")

        self.dashboard = DashboardView()
        self.process_view = ProcessView(
            on_process_select=self._on_process_select,
            page=page,
            max_rows=self.settings_store.settings.max_table_rows,
        )
        self.security_view = SecurityView()
        self.insights_view = InsightsView(on_mark_alerts_read=self._on_mark_alerts_read)
        self.history_view = HistoryView()
        self.settings_view = SettingsView(on_save=self._on_settings_saved)
        self.settings_view.load(self.settings_store.settings)

        self.live_dot = ft.Container(width=8, height=8, bgcolor=TEXT_MUTED, border_radius=4)
        self.live_label = ft.Text("LIVE", size=10, weight=ft.FontWeight.W_700, color=TEXT_SECONDARY)
        self.header_conn_badge = ft.Container(content=badge("…", color=TEXT_SECONDARY))
        self.header_up = ft.Text("↑ —", size=12, color=ACCENT, weight=ft.FontWeight.W_500)
        self.header_down = ft.Text("↓ —", size=12, color=ACCENT_GREEN, weight=ft.FontWeight.W_500)
        self.pause_btn = ft.IconButton(
            icon=ft.Icons.PAUSE,
            tooltip="Pause live (P)",
            icon_color=TEXT_SECONDARY,
            on_click=self._toggle_pause,
        )

        self.tabs_control = _TabsIndex()
        _raw_tab_bodies = [
            self.dashboard.root,
            self.process_view.root,
            self.security_view.root,
            self.insights_view.root,
            self.history_view.root,
            self.settings_view.root,
        ]
        self._tab_panels = []
        for i, body in enumerate(_raw_tab_bodies):
            self._tab_panels.append(
                ft.Column(
                    [body],
                    expand=True,
                    spacing=0,
                    tight=False,
                    visible=(i == TAB_DASHBOARD),
                    left=0,
                    top=0,
                    right=0,
                    bottom=0,
                )
            )
        self.tab_body_host = ft.Column(
            [
                ft.Stack(
                    controls=self._tab_panels,
                    expand=True,
                    fit=ft.StackFit.EXPAND,
                )
            ],
            expand=True,
            spacing=0,
        )
        self.tab_content_host = self.tab_body_host

        # Keep a handle for tests; content is rebuilt via _build_sidebar_shell_content.
        self.sidebar_nav_host = None
        self.sidebar_shell = ft.Container(
            content=self._build_sidebar_shell_content(),
            width=SIDEBAR_WIDTH,
            bgcolor=SIDEBAR_BG,
            border=ft.Border.only(right=ft.BorderSide(1, BORDER)),
        )

        live_chip = ft.Container(
            content=ft.Row(
                [
                    self.live_dot,
                    self.live_label,
                    ft.Container(width=4),
                    self.header_conn_badge,
                    ft.Container(width=6),
                    self.header_up,
                    self.header_down,
                ],
                spacing=8,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            bgcolor=SURFACE_ELEVATED,
            border=ft.Border.all(1, BORDER),
            border_radius=10,
            padding=ft.Padding.symmetric(horizontal=12, vertical=8),
        )

        header = ft.Container(
            content=ft.Row(
                [
                    ft.Column(
                        [
                            ft.Text(
                                "NETWORK OPERATIONS CENTER",
                                size=15,
                                weight=ft.FontWeight.W_700,
                                color=TEXT_PRIMARY,
                                font_family="Consolas",
                            ),
                            ft.Text(
                                f"{get_platform_label()}  ·  live telemetry  ·  local analysis only",
                                size=11,
                                color=TEXT_MUTED,
                                font_family="Consolas",
                            ),
                        ],
                        spacing=2,
                    ),
                    ft.Container(expand=True),
                    live_chip,
                    self.pause_btn,
                    ft.IconButton(
                        icon=ft.Icons.CACHED_OUTLINED,
                        tooltip="Clear DNS cache",
                        icon_color=TEXT_SECONDARY,
                        on_click=lambda _: self._refresh_dns(),
                    ),
                    ft.IconButton(
                        icon=ft.Icons.DOWNLOAD_OUTLINED,
                        tooltip="Export live snapshot CSV (Ctrl+E)",
                        icon_color=TEXT_SECONDARY,
                        on_click=lambda _: self._on_export(
                            list(self._latest_records),
                            "csv",
                        ),
                    ),
                ],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            bgcolor=SURFACE,
            border=ft.Border.only(bottom=ft.BorderSide(1, BORDER)),
            padding=ft.Padding.symmetric(horizontal=16, vertical=12),
        )

        content_column = ft.Column(
            [
                header,
                self.tab_body_host,
            ],
            expand=True,
            spacing=0,
        )

        page.add(
            ft.Row(
                [
                    self.sidebar_shell,
                    content_column,
                ],
                expand=True,
                spacing=0,
                vertical_alignment=ft.CrossAxisAlignment.STRETCH,
            )
        )

        self.collector.start()
        self.tray.start()
        page.update()

    def _refresh_dns(self) -> None:
        self.collector.dns.clear_cache()
        self._toast("DNS cache cleared")

    def _on_window_event(self, e: ft.WindowEvent) -> None:
        if e.type != ft.WindowEventType.CLOSE or not self.page:
            return

        async def hide() -> None:
            self.page.window.visible = False
            _safe_page_update(self.page)

        self.page.run_task(hide)


def run() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    app = PyNetVizApp()
    ft.run(app.main)
