from __future__ import annotations

import logging
import time
from typing import Optional

import flet as ft

from pynetviz import __app_name__, __version__
from pynetviz.collector.connection_collector import ConnectionCollector
from pynetviz.models.connection import ConnectionRecord, DashboardStats, ProcessSummary
from pynetviz.services.geoip_service import GeoIPService
from pynetviz.services.whois_service import WhoisService
from pynetviz.ui.connections_table import ConnectionsTable
from pynetviz.ui.dashboard import DashboardView
from pynetviz.ui.detail_pane import DetailPane
from pynetviz.ui.navigation import (
    TAB_CONNECTIONS,
    TAB_DASHBOARD,
    TAB_PROCESSES,
    NavigationState,
)
from pynetviz.ui.process_view import ProcessView
from pynetviz.ui.theme import (
    ACCENT,
    ACCENT_GREEN,
    BORDER,
    DARK_BG,
    SURFACE,
    SURFACE_ELEVATED,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    apply_dark_theme,
    badge,
    nav_tab,
)
from pynetviz.ui.tray import SystemTray
from pynetviz.utils.platform import get_platform_label, needs_elevation_hint

logger = logging.getLogger(__name__)

# UI refresh throttle — never rebuild heavy trees faster than this
UI_MIN_INTERVAL_S = 0.5
# psutil process detail is relatively expensive (oneshot + exe/username on Windows)
PROCESS_DETAIL_TTL_S = 2.0


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
        self.collector = ConnectionCollector(
            poll_interval=0.5,
            on_update=self._on_collector_update,
        )
        self.geoip = GeoIPService()
        self.whois = WhoisService()
        self.tray = SystemTray(on_show=self._show_window, on_quit=self._quit)
        self._selected_record: Optional[ConnectionRecord] = None
        self._latest_stats = DashboardStats()
        self._latest_records: list[ConnectionRecord] = []
        self._latest_processes: list[ProcessSummary] = []
        self._updating = False
        self._pending_ui = False
        self._last_ui_paint = 0.0
        self._last_header_key: str = ""
        # Cache get_process_detail so live paints don't hit psutil every cycle.
        self._process_detail_cache: dict[int, tuple[float, dict]] = {}
        self._last_detail_sig: str = ""

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

    # ── lookups / selection ──────────────────────────────────────────────────

    def _on_copy(self, text: str) -> None:
        if not self.page:
            return

        async def copy_text() -> None:
            await self.page.clipboard.set(text)
            self._toast(f"Copied: {text}")

        self.page.run_task(copy_text)

    def _on_whois(self, ip: str) -> None:
        if not ip or ip in ("0.0.0.0", "::", "*"):
            return

        def callback(result: dict) -> None:
            msg = f"WHOIS {ip}: {result.get('org', 'Unknown')} ({result.get('country', '')})"

            async def apply() -> None:
                if self._selected_record and self.detail_pane.root.visible:
                    self.detail_pane.set_lookup_info(msg)
                self._toast(msg)

            if self.page:
                self.page.run_task(apply)

        self.whois.lookup_async(ip, callback)

    def _on_geoip(self, ip: str) -> None:
        if not ip or ip in ("0.0.0.0", "::", "*"):
            return

        def callback(result: dict) -> None:
            msg = f"GeoIP {ip}: {result.get('city', '?')}, {result.get('country', '?')}"

            async def apply() -> None:
                if self._selected_record and self.detail_pane.root.visible:
                    self.detail_pane.set_lookup_info(msg)
                self._toast(msg)

            if self.page:
                self.page.run_task(apply)

        self.geoip.lookup_async(ip, callback)

    def _get_cached_process_detail(self, pid: int, *, force: bool = False) -> dict:
        """Return process detail, refreshing from psutil at most every PROCESS_DETAIL_TTL_S."""
        now = time.monotonic()
        cached = self._process_detail_cache.get(pid)
        if not force and cached is not None and (now - cached[0]) < PROCESS_DETAIL_TTL_S:
            return cached[1]
        detail = self.collector.get_process_detail(pid)
        self._process_detail_cache[pid] = (now, detail)
        # Bound cache size (one entry per recently selected PID is enough)
        if len(self._process_detail_cache) > 32:
            oldest = min(self._process_detail_cache.items(), key=lambda kv: kv[1][0])
            self._process_detail_cache.pop(oldest[0], None)
        return detail

    @staticmethod
    def _detail_signature(record: ConnectionRecord, detail: dict) -> str:
        """Signature of fields the detail pane displays (skip rebuild when stable)."""
        return (
            f"{record.connection_key}|{record.state}|{record.hostname}|"
            f"{record.bytes_sent}|{record.bytes_recv}|"
            f"{record.last_seen.strftime('%H:%M:%S')}|"
            f"{detail.get('cpu')}|{detail.get('memory_mb')}|"
            f"{detail.get('num_threads')}|{detail.get('status')}|"
            f"{detail.get('username')}|{detail.get('error', '')}"
        )

    def _refresh_selected_detail(self, *, force: bool = False) -> bool:
        """Sync detail pane with latest selected connection. Returns True if UI mutated."""
        if not self._selected_record:
            return False
        if not getattr(self, "detail_pane", None) or not self.detail_pane.root.visible:
            return False

        key = self._selected_record.connection_key
        record: Optional[ConnectionRecord] = None
        for r in self._latest_records:
            if r.connection_key == key:
                record = r
                break
        if record is None:
            # Connection disappeared — keep last painted state (sticky).
            return False

        detail = self._get_cached_process_detail(record.pid, force=force)
        sig = self._detail_signature(record, detail)
        if not force and sig == self._last_detail_sig:
            return False

        self._selected_record = record
        self._last_detail_sig = sig
        self.detail_pane.show_connection(record, detail)
        return True

    def _on_row_select(self, record: ConnectionRecord) -> None:
        self._selected_record = record
        detail = self._get_cached_process_detail(record.pid, force=True)
        self._last_detail_sig = self._detail_signature(record, detail)
        self.detail_pane.show_connection(record, detail)
        _safe_page_update(self.page)

    def _on_detail_close(self) -> None:
        self.detail_pane.hide()
        self._selected_record = None
        self._last_detail_sig = ""
        # Drop row highlight so closed detail and table selection stay in sync.
        try:
            if getattr(self, "connections_table", None) is not None:
                self.connections_table.clear_selection()
        except Exception:
            logger.debug("clear_selection on detail close failed", exc_info=True)
        _safe_page_update(self.page)

    def _on_process_select(self, name: str, pid: int) -> None:
        self.nav.select_process(pid, name)
        try:
            self.connections_table.set_process_filter(name, apply=False)
        except Exception:
            logger.debug("set_process_filter failed", exc_info=True)

    def _sync_process_filter_for_connections(self) -> None:
        """Apply nav process filter when entering Connections (not every live paint).

        Re-asserting on every collector tick fought manual filter edits / Clear.
        """
        filt = self.nav.connection_process_filter
        if not filt or not getattr(self, "connections_table", None):
            return
        try:
            self.connections_table.set_process_filter(filt, apply=False)
        except Exception:
            logger.debug("sync process filter failed", exc_info=True)

    # ── tabs (custom pills + visibility stack — not Flet TabBarView) ─────────
    # TabBarView + nested ListView/TextField fights hit-testing under load and
    # freezes page.update when every tab's subtree is in the control tree.
    # Visibility panels keep only one heavy tree interactive and are reliable.

    def switch_tab(self, index: int) -> bool:
        """Programmatic tab switch (also used by tests). Returns True if changed."""
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
        self._refresh_tab_bar()

        if index == TAB_CONNECTIONS:
            self._sync_process_filter_for_connections()

        # Paint once immediately; stamp paint time so the collector loop
        # does not immediately repaint the same tab (double work under load).
        self._paint_active_tab()
        self._last_ui_paint = time.monotonic()
        _safe_page_update(self.page)
        return True

    def _on_tabs_change(self, e=None) -> None:
        """Tab change handler for tests and optional control events.

        Prefer e.data (index) when present; fall back to tabs_control.selected_index.
        """
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
        # switch_tab owns paint + visibility + page.update
        if not self.switch_tab(idx):
            return
        logger.info("Tabs change -> %s (%s)", idx, self.nav.tab_name)

    def _apply_tab_visibility(self, index: int) -> None:
        """Mount only the active body so inactive heavy lists are not serialized."""
        panels = getattr(self, "_tab_panels", None)
        host = getattr(self, "tab_body_host", None)
        if not panels or host is None:
            return
        if 0 <= index < len(panels):
            host.content = panels[index]

    def _refresh_tab_bar(self) -> None:
        host = getattr(self, "tab_bar_host", None)
        if host is None:
            return
        host.content = self._build_tab_bar_row()

    def _build_tab_bar_row(self) -> ft.Row:
        active = self.nav.tab_index
        defs = (
            (TAB_DASHBOARD, "Dashboard", ft.Icons.DASHBOARD_OUTLINED),
            (TAB_CONNECTIONS, "Connections", ft.Icons.TABLE_ROWS_OUTLINED),
            (TAB_PROCESSES, "Processes", ft.Icons.APPS_OUTLINED),
        )
        chips = [
            nav_tab(
                label,
                icon,
                selected=(idx == active),
                on_click=lambda _e, i=idx: self.switch_tab(i),
            )
            for idx, label, icon in defs
        ]
        return ft.Row(chips, spacing=8, wrap=True)

    def _paint_active_tab(self) -> None:
        """Push latest data into the currently visible tab only."""
        tab = self.nav.tab_index
        try:
            if tab == TAB_DASHBOARD:
                self.dashboard.update(self._latest_stats)
            elif tab == TAB_CONNECTIONS:
                # Do not re-apply nav process filter here — live paints would
                # overwrite the user's filter field / clear-filters action.
                self.connections_table.update(self._latest_records)
            elif tab == TAB_PROCESSES:
                self.process_view.update(self._latest_processes, self._latest_records)
        except Exception:
            logger.exception("paint active tab failed")

    # ── collector → UI ───────────────────────────────────────────────────────

    def _on_collector_update(
        self,
        records: list[ConnectionRecord],
        stats: DashboardStats,
        processes: list[ProcessSummary],
    ) -> None:
        if not self.page:
            return

        # Always store latest (cheap)
        self._latest_stats = stats
        self._latest_records = records
        self._latest_processes = processes
        self.process_view.ingest(processes, records)
        self.connections_table.ingest(records)
        self._pending_ui = True

        if self._updating:
            return

        # Claim the update slot *before* scheduling so a concurrent collector
        # tick cannot start a second update_ui (race with finally re-schedule).
        self._updating = True
        self.page.run_task(self._update_ui_loop)

    async def _update_ui_loop(self) -> None:
        """Coalesce pending collector ticks into one throttled paint cycle."""
        try:
            while self._pending_ui:
                self._pending_ui = False
                now = time.monotonic()

                s = self._latest_stats
                header_changed = False
                painted = False
                detail_changed = False

                # Header is light — skip control mutation + page.update when unchanged.
                try:
                    new_badge = f"{s.total_connections} conn"
                    new_up = f"↑ {s.upload_bps / 1024:.1f} KB/s"
                    new_down = f"↓ {s.download_bps / 1024:.1f} KB/s"
                    header_key = f"{new_badge}|{new_up}|{new_down}"
                    if header_key != self._last_header_key:
                        header_changed = True
                        self._last_header_key = header_key
                        self.tray.update_stats(s.total_connections)
                        self.live_dot.bgcolor = ACCENT_GREEN
                        self.header_conn_badge.content = badge(new_badge, color=ACCENT)
                        self.header_up.value = new_up
                        self.header_down.value = new_down
                except Exception:
                    logger.debug("header update failed", exc_info=True)
                    header_changed = True

                # Throttle heavy tab paint (tab switch paints itself and stamps time)
                if (now - self._last_ui_paint) >= UI_MIN_INTERVAL_S:
                    self._last_ui_paint = now
                    painted = True
                    self._paint_active_tab()
                    if self.nav.is_connections():
                        detail_changed = self._refresh_selected_detail(force=False)

                if painted or header_changed or detail_changed:
                    _safe_page_update(self.page)
        except Exception:
            logger.exception("UI update failed")
        finally:
            # Collector runs on another thread. Between "no pending" and releasing
            # _updating, a tick can set _pending_ui while still seeing _updating
            # True and never schedule — re-check after release to close that gap.
            if self._pending_ui and self.page:
                # Keep _updating claimed; re-enter without opening a race window.
                self.page.run_task(self._update_ui_loop)
            else:
                self._updating = False
                if self._pending_ui and self.page:
                    self._updating = True
                    self.page.run_task(self._update_ui_loop)

    # ── bootstrap ────────────────────────────────────────────────────────────

    def main(self, page: ft.Page) -> None:
        self.page = page
        apply_dark_theme(page)
        page.title = f"{__app_name__} v{__version__}"
        page.window.width = 1440
        page.window.height = 920
        page.window.min_width = 1040
        page.window.min_height = 680
        page.window.prevent_close = True
        page.window.on_event = self._on_window_event

        if needs_elevation_hint():
            logger.info("Running without elevation; some connections may be hidden.")

        self.dashboard = DashboardView()
        self.detail_pane = DetailPane(on_close=self._on_detail_close)
        self.connections_table = ConnectionsTable(
            page=page,
            on_row_select=self._on_row_select,
            on_copy=self._on_copy,
            on_whois=self._on_whois,
            on_geoip=self._on_geoip,
        )
        self.process_view = ProcessView(
            on_process_select=self._on_process_select,
            page=page,
        )

        self.live_dot = ft.Container(width=8, height=8, bgcolor=TEXT_MUTED, border_radius=4)
        self.header_conn_badge = ft.Container(content=badge("…", color=TEXT_SECONDARY))
        self.header_up = ft.Text("↑ —", size=12, color=ACCENT, weight=ft.FontWeight.W_500)
        self.header_down = ft.Text("↓ —", size=12, color=ACCENT_GREEN, weight=ft.FontWeight.W_500)

        connections_body = ft.Row(
            [
                ft.Container(content=self.connections_table.root, expand=True),
                self.detail_pane.root,
            ],
            expand=True,
            spacing=0,
        )

        # Custom pill tabs + content swap (not Flet TabBarView).
        # Only the active body is mounted so page.update stays usable.
        # tabs_control is a small shim so tests can assert selected_index.
        self.tabs_control = type("TabsControl", (), {"selected_index": 0})()
        self._tab_panels = [
            self.dashboard.root,
            connections_body,
            self.process_view.root,
        ]
        self.tab_bar_host = ft.Container(
            content=self._build_tab_bar_row(),
            padding=ft.Padding.only(bottom=4),
        )
        self.tab_body_host = ft.Container(
            content=self._tab_panels[TAB_DASHBOARD],
            expand=True,
        )
        self.tab_content_host = self.tab_body_host
        self.tabs_shell = ft.Column(
            [self.tab_bar_host, self.tab_body_host],
            expand=True,
            spacing=8,
        )

        brand = ft.Row(
            [
                ft.Container(
                    content=ft.Icon(ft.Icons.LAN, color=ACCENT, size=22),
                    bgcolor=f"{ACCENT}22",
                    border_radius=10,
                    padding=10,
                    border=ft.Border.all(1, f"{ACCENT}44"),
                ),
                ft.Column(
                    [
                        ft.Text(__app_name__, size=18, weight=ft.FontWeight.W_700, color=TEXT_PRIMARY),
                        ft.Text(
                            f"Network monitor · {get_platform_label()} · v{__version__}",
                            size=11,
                            color=TEXT_MUTED,
                        ),
                    ],
                    spacing=0,
                ),
            ],
            spacing=12,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        )

        live_chip = ft.Container(
            content=ft.Row(
                [
                    self.live_dot,
                    ft.Text("LIVE", size=10, weight=ft.FontWeight.W_700, color=TEXT_SECONDARY),
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
                    brand,
                    ft.Container(expand=True),
                    live_chip,
                    ft.IconButton(
                        icon=ft.Icons.CACHED_OUTLINED,
                        tooltip="Clear DNS cache",
                        icon_color=TEXT_SECONDARY,
                        on_click=lambda _: self._refresh_dns(),
                    ),
                ],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            bgcolor=SURFACE,
            border=ft.Border.only(bottom=ft.BorderSide(1, BORDER)),
            padding=ft.Padding.symmetric(horizontal=16, vertical=12),
        )

        body = ft.Container(
            content=self.tabs_shell,
            expand=True,
            padding=ft.Padding.symmetric(horizontal=12, vertical=8),
            bgcolor=DARK_BG,
        )

        page.add(
            ft.Column(
                [header, body],
                expand=True,
                spacing=0,
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
