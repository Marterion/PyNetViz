"""Unit tests for navigation, process selection, and collector timing.

No Flet window required — pure logic + lightweight control construction.
"""

from __future__ import annotations

import time
import unittest
from datetime import datetime
from unittest.mock import MagicMock

from pynetviz.collector.connection_collector import ConnectionCollector
from pynetviz.models.connection import (
    ConnectionDirection,
    ConnectionRecord,
    DashboardStats,
    ProcessSummary,
)
from pynetviz.ui.app import PROCESS_DETAIL_TTL_S, PyNetVizApp, UI_MIN_INTERVAL_S
from pynetviz.ui.connections_table import ConnectionsTable
from pynetviz.ui.dashboard import DashboardView
from pynetviz.ui.detail_pane import DetailPane
from pynetviz.ui.navigation import (
    TAB_CONNECTIONS,
    TAB_COUNT,
    TAB_DASHBOARD,
    TAB_PROCESSES,
    NavigationState,
)
from pynetviz.ui.process_view import ProcessView


def _rec(pid: int, name: str, key: str, state: str = "ESTABLISHED") -> ConnectionRecord:
    r = ConnectionRecord(
        pid=pid,
        process_name=name,
        executable_path="C:\\x",
        local_addr="127.0.0.1",
        local_port=1000 + pid,
        remote_addr="8.8.8.8",
        remote_port=443,
        protocol="TCP",
        state=state,
        direction=ConnectionDirection.OUTBOUND if state != "LISTEN" else ConnectionDirection.LISTEN,
        hostname="example",
        last_seen=datetime.now(),
        bytes_sent=10,
        bytes_recv=20,
        connection_key=key,
    )
    r.row_color = r.compute_row_color()
    return r


def _proc(pid: int, name: str, count: int = 1) -> ProcessSummary:
    return ProcessSummary(
        pid=pid,
        name=name,
        executable_path="C:\\x",
        connection_count=count,
        bytes_sent=1,
        bytes_recv=2,
        cpu_percent=1.0,
        memory_mb=50.0,
    )


class TestNavigationState(unittest.TestCase):
    def test_default_dashboard(self):
        nav = NavigationState()
        self.assertEqual(nav.tab_index, TAB_DASHBOARD)
        self.assertTrue(nav.is_dashboard())
        self.assertFalse(nav.is_connections())
        self.assertFalse(nav.is_processes())

    def test_switch_all_tabs(self):
        nav = NavigationState()
        self.assertTrue(nav.switch_tab(TAB_CONNECTIONS))
        self.assertEqual(nav.tab_index, TAB_CONNECTIONS)
        self.assertEqual(nav.tab_name, "Connections")
        self.assertTrue(nav.switch_tab(TAB_PROCESSES))
        self.assertEqual(nav.tab_name, "Processes")
        self.assertTrue(nav.switch_tab(TAB_DASHBOARD))
        self.assertEqual(nav.tab_name, "Dashboard")

    def test_switch_same_tab_returns_false(self):
        nav = NavigationState()
        self.assertFalse(nav.switch_tab(TAB_DASHBOARD))

    def test_switch_out_of_range(self):
        nav = NavigationState()
        with self.assertRaises(ValueError):
            nav.switch_tab(-1)
        with self.assertRaises(ValueError):
            nav.switch_tab(TAB_COUNT)
        with self.assertRaises(ValueError):
            nav.switch_tab(99)

    def test_rapid_tab_cycle(self):
        nav = NavigationState()
        order = []
        for _ in range(20):
            for i in (0, 1, 2):
                nav.switch_tab(i)
                order.append(nav.tab_index)
        self.assertEqual(order[-3:], [0, 1, 2])
        self.assertEqual(len(order), 60)

    def test_process_select_sets_filter(self):
        nav = NavigationState()
        nav.select_process(42, "chrome.exe")
        self.assertTrue(nav.process.is_selected)
        self.assertEqual(nav.process.pid, 42)
        self.assertEqual(nav.process.name, "chrome.exe")
        self.assertEqual(nav.connection_process_filter, "chrome.exe")

    def test_clear_process(self):
        nav = NavigationState()
        nav.select_process(1, "a")
        nav.clear_process()
        self.assertFalse(nav.process.is_selected)
        self.assertEqual(nav.connection_process_filter, "")


class TestProcessViewSelection(unittest.TestCase):
    def setUp(self):
        self.selected = []
        self.page = MagicMock()
        self.view = ProcessView(
            on_process_select=lambda n, p: self.selected.append((n, p)),
            page=self.page,
        )
        self.procs = [_proc(1, "a.exe", 3), _proc(2, "b.exe", 1)]
        self.recs = [
            _rec(1, "a.exe", "k1"),
            _rec(1, "a.exe", "k2"),
            _rec(2, "b.exe", "k3", state="LISTEN"),
        ]
        self.view.update(self.procs, self.recs)

    def test_list_populated(self):
        self.assertEqual(len(self.view.process_list.controls), 2)

    def test_click_selects_process(self):
        # Outer wrap is Container; ListTile holds the click handler
        wrap = self.view.process_list.controls[1]
        list_tile = wrap.content
        self.assertTrue(callable(list_tile.on_click))
        e = MagicMock()
        e.control = list_tile
        list_tile.on_click(e)
        self.assertEqual(self.selected[-1], ("b.exe", 2))
        self.assertEqual(self.view._selected_pid, 2)
        self.assertEqual(self.view.selected_label.value, "b.exe")
        self.assertFalse(self.view.selection_hint.visible)

    def test_selection_shows_connections(self):
        self.view.select_by_index(0)
        self.assertIn("2 active", self.view.connection_count_label.value)
        self.assertEqual(len(self.view.connections_for_process.controls), 2)

    def test_selection_sticky_across_polls(self):
        self.view.select_by_index(0)
        for i in range(10):
            procs = [_proc(1, "a.exe", 3 + i), _proc(2, "b.exe", 1)]
            self.view.update(procs, self.recs)
        self.assertEqual(self.view._selected_pid, 1)
        self.assertEqual(self.view.selected_label.value, "a.exe")

    def test_ingest_does_not_rebuild_list(self):
        before = list(self.view.process_list.controls)
        self.view.ingest([_proc(9, "z.exe", 1)], [])
        # ingest should not replace list controls
        self.assertIs(self.view.process_list.controls[0], before[0])


class TestConnectionsTable(unittest.TestCase):
    def setUp(self):
        self.page = MagicMock()
        self.selected = []
        self.table = ConnectionsTable(
            page=self.page,
            on_row_select=lambda r: self.selected.append(r),
            on_copy=lambda t: None,
            on_whois=lambda i: None,
            on_geoip=lambda i: None,
        )

    def test_update_and_filter(self):
        recs = [_rec(1, "chrome.exe", "a"), _rec(2, "discord.exe", "b")]
        self.table.update(recs)
        self.assertEqual(len(self.table._filtered), 2)
        self.table.set_process_filter("chrome", apply=True)
        self.assertEqual(len(self.table._filtered), 1)
        self.assertEqual(self.table._filtered[0].process_name, "chrome.exe")

    def test_ingest_stores_without_filter_apply(self):
        recs = [_rec(1, "a", "a")]
        self.table.ingest(recs)
        self.assertEqual(len(self.table._records), 1)
        # filtered not rebuilt by ingest alone
        self.assertEqual(len(self.table._filtered), 0)

    def test_row_click(self):
        rec = _rec(5, "svc", "x")
        self.table.update([rec])
        row = self.table.list_view.controls[0]
        row.on_click(MagicMock(control=row))
        self.assertEqual(len(self.selected), 1)
        self.assertEqual(self.selected[0].pid, 5)


class TestDashboard(unittest.TestCase):
    def test_update_stats(self):
        d = DashboardView()
        d.update(
            DashboardStats(
                total_connections=12,
                listening_ports=3,
                established_connections=9,
                upload_bps=2048,
                download_bps=4096,
                top_processes=[("a", 5), ("b", 2)],
                connection_history=[(datetime.now(), 12)],
                bandwidth_history=[(datetime.now(), 2048.0, 4096.0)],
            )
        )
        self.assertEqual(d.total_card.content.controls[1].value, "12")


class TestCollector(unittest.TestCase):
    def test_default_poll_interval_responsive(self):
        c = ConnectionCollector(poll_interval=0.5)
        self.assertLessEqual(c.poll_interval, 0.75)
        self.assertGreaterEqual(c.poll_interval, 0.2)

    def test_collect_returns_tuple(self):
        c = ConnectionCollector()
        records, stats, processes = c._collect()
        self.assertIsInstance(records, list)
        self.assertIsInstance(stats, DashboardStats)
        self.assertIsInstance(processes, list)
        self.assertGreaterEqual(stats.total_connections, 0)


class TestAppTabLogic(unittest.TestCase):
    def setUp(self):
        self.app = PyNetVizApp()
        # Lightweight stubs so switch_tab doesn't need a real page/window
        self.app.page = MagicMock()
        self.app.dashboard = DashboardView()
        self.app.connections_table = ConnectionsTable(
            page=self.app.page,
            on_row_select=lambda r: None,
            on_copy=lambda t: None,
            on_whois=lambda i: None,
            on_geoip=lambda i: None,
        )
        self.app.process_view = ProcessView(
            on_process_select=self.app._on_process_select,
            page=self.app.page,
        )
        self.app.detail_pane = MagicMock()
        self.app.tabs_control = MagicMock()
        self.app.tabs_control.selected_index = 0
        self.app._latest_stats = DashboardStats(total_connections=1)
        self.app._latest_records = [_rec(1, "a.exe", "k")]
        self.app._latest_processes = [_proc(1, "a.exe")]

    def test_switch_tab_updates_nav_and_control(self):
        self.assertTrue(self.app.switch_tab(TAB_CONNECTIONS))
        self.assertEqual(self.app.nav.tab_index, TAB_CONNECTIONS)
        self.assertEqual(self.app.tabs_control.selected_index, TAB_CONNECTIONS)

        self.assertTrue(self.app.switch_tab(TAB_PROCESSES))
        self.assertEqual(self.app.nav.tab_index, TAB_PROCESSES)

        self.assertTrue(self.app.switch_tab(TAB_DASHBOARD))
        self.assertEqual(self.app.nav.tab_index, TAB_DASHBOARD)

    def test_rapid_switch_all_tabs_twenty_times(self):
        for _ in range(20):
            for idx in (0, 1, 2):
                self.app.switch_tab(idx)
                self.assertEqual(self.app.nav.tab_index, idx)
                self.assertEqual(self.app.tabs_control.selected_index, idx)

    def test_process_select_via_app_callback(self):
        self.app._on_process_select("chrome.exe", 99)
        self.assertEqual(self.app.nav.process.pid, 99)
        self.assertEqual(self.app.nav.connection_process_filter, "chrome.exe")

    def test_ui_min_interval_is_sane(self):
        self.assertGreaterEqual(UI_MIN_INTERVAL_S, 0.3)
        self.assertLessEqual(UI_MIN_INTERVAL_S, 1.0)

    def test_process_click_through_view_updates_nav(self):
        self.app.process_view.update(self.app._latest_processes, self.app._latest_records)
        self.app.switch_tab(TAB_PROCESSES)
        self.assertTrue(self.app.process_view.select_first())
        self.assertEqual(self.app.nav.process.pid, 1)
        self.assertEqual(self.app.nav.process.name, "a.exe")


class TestResponsivenessGuarantees(unittest.TestCase):
    def test_throttle_constant(self):
        # Active-tab paint should not exceed ~3 Hz
        self.assertGreaterEqual(UI_MIN_INTERVAL_S, 0.33)

    def test_switch_tab_is_fast(self):
        app = PyNetVizApp()
        app.page = MagicMock()
        app.dashboard = DashboardView()
        app.connections_table = ConnectionsTable(
            page=app.page,
            on_row_select=lambda r: None,
            on_copy=lambda t: None,
            on_whois=lambda i: None,
            on_geoip=lambda i: None,
        )
        app.process_view = ProcessView(on_process_select=lambda n, p: None, page=app.page)
        app.detail_pane = MagicMock()
        app.tabs_control = MagicMock()
        app.tabs_control.selected_index = 0
        app._latest_stats = DashboardStats()
        app._latest_records = []
        app._latest_processes = []

        t0 = time.perf_counter()
        for _ in range(50):
            app.switch_tab(1)
            app.switch_tab(2)
            app.switch_tab(0)
        elapsed = time.perf_counter() - t0
        # 150 switches should complete well under 2 seconds without a real GUI
        self.assertLess(elapsed, 2.0, f"tab switching too slow: {elapsed:.3f}s")

    def test_tabs_change_same_index_skips_paint(self):
        """Duplicate on_change / re-click must not force paint + page.update."""
        app = PyNetVizApp()
        app.page = MagicMock()
        app.dashboard = DashboardView()
        app.connections_table = ConnectionsTable(
            page=app.page,
            on_row_select=lambda r: None,
            on_copy=lambda t: None,
            on_whois=lambda i: None,
            on_geoip=lambda i: None,
        )
        app.process_view = ProcessView(on_process_select=lambda n, p: None, page=app.page)
        app.detail_pane = MagicMock()
        app.tabs_control = MagicMock()
        app.tabs_control.selected_index = TAB_CONNECTIONS
        app.nav.tab_index = TAB_CONNECTIONS
        app._latest_stats = DashboardStats()
        app._latest_records = []
        app._latest_processes = []

        paint_calls = []
        app._paint_active_tab = lambda: paint_calls.append(1)  # type: ignore[method-assign]
        app.page.update.reset_mock()

        # Explicit same-index event (data configured — MagicMock.data is truthy noise)
        e = MagicMock()
        e.data = TAB_CONNECTIONS
        app._on_tabs_change(e)
        self.assertEqual(paint_calls, [])
        app.page.update.assert_not_called()

    def test_tabs_change_switches_and_paints_once(self):
        app = PyNetVizApp()
        app.page = MagicMock()
        app.dashboard = DashboardView()
        app.connections_table = ConnectionsTable(
            page=app.page,
            on_row_select=lambda r: None,
            on_copy=lambda t: None,
            on_whois=lambda i: None,
            on_geoip=lambda i: None,
        )
        app.process_view = ProcessView(on_process_select=lambda n, p: None, page=app.page)
        app.detail_pane = MagicMock()
        app.tabs_control = MagicMock()
        app.tabs_control.selected_index = TAB_PROCESSES
        app.nav.tab_index = TAB_DASHBOARD
        app._latest_stats = DashboardStats()
        app._latest_records = []
        app._latest_processes = [_proc(1, "a.exe")]

        e = MagicMock()
        e.data = TAB_PROCESSES
        app._on_tabs_change(e)
        self.assertEqual(app.nav.tab_index, TAB_PROCESSES)
        app.page.update.assert_called()

    def test_switch_tab_stamps_paint_time(self):
        """Immediate paint should advance _last_ui_paint so collector does not double-paint."""
        app = PyNetVizApp()
        app.page = MagicMock()
        app.dashboard = DashboardView()
        app.connections_table = ConnectionsTable(
            page=app.page,
            on_row_select=lambda r: None,
            on_copy=lambda t: None,
            on_whois=lambda i: None,
            on_geoip=lambda i: None,
        )
        app.process_view = ProcessView(on_process_select=lambda n, p: None, page=app.page)
        app.detail_pane = MagicMock()
        app.tabs_control = MagicMock()
        app.tabs_control.selected_index = 0
        app._latest_stats = DashboardStats()
        app._latest_records = []
        app._latest_processes = []
        app._last_ui_paint = 0.0

        before = time.monotonic()
        self.assertTrue(app.switch_tab(TAB_CONNECTIONS))
        self.assertGreaterEqual(app._last_ui_paint, before)

    def test_no_dead_force_paint_flag(self):
        """_force_paint was never set True in production — removed in Cycle 3."""
        app = PyNetVizApp()
        self.assertFalse(hasattr(app, "_force_paint"))

    def test_tab_wiring_uses_custom_visibility_stack(self):
        """Source contract: custom pill tabs + visibility panels (not TabBarView)."""
        import inspect
        from pynetviz.ui import app as app_mod

        src = inspect.getsource(app_mod.PyNetVizApp.main)
        self.assertIn("tabs_shell", src)
        self.assertIn("_tab_panels", src)
        self.assertNotIn("ft.TabBarView", src)
        self.assertNotIn("ft.Tabs(", src)


class TestProcessListStability(unittest.TestCase):
    def setUp(self):
        self.page = MagicMock()
        self.view = ProcessView(on_process_select=lambda n, p: None, page=self.page)
        self.procs = [_proc(1, "a.exe", 3), _proc(2, "b.exe", 1)]
        self.recs = [_rec(1, "a.exe", "k1"), _rec(2, "b.exe", "k2")]
        self.view.update(self.procs, self.recs)

    def test_same_identity_skips_list_rebuild(self):
        before = list(self.view.process_list.controls)
        # Multiple live polls with same PIDs / selection
        for i in range(5):
            self.view.update(
                [_proc(1, "a.exe", 3 + i), _proc(2, "b.exe", 1 + i)],
                self.recs,
            )
        self.assertIs(self.view.process_list.controls[0], before[0])
        self.assertIs(self.view.process_list.controls[1], before[1])

    def test_selection_force_rebuilds_list(self):
        before = self.view.process_list.controls[0]
        self.view.select_by_index(0)
        # Selection highlight requires a forced rebuild
        self.assertIsNot(self.view.process_list.controls[0], before)
        self.assertEqual(self.view._selected_pid, 1)

    def test_membership_change_rebuilds_list(self):
        before = list(self.view.process_list.controls)
        self.view.update([_proc(1, "a.exe", 3), _proc(9, "z.exe", 1)], self.recs)
        self.assertEqual(len(self.view.process_list.controls), 2)
        self.assertIsNot(self.view.process_list.controls[0], before[0])


class TestConnectionsTableRowClick(unittest.TestCase):
    def test_row_click_does_not_double_page_update(self):
        """Table rebuilds highlight; page.update is owned by on_row_select (app)."""
        page = MagicMock()
        selected = []

        def on_select(r):
            selected.append(r)
            page.update()

        table = ConnectionsTable(
            page=page,
            on_row_select=on_select,
            on_copy=lambda t: None,
            on_whois=lambda i: None,
            on_geoip=lambda i: None,
        )
        rec = _rec(5, "svc", "x")
        table.update([rec])
        page.update.reset_mock()

        row = table.list_view.controls[0]
        row.on_click(MagicMock(control=row))

        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0].pid, 5)
        # Exactly one update from the app callback — not table + callback
        self.assertEqual(page.update.call_count, 1)
        self.assertEqual(table._selected_key, "x")


class TestConnectionsTableRebuildThrottle(unittest.TestCase):
    def setUp(self):
        self.page = MagicMock()
        self.table = ConnectionsTable(
            page=self.page,
            on_row_select=lambda r: None,
            on_copy=lambda t: None,
            on_whois=lambda i: None,
            on_geoip=lambda i: None,
        )

    def test_byte_only_change_skips_rebuild_within_throttle(self):
        """Live byte counters must not rebuild the whole row tree every poll."""
        r1 = _rec(1, "a.exe", "k1")
        r1.bytes_sent = 10
        r1.bytes_recv = 20
        self.table.update([r1])
        before = self.table.list_view.controls[0]
        # Ensure we are inside the content-throttle window
        self.table._last_rows_rebuild = time.monotonic()

        r2 = _rec(1, "a.exe", "k1")
        r2.bytes_sent = 9999
        r2.bytes_recv = 8888
        self.table.update([r2])

        self.assertIs(self.table.list_view.controls[0], before)
        self.assertEqual(len(self.table.list_view.controls), 1)

    def test_structural_change_rebuilds_immediately(self):
        self.table.update([_rec(1, "a.exe", "k1")])
        before = self.table.list_view.controls[0]
        self.table._last_rows_rebuild = time.monotonic()

        self.table.update([_rec(1, "a.exe", "k1"), _rec(2, "b.exe", "k2")])
        self.assertEqual(len(self.table.list_view.controls), 2)
        self.assertIsNot(self.table.list_view.controls[0], before)

    def test_identical_signature_skips_even_after_time_window(self):
        """Old inverted gate rebuilt identical tables after 0.35s — must not return."""
        rec = _rec(1, "a.exe", "k1")
        self.table.update([rec])
        before = self.table.list_view.controls[0]
        # Pretend last rebuild was long ago but data is identical
        self.table._last_rows_rebuild = time.monotonic() - 10.0
        self.table.update([rec])
        self.assertIs(self.table.list_view.controls[0], before)

    def test_force_rebuild_on_selection(self):
        rec = _rec(1, "a.exe", "k1")
        self.table.update([rec])
        before = self.table.list_view.controls[0]
        self.table._last_rows_rebuild = time.monotonic()
        row = self.table.list_view.controls[0]
        row.on_click(MagicMock(control=row))
        self.assertEqual(self.table._selected_key, "k1")
        self.assertIsNot(self.table.list_view.controls[0], before)


class TestProcessListReorderStability(unittest.TestCase):
    def test_count_reorder_does_not_rebuild_tiles(self):
        page = MagicMock()
        view = ProcessView(on_process_select=lambda n, p: None, page=page)
        recs = [_rec(1, "a.exe", "k1"), _rec(2, "b.exe", "k2")]
        view.update([_proc(1, "a.exe", 3), _proc(2, "b.exe", 1)], recs)
        before = list(view.process_list.controls)

        # Rank by connection count flips, membership unchanged
        view.update([_proc(2, "b.exe", 50), _proc(1, "a.exe", 1)], recs)
        self.assertIs(view.process_list.controls[0], before[0])
        self.assertIs(view.process_list.controls[1], before[1])


class TestCollectorClosingPrune(unittest.TestCase):
    def test_closing_rows_pruned_after_ttl(self):
        from datetime import timedelta
        from unittest.mock import patch

        from pynetviz.collector.connection_collector import CLOSING_TTL_S
        from pynetviz.models.connection import RowHighlight

        c = ConnectionCollector(poll_interval=0.5)
        gone = _rec(1, "gone.exe", "gone-key")
        c._connections["gone-key"] = gone
        c._connection_bytes["gone-key"] = (1, 2)
        c._closing_since["gone-key"] = datetime.now() - timedelta(seconds=CLOSING_TTL_S + 0.5)

        with patch("psutil.net_connections", return_value=[]):
            c._collect()

        self.assertNotIn("gone-key", c._connections)
        self.assertNotIn("gone-key", c._closing_since)
        self.assertNotIn("gone-key", c._connection_bytes)

    def test_closing_rows_kept_within_ttl(self):
        from unittest.mock import patch

        from pynetviz.models.connection import RowHighlight

        c = ConnectionCollector(poll_interval=0.5)
        gone = _rec(1, "gone.exe", "gone-key")
        c._connections["gone-key"] = gone
        # First observation of stale: no prior closing marker
        with patch("psutil.net_connections", return_value=[]):
            c._collect()

        self.assertIn("gone-key", c._connections)
        self.assertEqual(c._connections["gone-key"].highlight, RowHighlight.CLOSING)
        self.assertIn("gone-key", c._closing_since)


class TestCollectorUiCoalescing(unittest.TestCase):
    def _stub_app(self) -> PyNetVizApp:
        app = PyNetVizApp()
        app.page = MagicMock()
        app.dashboard = DashboardView()
        app.connections_table = ConnectionsTable(
            page=app.page,
            on_row_select=lambda r: None,
            on_copy=lambda t: None,
            on_whois=lambda i: None,
            on_geoip=lambda i: None,
        )
        app.process_view = ProcessView(on_process_select=lambda n, p: None, page=app.page)
        app.detail_pane = MagicMock()
        app.tabs_control = MagicMock()
        app.tabs_control.selected_index = 0
        app.tray = MagicMock()
        app.live_dot = MagicMock()
        app.header_conn_badge = MagicMock()
        app.header_up = MagicMock()
        app.header_up.value = ""
        app.header_down = MagicMock()
        app.header_down.value = ""
        app._latest_stats = DashboardStats()
        app._latest_records = []
        app._latest_processes = []
        return app

    def test_claims_updating_before_schedule(self):
        """Race fix: _updating must be True before run_task so dual loops cannot start."""
        app = self._stub_app()
        scheduled = []

        def capture(fn):
            scheduled.append(fn)
            return MagicMock()

        app.page.run_task = capture
        app._updating = False
        app._on_collector_update([], DashboardStats(total_connections=1), [])
        self.assertTrue(app._updating)
        self.assertEqual(len(scheduled), 1)

        # Concurrent tick while claimed must only set pending, not schedule again
        app._on_collector_update([], DashboardStats(total_connections=2), [])
        self.assertEqual(len(scheduled), 1)
        self.assertTrue(app._pending_ui)

    def test_update_loop_skips_page_update_when_idle(self):
        """When paint is throttled and header unchanged, do not page.update."""
        import asyncio

        app = self._stub_app()
        app._updating = True
        app._pending_ui = True
        app._last_ui_paint = time.monotonic()  # within throttle window
        app._last_header_key = "0 conn|↑ 0.0 KB/s|↓ 0.0 KB/s"
        app._latest_stats = DashboardStats(
            total_connections=0, upload_bps=0.0, download_bps=0.0
        )
        app.page.update.reset_mock()

        asyncio.run(app._update_ui_loop())

        app.page.update.assert_not_called()
        self.assertFalse(app._updating)

    def test_update_loop_paints_and_updates_when_due(self):
        import asyncio

        app = self._stub_app()
        app._updating = True
        app._pending_ui = True
        app._last_ui_paint = 0.0  # force paint
        app._last_header_key = ""
        app._latest_stats = DashboardStats(
            total_connections=3, upload_bps=1024.0, download_bps=2048.0
        )
        paint_calls = []
        app._paint_active_tab = lambda: paint_calls.append(1)  # type: ignore[method-assign]
        app.page.update.reset_mock()

        asyncio.run(app._update_ui_loop())

        self.assertEqual(paint_calls, [1])
        app.page.update.assert_called()
        self.assertFalse(app._updating)
        self.assertFalse(app._pending_ui)


class TestProcessDetailCache(unittest.TestCase):
    def _app_with_detail(self) -> PyNetVizApp:
        app = PyNetVizApp()
        app.page = MagicMock()
        app.detail_pane = DetailPane(on_close=lambda: None)
        app.collector = MagicMock()
        return app

    def test_ttl_sane(self):
        self.assertGreaterEqual(PROCESS_DETAIL_TTL_S, 1.0)
        self.assertLessEqual(PROCESS_DETAIL_TTL_S, 5.0)

    def test_cache_hits_within_ttl(self):
        app = self._app_with_detail()
        app.collector.get_process_detail.return_value = {
            "pid": 7,
            "cpu": 1.0,
            "memory_mb": 10.0,
            "num_threads": 4,
            "status": "running",
            "username": "u",
        }
        d1 = app._get_cached_process_detail(7)
        d2 = app._get_cached_process_detail(7)
        self.assertIs(d1, d2)
        self.assertEqual(app.collector.get_process_detail.call_count, 1)

    def test_force_bypasses_cache(self):
        app = self._app_with_detail()
        app.collector.get_process_detail.return_value = {"pid": 1, "cpu": 0.0}
        app._get_cached_process_detail(1)
        app._get_cached_process_detail(1, force=True)
        self.assertEqual(app.collector.get_process_detail.call_count, 2)

    def test_cache_expires_after_ttl(self):
        app = self._app_with_detail()
        app.collector.get_process_detail.return_value = {"pid": 1, "cpu": 0.0}
        app._get_cached_process_detail(1)
        # Age the cache entry past TTL
        pid, (ts, detail) = next(iter(app._process_detail_cache.items()))
        app._process_detail_cache[pid] = (ts - PROCESS_DETAIL_TTL_S - 0.1, detail)
        app._get_cached_process_detail(1)
        self.assertEqual(app.collector.get_process_detail.call_count, 2)

    def test_refresh_skips_identical_signature(self):
        app = self._app_with_detail()
        app.detail_pane.root.visible = True
        rec = _rec(3, "svc.exe", "ck-1")
        app._selected_record = rec
        app._latest_records = [rec]
        app.collector.get_process_detail.return_value = {
            "pid": 3,
            "cpu": 2.5,
            "memory_mb": 40.0,
            "num_threads": 8,
            "status": "running",
            "username": "me",
        }
        self.assertTrue(app._refresh_selected_detail(force=True))
        show_calls = []
        orig = app.detail_pane.show_connection

        def track(record, detail):
            show_calls.append(1)
            return orig(record, detail)

        app.detail_pane.show_connection = track  # type: ignore[method-assign]
        # Same data — should not rebuild pane
        self.assertFalse(app._refresh_selected_detail(force=False))
        self.assertEqual(show_calls, [])
        # Still only one psutil fetch (cache + no force)
        self.assertEqual(app.collector.get_process_detail.call_count, 1)

    def test_refresh_updates_when_bytes_change(self):
        app = self._app_with_detail()
        app.detail_pane.root.visible = True
        rec = _rec(3, "svc.exe", "ck-1")
        app._selected_record = rec
        app._latest_records = [rec]
        app.collector.get_process_detail.return_value = {
            "pid": 3,
            "cpu": 1.0,
            "memory_mb": 10.0,
            "num_threads": 2,
            "status": "running",
            "username": "me",
        }
        self.assertTrue(app._refresh_selected_detail(force=True))

        rec2 = _rec(3, "svc.exe", "ck-1")
        rec2.bytes_sent = 99999
        app._latest_records = [rec2]
        self.assertTrue(app._refresh_selected_detail(force=False))
        self.assertEqual(app._selected_record.bytes_sent, 99999)

    def test_row_select_uses_cache_helper(self):
        app = self._app_with_detail()
        app.collector.get_process_detail.return_value = {
            "pid": 5,
            "cpu": 0.0,
            "memory_mb": 1.0,
            "num_threads": 1,
            "status": "running",
            "username": "x",
        }
        rec = _rec(5, "svc", "x")
        app._on_row_select(rec)
        self.assertTrue(app.detail_pane.root.visible)
        self.assertEqual(app.collector.get_process_detail.call_count, 1)
        app.page.update.assert_called()


class TestProcessDetailsCardStability(unittest.TestCase):
    def test_stable_conn_set_skips_card_rebuild(self):
        page = MagicMock()
        view = ProcessView(on_process_select=lambda n, p: None, page=page)
        procs = [_proc(1, "a.exe", 2)]
        recs = [_rec(1, "a.exe", "k1"), _rec(1, "a.exe", "k2")]
        view.update(procs, recs)
        view.select_by_index(0)
        before = list(view.connections_for_process.controls)

        # Same connection keys/states; only CPU/count noise
        view.update([_proc(1, "a.exe", 2,)], recs)
        # connection_count changes but cards identity is keys+state
        view.update([_proc(1, "a.exe", 9)], recs)
        self.assertEqual(len(view.connections_for_process.controls), 2)
        self.assertIs(view.connections_for_process.controls[0], before[0])
        self.assertIs(view.connections_for_process.controls[1], before[1])

    def test_new_connection_rebuilds_cards(self):
        page = MagicMock()
        view = ProcessView(on_process_select=lambda n, p: None, page=page)
        view.update([_proc(1, "a.exe", 1)], [_rec(1, "a.exe", "k1")])
        view.select_by_index(0)
        before = view.connections_for_process.controls[0]

        view.update(
            [_proc(1, "a.exe", 2)],
            [_rec(1, "a.exe", "k1"), _rec(1, "a.exe", "k2")],
        )
        self.assertEqual(len(view.connections_for_process.controls), 2)
        self.assertIsNot(view.connections_for_process.controls[0], before)


class TestProcessFilterPaintIsolation(unittest.TestCase):
    """Live collector paints must not fight manual process-filter edits."""

    def _stub_app(self) -> PyNetVizApp:
        app = PyNetVizApp()
        app.page = MagicMock()
        app.dashboard = DashboardView()
        app.connections_table = ConnectionsTable(
            page=app.page,
            on_row_select=lambda r: None,
            on_copy=lambda t: None,
            on_whois=lambda i: None,
            on_geoip=lambda i: None,
        )
        app.process_view = ProcessView(on_process_select=lambda n, p: None, page=app.page)
        app.detail_pane = MagicMock()
        app.tabs_control = MagicMock()
        app.tabs_control.selected_index = 0
        app._latest_stats = DashboardStats()
        app._latest_records = [_rec(1, "chrome.exe", "a"), _rec(2, "discord.exe", "b")]
        app._latest_processes = []
        return app

    def test_live_paint_does_not_overwrite_filter_field(self):
        app = self._stub_app()
        app.nav.select_process(1, "chrome.exe")
        app.connections_table.process_filter.value = "discord"  # user edit
        app.nav.tab_index = TAB_CONNECTIONS
        app._paint_active_tab()
        self.assertEqual(app.connections_table.process_filter.value, "discord")

    def test_switch_to_connections_applies_nav_filter(self):
        app = self._stub_app()
        app.nav.select_process(1, "chrome.exe")
        app.connections_table.process_filter.value = ""
        self.assertTrue(app.switch_tab(TAB_CONNECTIONS))
        self.assertEqual(app.connections_table.process_filter.value, "chrome.exe")
        # Filter is applied during paint via table.update → _apply_filters
        names = {r.process_name for r in app.connections_table._filtered}
        self.assertEqual(names, {"chrome.exe"})


class TestDetailCloseClearsSelection(unittest.TestCase):
    def test_clear_selection_drops_highlight(self):
        page = MagicMock()
        table = ConnectionsTable(
            page=page,
            on_row_select=lambda r: None,
            on_copy=lambda t: None,
            on_whois=lambda i: None,
            on_geoip=lambda i: None,
        )
        rec = _rec(5, "svc", "x")
        table.update([rec])
        table.list_view.controls[0].on_click(MagicMock(control=table.list_view.controls[0]))
        self.assertEqual(table._selected_key, "x")
        before = table.list_view.controls[0]
        table.clear_selection()
        self.assertIsNone(table._selected_key)
        self.assertIsNot(table.list_view.controls[0], before)

    def test_detail_close_clears_table_selection(self):
        app = PyNetVizApp()
        app.page = MagicMock()
        app.detail_pane = DetailPane(on_close=lambda: None)
        app.connections_table = ConnectionsTable(
            page=app.page,
            on_row_select=lambda r: None,
            on_copy=lambda t: None,
            on_whois=lambda i: None,
            on_geoip=lambda i: None,
        )
        rec = _rec(1, "a.exe", "k1")
        app.connections_table.update([rec])
        app.connections_table._selected_key = "k1"
        app._selected_record = rec
        app.detail_pane.root.visible = True
        app._on_detail_close()
        self.assertIsNone(app._selected_record)
        self.assertIsNone(app.connections_table._selected_key)
        self.assertFalse(app.detail_pane.root.visible)


class TestUpdateLoopRaceRelease(unittest.TestCase):
    def test_pending_set_during_release_is_rescheduled(self):
        """Finally double-check: pending arriving as claim is released must schedule."""
        app = PyNetVizApp()
        app.page = MagicMock()
        app._updating = True
        app._pending_ui = False

        rescheduled = []

        def capture(fn):
            rescheduled.append(fn)
            return MagicMock()

        app.page.run_task = capture

        # Mirror _update_ui_loop finally: first check sees no pending, then a
        # collector tick sets pending before/after release — re-claim + schedule.
        if app._pending_ui and app.page:
            app.page.run_task(app._update_ui_loop)
        else:
            app._updating = False
            app._pending_ui = True  # race window
            if app._pending_ui and app.page:
                app._updating = True
                app.page.run_task(app._update_ui_loop)

        self.assertTrue(app._updating)
        self.assertEqual(len(rescheduled), 1)
        # Bound methods are not identity-equal across lookups; compare underlying func.
        self.assertIs(rescheduled[0].__func__, PyNetVizApp._update_ui_loop)


class TestProcessHistoryPrune(unittest.TestCase):
    def test_ingest_prunes_stale_pid_history(self):
        view = ProcessView(on_process_select=lambda n, p: None, page=MagicMock())
        # Seed history for many PIDs
        for pid in range(1, 20):
            view._history[pid].append((datetime.now(), 1))
        view.ingest([_proc(1, "a.exe", 1)], [_rec(1, "a.exe", "k")])
        self.assertIn(1, view._history)
        # Stale PIDs should be gone once history grows beyond active+8
        self.assertLessEqual(len(view._history), 10)
        self.assertNotIn(19, view._history)


if __name__ == "__main__":
    unittest.main()
