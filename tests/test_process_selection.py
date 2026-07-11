"""Focused tests: Processes tab selection must leave empty state.

These tests intentionally exercise every selection path (dropdown, ListTile,
View button, public API) so \"Select a process\" cannot stick after a click.
"""

from __future__ import annotations

import unittest
from datetime import datetime
from unittest.mock import MagicMock

import flet as ft

from pynetviz.models.connection import (
    ConnectionDirection,
    ConnectionRecord,
    ProcessSummary,
)
from pynetviz.ui.process_view import (
    ProcessView,
    decode_process_ref,
    encode_process_ref,
)


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
        direction=ConnectionDirection.OUTBOUND,
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
        cpu_percent=2.5,
        memory_mb=80.0,
    )


class TestEncodeDecode(unittest.TestCase):
    def test_roundtrip(self):
        ref = encode_process_ref(42, "chrome.exe")
        self.assertEqual(decode_process_ref(ref), (42, "chrome.exe"))

    def test_name_with_spaces(self):
        ref = encode_process_ref(1, "My App.exe")
        self.assertEqual(decode_process_ref(ref), (1, "My App.exe"))

    def test_invalid(self):
        self.assertIsNone(decode_process_ref(None))
        self.assertIsNone(decode_process_ref(""))
        self.assertIsNone(decode_process_ref("nontab"))
        self.assertIsNone(decode_process_ref("x\tname"))


class TestProcessSelectionPaths(unittest.TestCase):
    def setUp(self):
        self.selected = []
        self.page = MagicMock()
        self.view = ProcessView(
            on_process_select=lambda n, p: self.selected.append((n, p)),
            page=self.page,
        )
        self.procs = [
            _proc(10, "chrome.exe", 5),
            _proc(20, "discord.exe", 2),
            _proc(30, "python.exe", 1),
        ]
        self.recs = [
            _rec(10, "chrome.exe", "c1"),
            _rec(10, "chrome.exe", "c2"),
            _rec(20, "discord.exe", "d1"),
            _rec(30, "python.exe", "p1", state="LISTEN"),
        ]
        self.view.update(self.procs, self.recs)

    def _assert_selected(self, pid: int, name: str, conn_count: int) -> None:
        self.assertFalse(
            self.view.selection_is_empty_state,
            f"still empty state, label={self.view.selected_label.value!r}",
        )
        self.assertEqual(self.view.selected_label.value, name)
        self.assertEqual(self.view._selected_pid, pid)
        self.assertTrue(self.view.has_selection)
        self.assertFalse(self.view.selection_hint.visible)
        self.assertIn(str(conn_count), self.view.connection_count_label.value)
        self.assertEqual(self.selected[-1], (name, pid))
        # page.update must be attempted so Flet repaints details
        self.page.update.assert_called()

    def test_starts_empty(self):
        fresh = ProcessView(on_process_select=lambda n, p: None)
        self.assertTrue(fresh.selection_is_empty_state)
        self.assertFalse(fresh.has_selection)

    def test_select_process_api_clears_empty_state(self):
        self.view.select_process("discord.exe", 20)
        self._assert_selected(20, "discord.exe", 1)
        self.assertEqual(len(self.view.connections_for_process.controls), 1)

    def test_select_by_index(self):
        self.assertTrue(self.view.select_by_index(0))
        self._assert_selected(10, "chrome.exe", 2)
        self.assertEqual(len(self.view.connections_for_process.controls), 2)

    def test_select_by_index_oob(self):
        self.assertFalse(self.view.select_by_index(99))
        self.assertTrue(self.view.selection_is_empty_state)

    def test_select_first(self):
        self.assertTrue(self.view.select_first())
        self._assert_selected(10, "chrome.exe", 2)

    def test_dropdown_options_populated(self):
        self.assertEqual(len(self.view.process_dropdown.options), 3)
        keys = [o.key for o in self.view.process_dropdown.options]
        self.assertIn(encode_process_ref(10, "chrome.exe"), keys)

    def test_dropdown_select_path(self):
        ref = encode_process_ref(30, "python.exe")
        self.view.process_dropdown.value = ref
        e = MagicMock()
        e.control = self.view.process_dropdown
        self.view._on_dropdown_select(e)
        self._assert_selected(30, "python.exe", 1)

    def test_list_tiles_are_clickable(self):
        self.assertEqual(len(self.view.process_list.controls), 3)
        for tile_wrap in self.view.process_list.controls:
            # Container wrapping ListTile
            self.assertIsInstance(tile_wrap, ft.Container)
            self.assertIsNotNone(tile_wrap.data)
            list_tile = tile_wrap.content
            self.assertIsInstance(list_tile, ft.ListTile)
            self.assertTrue(callable(list_tile.on_click))
            self.assertIsNotNone(list_tile.data)
            # trailing View button
            btn = list_tile.trailing
            self.assertIsInstance(btn, ft.TextButton)
            self.assertTrue(callable(btn.on_click))
            self.assertEqual(btn.data, list_tile.data)

    def test_listtile_on_click_selects(self):
        wrap = self.view.process_list.controls[1]
        list_tile = wrap.content
        e = MagicMock()
        e.control = list_tile
        list_tile.on_click(e)
        self._assert_selected(20, "discord.exe", 1)

    def test_view_button_on_click_selects(self):
        wrap = self.view.process_list.controls[2]
        btn = wrap.content.trailing
        e = MagicMock()
        e.control = btn
        btn.on_click(e)
        self._assert_selected(30, "python.exe", 1)

    def test_container_data_click_path(self):
        """If event delivers outer Container, data still decodes."""
        wrap = self.view.process_list.controls[0]
        e = MagicMock()
        e.control = wrap
        self.view._on_tile_click(e)
        self._assert_selected(10, "chrome.exe", 2)

    def test_selection_survives_live_update(self):
        self.view.select_process("chrome.exe", 10)
        for i in range(8):
            procs = [
                _proc(10, "chrome.exe", 5 + i),
                _proc(20, "discord.exe", 2),
                _proc(30, "python.exe", 1),
            ]
            self.view.update(procs, self.recs)
        self.assertEqual(self.view._selected_pid, 10)
        self.assertEqual(self.view.selected_label.value, "chrome.exe")
        self.assertFalse(self.view.selection_is_empty_state)

    def test_switching_selection_updates_details(self):
        self.view.select_by_index(0)
        self.assertEqual(self.view.selected_label.value, "chrome.exe")
        self.view.select_by_index(1)
        self.assertEqual(self.view.selected_label.value, "discord.exe")
        self.assertNotEqual(self.view.selected_label.value, "Select a process")


class TestProcessSelectionWithAppNav(unittest.TestCase):
    def test_callback_updates_nav(self):
        from pynetviz.ui.app import PyNetVizApp
        from pynetviz.ui.navigation import TAB_PROCESSES

        app = PyNetVizApp()
        app.page = MagicMock()
        app.process_view = ProcessView(
            on_process_select=app._on_process_select,
            page=app.page,
        )
        app.connections_table = MagicMock()
        app.nav.switch_tab(TAB_PROCESSES)

        app.process_view.update(
            [_proc(7, "svchost.exe", 3)],
            [_rec(7, "svchost.exe", "s1"), _rec(7, "svchost.exe", "s2")],
        )
        self.assertTrue(app.process_view.select_first())
        self.assertEqual(app.nav.process.pid, 7)
        self.assertEqual(app.nav.process.name, "svchost.exe")
        self.assertFalse(app.process_view.selection_is_empty_state)
        self.assertEqual(app.process_view.selected_label.value, "svchost.exe")


if __name__ == "__main__":
    unittest.main()
