"""Live Flet agent: boots the real app, switches to Processes, selects a process.

This is an integration agent (not a pure unit test). It opens a short-lived
desktop window, drives selection through public APIs that mirror UI paths, and
asserts the details pane leaves the empty \"Select a process\" state.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import traceback
import unittest

import flet as ft

from pynetviz.ui.app import PyNetVizApp
from pynetviz.ui.navigation import TAB_PROCESSES
from pynetviz.ui.process_view import decode_process_ref

logger = logging.getLogger(__name__)


class TestLiveProcessSelectionAgent(unittest.TestCase):
    """Runs only when FLET_LIVE=1 or --live is passed (slow / GUI)."""

    @classmethod
    def setUpClass(cls):
        cls.run_live = "--live" in sys.argv or __import__("os").environ.get("FLET_LIVE") == "1"

    def test_live_select_process_via_app(self):
        if not self.run_live:
            self.skipTest("Set FLET_LIVE=1 or pass --live to run GUI agent")

        result: dict = {"ok": False, "error": None, "label": None, "pid": None}

        app = PyNetVizApp()
        # Faster agent loop; still real collector
        app.collector.poll_interval = 0.3

        def main(page: ft.Page):
            try:
                app.main(page)

                async def exercise():
                    try:
                        # Wait for first collector samples
                        for _ in range(30):
                            await asyncio.sleep(0.2)
                            if app._latest_processes:
                                break
                        self.assertTrue(
                            app._latest_processes,
                            "collector produced no processes",
                        )

                        # Switch to Processes tab the same way the UI does
                        app.switch_tab(TAB_PROCESSES)
                        await asyncio.sleep(0.3)

                        # Ensure list/dropdown painted
                        app.process_view.update(
                            app._latest_processes, app._latest_records
                        )
                        page.update()
                        await asyncio.sleep(0.2)

                        # Path A: public select_first (same core as click)
                        ok = app.process_view.select_first()
                        self.assertTrue(ok, "select_first failed")
                        page.update()
                        await asyncio.sleep(0.2)

                        label = app.process_view.selected_label.value
                        result["label"] = label
                        result["pid"] = app.process_view._selected_pid
                        self.assertNotEqual(label, "Select a process")
                        self.assertFalse(app.process_view.selection_is_empty_state)
                        self.assertTrue(app.process_view.has_selection)

                        # Path B: fire ListTile on_click like a real event
                        tiles = app.process_view.process_list.controls
                        self.assertGreaterEqual(len(tiles), 1)
                        if len(tiles) >= 2:
                            tile = tiles[1]
                            list_tile = tile.content
                            class E:
                                control = list_tile
                            list_tile.on_click(E())
                            page.update()
                            await asyncio.sleep(0.2)
                            self.assertNotEqual(
                                app.process_view.selected_label.value,
                                "Select a process",
                            )
                            # data must decode
                            ref = decode_process_ref(list_tile.data)
                            self.assertIsNotNone(ref)

                        # Path C: dropdown select second option if present
                        opts = app.process_view.process_dropdown.options
                        if len(opts) >= 1:
                            app.process_view.process_dropdown.value = opts[0].key
                            class DE:
                                control = app.process_view.process_dropdown
                            app.process_view._on_dropdown_select(DE())
                            page.update()
                            await asyncio.sleep(0.15)
                            self.assertFalse(app.process_view.selection_is_empty_state)

                        result["ok"] = True
                        result["label"] = app.process_view.selected_label.value
                        result["pid"] = app.process_view._selected_pid
                        logger.info(
                            "LIVE AGENT OK label=%s pid=%s",
                            result["label"],
                            result["pid"],
                        )
                    except Exception as ex:
                        result["error"] = f"{ex}\n{traceback.format_exc()}"
                        logger.exception("live agent failed")
                    finally:
                        try:
                            app.collector.stop()
                            app.tray.stop()
                        except Exception:
                            pass
                        # App sets prevent_close=True so window.close() only
                        # hides to tray — ft.run never exits. Force destroy.
                        try:
                            page.window.prevent_close = False
                            page.window.on_event = None
                        except Exception:
                            pass
                        try:
                            await page.window.destroy()
                        except Exception:
                            try:
                                await page.window.close()
                            except Exception:
                                pass

                page.run_task(exercise)
            except Exception as ex:
                result["error"] = f"{ex}\n{traceback.format_exc()}"
                raise

        ft.run(main)

        if result["error"]:
            self.fail(result["error"])
        self.assertTrue(result["ok"], result)
        self.assertNotEqual(result["label"], "Select a process")
        self.assertIsNotNone(result["pid"])


if __name__ == "__main__":
    # Allow: python tests/test_process_live_agent.py --live
    unittest.main(argv=[a for a in sys.argv if a != "--live"])
