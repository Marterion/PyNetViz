from __future__ import annotations

import logging
from collections import defaultdict, deque
from datetime import datetime
from typing import Callable, Optional

import flet as ft

from pynetviz.models.connection import ConnectionRecord, ProcessSummary, RowHighlight
from pynetviz.ui.charts import build_process_mini_chart
from pynetviz.ui.theme import (
    ACCENT,
    BORDER,
    SURFACE,
    SURFACE_ELEVATED,
    SURFACE_HOVER,
    SURFACE_VARIANT,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    badge,
    section_title,
)

logger = logging.getLogger(__name__)


def encode_process_ref(pid: int, name: str) -> str:
    """Serialize pid/name for Flet control.data (must be a simple string)."""
    return f"{int(pid)}\t{name}"


def decode_process_ref(data) -> Optional[tuple[int, str]]:
    """Parse control.data back to (pid, name). Returns None if invalid."""
    if data is None:
        return None
    if isinstance(data, dict):
        try:
            return int(data["pid"]), str(data.get("name", ""))
        except (KeyError, TypeError, ValueError):
            return None
    text = str(data)
    if "\t" not in text:
        return None
    pid_s, name = text.split("\t", 1)
    try:
        return int(pid_s), name
    except ValueError:
        return None


class ProcessView:
    """Per-process browser.

    Selection is intentionally multi-path so it works inside Flet TabBarView:
      1. Dropdown at top (always reliable)
      2. ListTile on_click
      3. Explicit \"View\" button on each row
      4. Public select_process / select_by_index for tests & automation
    """

    def __init__(
        self,
        on_process_select: Callable[[str, int], None],
        on_refresh: Optional[Callable[[], None]] = None,
        page: Optional[ft.Page] = None,
    ) -> None:
        self.on_process_select = on_process_select
        self.on_refresh = on_refresh
        self.page = page
        self._history: dict[int, deque[tuple[datetime, int]]] = defaultdict(
            lambda: deque(maxlen=120)
        )
        self._selected_pid: Optional[int] = None
        self._selected_name: Optional[str] = None
        self._latest_processes: list[ProcessSummary] = []
        self._latest_connections: list[ConnectionRecord] = []
        self._by_pid: dict[int, ProcessSummary] = {}
        self._list_identity_cached: str = ""
        self._details_identity_cached: str = ""
        self._dropdown_identity: str = ""

        # Dropdown is the most reliable selector inside TabBarView / scroll views
        self.process_dropdown = ft.Dropdown(
            hint_text="Select a process…",
            options=[],
            on_select=self._on_dropdown_select,
            border_color=BORDER,
            focused_border_color=ACCENT,
            bgcolor=SURFACE_ELEVATED,
            color=TEXT_PRIMARY,
            text_size=13,
            border_radius=10,
            dense=True,
        )

        self.process_list = ft.ListView(
            expand=True,
            spacing=4,
            auto_scroll=False,
            padding=ft.Padding.only(right=4),
        )

        self.mini_chart_host = ft.Container(
            content=ft.Text(
                "Select a process to see activity",
                size=12,
                color=TEXT_SECONDARY,
            ),
            height=120,
        )
        self.connections_for_process = ft.Column(
            spacing=6, scroll=ft.ScrollMode.AUTO, expand=True
        )
        self.selected_label = ft.Text(
            "Select a process",
            size=16,
            weight=ft.FontWeight.W_600,
            color=TEXT_PRIMARY,
        )
        self.selection_hint = ft.Text(
            "Pick a process from the dropdown or click a row on the left.",
            size=12,
            color=TEXT_SECONDARY,
        )
        self.connection_count_label = ft.Text("", size=12, color=TEXT_SECONDARY)
        self.meta_row = ft.Row(spacing=8, wrap=True)

        self.details_panel = ft.Container(
            content=ft.Column(
                [
                    self.selected_label,
                    self.meta_row,
                    self.connection_count_label,
                    self.selection_hint,
                    ft.Divider(height=1, color=BORDER),
                    ft.Text("Activity", size=12, weight=ft.FontWeight.W_600, color=TEXT_SECONDARY),
                    self.mini_chart_host,
                    ft.Divider(height=1, color=BORDER),
                    ft.Text("Connections", size=12, weight=ft.FontWeight.W_600, color=TEXT_SECONDARY),
                    self.connections_for_process,
                ],
                expand=True,
                spacing=10,
            ),
            expand=True,
            bgcolor=SURFACE,
            border_radius=12,
            border=ft.Border.all(1, BORDER),
            padding=16,
        )

        self.root = ft.Row(
            [
                ft.Container(
                    content=ft.Column(
                        [
                            ft.Row(
                                [
                                    section_title("Processes"),
                                    ft.Container(expand=True),
                                    ft.Text("by connections", size=11, color=TEXT_MUTED),
                                ]
                            ),
                            self.process_dropdown,
                            self.process_list,
                        ],
                        expand=True,
                        spacing=10,
                    ),
                    width=380,
                    bgcolor=SURFACE,
                    border_radius=12,
                    border=ft.Border.all(1, BORDER),
                    padding=12,
                ),
                self.details_panel,
            ],
            spacing=12,
            expand=True,
        )

    # ── selection (single entry point) ───────────────────────────────────────

    def _select_process(self, pid: int, name: str) -> None:
        """Core selection path used by every click/dropdown/public API."""
        logger.info("Process selected: %s (PID %s)", name, pid)
        self._selected_pid = int(pid)
        self._selected_name = str(name)

        # Keep dropdown in sync without re-firing on_select storms
        ref = encode_process_ref(self._selected_pid, self._selected_name)
        if self.process_dropdown.value != ref:
            self.process_dropdown.value = ref

        self._rebuild_process_list(force=True)
        self._render_details(force=True)

        try:
            self.on_process_select(self._selected_name, self._selected_pid)
        except Exception:
            logger.exception("on_process_select callback failed")

        self._safe_update()

    def select_process(self, name: str, pid: int) -> None:
        """Public API for tests and automation."""
        self._select_process(pid, name)

    def select_by_index(self, index: int) -> bool:
        """Select the process at list index. Returns False if out of range."""
        if index < 0 or index >= len(self._latest_processes):
            return False
        p = self._latest_processes[index]
        self._select_process(p.pid, p.name)
        return True

    def select_first(self) -> bool:
        return self.select_by_index(0)

    @property
    def has_selection(self) -> bool:
        return self._selected_pid is not None

    @property
    def selection_is_empty_state(self) -> bool:
        """True when the details header still shows the empty prompt."""
        return (self.selected_label.value or "") == "Select a process"

    def _safe_update(self) -> None:
        if not self.page:
            return
        try:
            self.page.update()
        except Exception:
            logger.debug("page.update after process select failed", exc_info=True)

    # ── event handlers ───────────────────────────────────────────────────────

    def _on_dropdown_select(self, e: ft.ControlEvent) -> None:
        ref = decode_process_ref(getattr(e.control, "value", None) or self.process_dropdown.value)
        if ref is None:
            return
        pid, name = ref
        self._select_process(pid, name)

    def _on_tile_click(self, e: ft.ControlEvent) -> None:
        """Works for ListTile / Button — reads string data from the event control."""
        control = getattr(e, "control", None)
        data = getattr(control, "data", None) if control is not None else None
        # Parent walk: Button may nest under ListTile trailing
        if data is None and control is not None:
            parent = getattr(control, "parent", None)
            if parent is not None:
                data = getattr(parent, "data", None)
        ref = decode_process_ref(data)
        if ref is None:
            logger.warning("Process tile click with invalid data: %r", data)
            return
        pid, name = ref
        self._select_process(pid, name)

    # ── data helpers ─────────────────────────────────────────────────────────

    def _connections_for_pid(self, pid: int) -> list[ConnectionRecord]:
        active_keys: set[str] = set()
        conns: list[ConnectionRecord] = []
        for record in self._latest_connections:
            if record.pid != pid:
                continue
            if record.highlight == RowHighlight.CLOSING:
                continue
            if record.connection_key in active_keys:
                continue
            active_keys.add(record.connection_key)
            conns.append(record)
        conns.sort(
            key=lambda r: (
                0 if r.state.upper() == "ESTABLISHED" else 1,
                -r.last_seen.timestamp(),
            )
        )
        return conns

    def _list_identity(self) -> str:
        pids = ",".join(
            str(pid) for pid in sorted(p.pid for p in self._latest_processes[:100])
        )
        return f"{self._selected_pid or ''}|{pids}"

    # ── list UI ──────────────────────────────────────────────────────────────

    def _make_tile(self, proc: ProcessSummary) -> ft.Control:
        is_selected = proc.pid == self._selected_pid
        ref = encode_process_ref(proc.pid, proc.name)

        # Explicit button — most reliable click target inside ListView/TabBarView
        view_btn = ft.TextButton(
            content="View",
            data=ref,
            on_click=self._on_tile_click,
            style=ft.ButtonStyle(color=ACCENT),
        )

        return ft.Container(
            content=ft.ListTile(
                leading=ft.Icon(
                    ft.Icons.MEMORY,
                    size=22,
                    color=ACCENT if is_selected else TEXT_SECONDARY,
                ),
                title=ft.Text(
                    proc.name,
                    size=13,
                    weight=ft.FontWeight.W_600,
                    color=TEXT_PRIMARY,
                    max_lines=1,
                    overflow=ft.TextOverflow.ELLIPSIS,
                ),
                subtitle=ft.Text(
                    f"PID {proc.pid} · {proc.connection_count} conn · "
                    f"{proc.cpu_percent:.0f}% CPU · {proc.memory_mb:.0f} MB",
                    size=11,
                    color=TEXT_MUTED,
                    max_lines=1,
                    overflow=ft.TextOverflow.ELLIPSIS,
                ),
                trailing=view_btn,
                selected=is_selected,
                dense=True,
                data=ref,
                on_click=self._on_tile_click,
            ),
            bgcolor=SURFACE_HOVER if is_selected else SURFACE_ELEVATED,
            border=ft.Border.all(1, ACCENT if is_selected else BORDER),
            border_radius=10,
            data=ref,
        )

    def _rebuild_dropdown(self) -> None:
        pids = ",".join(str(p.pid) for p in self._latest_processes[:100])
        if pids == self._dropdown_identity and self.process_dropdown.options:
            # Still refresh selected value
            if self._selected_pid is not None and self._selected_name is not None:
                self.process_dropdown.value = encode_process_ref(
                    self._selected_pid, self._selected_name
                )
            return
        self._dropdown_identity = pids
        self.process_dropdown.options = [
            ft.DropdownOption(
                key=encode_process_ref(p.pid, p.name),
                text=f"{p.name}  (PID {p.pid}, {p.connection_count} conn)",
            )
            for p in self._latest_processes[:100]
        ]
        if self._selected_pid is not None and self._selected_name is not None:
            self.process_dropdown.value = encode_process_ref(
                self._selected_pid, self._selected_name
            )
        elif not self._latest_processes:
            self.process_dropdown.value = None

    def _rebuild_process_list(self, force: bool = False) -> None:
        identity = self._list_identity()
        if (
            not force
            and self.process_list.controls
            and identity == self._list_identity_cached
        ):
            self._rebuild_dropdown()
            return

        self._list_identity_cached = identity
        self._rebuild_dropdown()

        if not self._latest_processes:
            self.process_list.controls = [
                ft.Text("No processes with network activity", size=12, color=TEXT_SECONDARY),
            ]
            return

        self.process_list.controls = [
            self._make_tile(p) for p in self._latest_processes[:100]
        ]

    # ── details panel ────────────────────────────────────────────────────────

    def _conn_card(self, c: ConnectionRecord) -> ft.Container:
        color = c.row_color or TEXT_SECONDARY
        return ft.Container(
            content=ft.Row(
                [
                    ft.Container(width=3, height=28, bgcolor=color, border_radius=2),
                    ft.Column(
                        [
                            ft.Text(
                                c.remote_endpoint,
                                size=12,
                                color=TEXT_PRIMARY,
                                weight=ft.FontWeight.W_500,
                                max_lines=1,
                                overflow=ft.TextOverflow.ELLIPSIS,
                            ),
                            ft.Text(
                                f"{c.local_endpoint} · {c.protocol} · {c.hostname or '—'}",
                                size=10,
                                color=TEXT_MUTED,
                                max_lines=1,
                                overflow=ft.TextOverflow.ELLIPSIS,
                            ),
                        ],
                        spacing=2,
                        expand=True,
                        tight=True,
                    ),
                    badge(c.state, color=color),
                ],
                spacing=8,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            padding=10,
            border=ft.Border.all(1, BORDER),
            border_radius=8,
            bgcolor=SURFACE_ELEVATED,
        )

    def _conn_cards_identity(self, pid: int, conns: list[ConnectionRecord]) -> str:
        return f"{pid}|" + ",".join(f"{c.connection_key}:{c.state}" for c in conns[:100])

    def _render_details(self, force: bool = False) -> None:
        if self._selected_pid is None:
            if not force and self._details_identity_cached == "none":
                return
            self._details_identity_cached = "none"
            self.selected_label.value = "Select a process"
            self.connection_count_label.value = ""
            self.meta_row.controls = []
            self.selection_hint.visible = True
            self.selection_hint.value = (
                "Pick a process from the dropdown or click a row on the left."
            )
            self.mini_chart_host.content = ft.Text(
                "Select a process to see activity",
                size=12,
                color=TEXT_SECONDARY,
            )
            self.connections_for_process.controls = [
                ft.Text("No process selected", size=12, color=TEXT_SECONDARY),
            ]
            return

        proc = self._by_pid.get(self._selected_pid)
        if proc is None:
            missing_id = f"missing|{self._selected_pid}"
            if not force and self._details_identity_cached == missing_id:
                return
            self._details_identity_cached = missing_id
            self.selected_label.value = (
                f"{self._selected_name or 'Process'} (PID {self._selected_pid})"
            )
            self.connection_count_label.value = ""
            self.meta_row.controls = []
            self.selection_hint.visible = True
            self.selection_hint.value = "Waiting for next data refresh…"
            self.connections_for_process.controls = [
                ft.Text("Loading process data…", size=12, color=TEXT_SECONDARY),
            ]
            return

        self.selection_hint.visible = False
        conns = self._connections_for_pid(proc.pid)
        self.selected_label.value = proc.name
        self.meta_row.controls = [
            badge(f"PID {proc.pid}", color=TEXT_SECONDARY, bgcolor=SURFACE_VARIANT),
            badge(f"{proc.cpu_percent:.0f}% CPU", color=TEXT_SECONDARY, bgcolor=SURFACE_VARIANT),
            badge(f"{proc.memory_mb:.0f} MB", color=TEXT_SECONDARY, bgcolor=SURFACE_VARIANT),
        ]
        self.connection_count_label.value = (
            f"{len(conns)} active connection{'s' if len(conns) != 1 else ''}"
        )
        history = list(self._history.get(proc.pid, []))
        self.mini_chart_host.content = build_process_mini_chart(history)

        cards_id = self._conn_cards_identity(proc.pid, conns)
        if not force and cards_id == self._details_identity_cached:
            return
        self._details_identity_cached = cards_id

        if conns:
            self.connections_for_process.controls = [self._conn_card(c) for c in conns[:100]]
        else:
            self.connections_for_process.controls = [
                ft.Text(
                    "No active connections for this process right now.",
                    size=12,
                    color=TEXT_SECONDARY,
                ),
            ]

    # ── live updates ─────────────────────────────────────────────────────────

    def ingest(
        self,
        processes: list[ProcessSummary],
        all_connections: list[ConnectionRecord],
    ) -> None:
        now = datetime.now()
        self._latest_processes = processes
        self._latest_connections = all_connections
        self._by_pid = {p.pid: p for p in processes}
        active = set(self._by_pid)
        for proc in processes:
            self._history[proc.pid].append((now, proc.connection_count))
        if len(self._history) > len(active) + 8:
            keep = active | ({self._selected_pid} if self._selected_pid is not None else set())
            for pid in list(self._history.keys()):
                if pid not in keep:
                    del self._history[pid]

    def update(
        self,
        processes: list[ProcessSummary],
        all_connections: list[ConnectionRecord],
    ) -> None:
        self.ingest(processes, all_connections)
        self._rebuild_process_list()
        self._render_details()

    def refresh_panel(self) -> None:
        self._rebuild_process_list(force=True)
        self._render_details(force=True)
