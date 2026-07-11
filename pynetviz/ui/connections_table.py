from __future__ import annotations

import ipaddress
import logging
import time
import webbrowser
from typing import Callable, Optional

import flet as ft

from pynetviz.models.connection import ConnectionRecord
from pynetviz.ui.theme import (
    ACCENT,
    BORDER,
    SURFACE,
    SURFACE_ELEVATED,
    SURFACE_HOVER,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    filter_field_style,
)

logger = logging.getLogger(__name__)

COLUMNS = [
    ("pid", "PID", 64),
    ("process_name", "Process", 130),
    ("local_endpoint", "Local", 140),
    ("remote_endpoint", "Remote", 140),
    ("hostname", "Hostname", 150),
    ("protocol", "Proto", 56),
    ("state", "State", 100),
    ("direction", "Dir", 78),
    ("last_seen", "Seen", 72),
    ("bytes_sent", "↑", 64),
    ("bytes_recv", "↓", 64),
]

COLUMN_KEYS = [c[0] for c in COLUMNS]


def _format_bytes(n: int) -> str:
    if n < 1024:
        return str(n)
    if n < 1024 * 1024:
        return f"{n // 1024}K"
    return f"{n // (1024 * 1024)}M"


class ConnectionsTable:
    def __init__(
        self,
        page: ft.Page,
        on_row_select: Callable[[ConnectionRecord], None],
        on_copy: Callable[[str], None],
        on_whois: Callable[[str], None],
        on_geoip: Callable[[str], None],
    ) -> None:
        self.page = page
        self.on_row_select = on_row_select
        self.on_copy = on_copy
        self.on_whois = on_whois
        self.on_geoip = on_geoip

        field_kw = filter_field_style()

        self.search_field = ft.TextField(
            hint_text="Search IP, process, hostname…",
            prefix_icon=ft.Icons.SEARCH,
            expand=True,
            height=42,
            on_change=self._on_filter_change,
            **field_kw,
        )
        self.process_filter = ft.TextField(
            hint_text="Process",
            width=130,
            height=42,
            on_change=self._on_filter_change,
            **field_kw,
        )
        self.state_filter = ft.Dropdown(
            hint_text="State",
            width=130,
            options=[
                ft.DropdownOption(key="", text="All states"),
                ft.DropdownOption(key="ESTABLISHED", text="ESTABLISHED"),
                ft.DropdownOption(key="LISTEN", text="LISTEN"),
                ft.DropdownOption(key="CLOSE_WAIT", text="CLOSE_WAIT"),
                ft.DropdownOption(key="TIME_WAIT", text="TIME_WAIT"),
                ft.DropdownOption(key="SYN_SENT", text="SYN_SENT"),
            ],
            on_select=self._on_filter_change,
            border_color=BORDER,
            focused_border_color=ACCENT,
            bgcolor=SURFACE_ELEVATED,
            color=TEXT_PRIMARY,
            text_size=13,
            border_radius=10,
        )
        self.protocol_filter = ft.Dropdown(
            hint_text="Proto",
            width=100,
            options=[
                ft.DropdownOption(key="", text="All"),
                ft.DropdownOption(key="TCP", text="TCP"),
                ft.DropdownOption(key="UDP", text="UDP"),
            ],
            on_select=self._on_filter_change,
            border_color=BORDER,
            focused_border_color=ACCENT,
            bgcolor=SURFACE_ELEVATED,
            color=TEXT_PRIMARY,
            text_size=13,
            border_radius=10,
        )
        self.port_filter = ft.TextField(
            hint_text="Port",
            width=80,
            height=42,
            on_change=self._on_filter_change,
            **field_kw,
        )
        self.clear_btn = ft.IconButton(
            icon=ft.Icons.FILTER_ALT_OFF_OUTLINED,
            tooltip="Clear filters",
            icon_color=TEXT_SECONDARY,
            on_click=self._clear_filters,
        )

        self._sort_column = "last_seen"
        self._sort_asc = False
        self._records: list[ConnectionRecord] = []
        self._filtered: list[ConnectionRecord] = []
        self._selected_key: Optional[str] = None
        # Structural (keys/state/selection) vs content (bytes/time) signatures
        # so live counter ticks don't rebuild the entire control tree every poll.
        self._struct_sig: str = ""
        self._content_sig: str = ""
        self._last_rows_rebuild: float = 0.0
        self._content_rebuild_min_s: float = 1.0
        self._force_next_rows: bool = True

        self.status_text = ft.Text("0 connections", size=12, color=TEXT_SECONDARY)
        self.list_view = ft.ListView(expand=True, spacing=0, auto_scroll=False)
        self.header_row = self._build_header()

        toolbar = ft.Container(
            content=ft.Row(
                [
                    self.search_field,
                    self.process_filter,
                    self.state_filter,
                    self.protocol_filter,
                    self.port_filter,
                    self.clear_btn,
                ],
                spacing=8,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            bgcolor=SURFACE,
            border=ft.Border.all(1, BORDER),
            border_radius=12,
            padding=10,
        )

        table_shell = ft.Container(
            content=ft.Column(
                [
                    ft.Container(
                        content=self.header_row,
                        bgcolor=SURFACE_ELEVATED,
                        padding=ft.Padding.symmetric(horizontal=8, vertical=8),
                        border=ft.Border.only(bottom=ft.BorderSide(1, BORDER)),
                    ),
                    ft.Container(content=self.list_view, expand=True, padding=ft.Padding.only(top=2)),
                ],
                spacing=0,
                expand=True,
            ),
            expand=True,
            bgcolor=SURFACE,
            border=ft.Border.all(1, BORDER),
            border_radius=12,
            clip_behavior=ft.ClipBehavior.HARD_EDGE,
        )

        self.root = ft.Column(
            [
                toolbar,
                ft.Row(
                    [
                        self.status_text,
                        ft.Container(expand=True),
                        ft.Text(
                            "Click row for details · long-press for actions",
                            size=11,
                            color=TEXT_MUTED,
                        ),
                    ],
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                ),
                table_shell,
            ],
            expand=True,
            spacing=10,
        )

    def _build_header(self) -> ft.Row:
        """Sortable compact header matching monospaced row layout."""
        sort_keys = [
            ("pid", "PID"),
            ("process_name", "Process"),
            ("local_endpoint", "Local"),
            ("remote_endpoint", "Remote"),
            ("hostname", "Host"),
            ("state", "State"),
            ("last_seen", "Seen"),
            ("bytes_sent", "↑"),
            ("bytes_recv", "↓"),
        ]
        chips = []
        for key, label in sort_keys:
            is_active = self._sort_column == key
            arrow = ""
            if is_active:
                arrow = " ↑" if self._sort_asc else " ↓"

            def make_handler(col_key: str):
                def handler(_e):
                    if self._sort_column == col_key:
                        self._sort_asc = not self._sort_asc
                    else:
                        self._sort_column = col_key
                        self._sort_asc = True
                    self._force_next_rows = True
                    self._apply_filters()
                    new_header = self._build_header()
                    self.header_row.controls = new_header.controls
                    if self.page:
                        try:
                            self.page.update()
                        except Exception:
                            pass

                return handler

            chips.append(
                ft.Container(
                    content=ft.Text(
                        f"{label}{arrow}",
                        size=11,
                        weight=ft.FontWeight.W_600,
                        color=ACCENT if is_active else TEXT_MUTED,
                        max_lines=1,
                    ),
                    on_click=make_handler(key),
                    padding=ft.Padding.symmetric(horizontal=8, vertical=2),
                    border_radius=6,
                    bgcolor=f"{ACCENT}18" if is_active else None,
                )
            )
        return ft.Row(chips, spacing=4, wrap=True)

    def _clear_filters(self, _e=None) -> None:
        self.search_field.value = ""
        self.process_filter.value = ""
        self.state_filter.value = None
        self.protocol_filter.value = None
        self.port_filter.value = ""
        self._force_next_rows = True
        self._apply_filters()
        if self.page:
            try:
                self.page.update()
            except Exception:
                pass

    def _on_filter_change(self, e=None) -> None:
        self._force_next_rows = True
        self._apply_filters()
        if self.page:
            try:
                self.page.update()
            except Exception:
                pass

    def _match_ip_range(self, ip: str, query: str) -> bool:
        if not query:
            return True
        try:
            if "/" in query:
                network = ipaddress.ip_network(query, strict=False)
                return ipaddress.ip_address(ip) in network
            return query in ip
        except ValueError:
            return query in ip

    def _apply_filters(self) -> None:
        search = (self.search_field.value or "").lower()
        process_q = (self.process_filter.value or "").lower()
        state_q = (self.state_filter.value or "").upper()
        proto_q = (self.protocol_filter.value or "").upper()
        port_q = (self.port_filter.value or "").strip()

        filtered = []
        for r in self._records:
            if process_q and process_q not in r.process_name.lower():
                continue
            if state_q and r.state.upper() != state_q:
                continue
            if proto_q and r.protocol.upper() != proto_q:
                continue
            if port_q:
                if port_q not in str(r.local_port) and port_q not in str(r.remote_port):
                    continue
            if search:
                haystack = " ".join(
                    [
                        str(r.pid),
                        r.process_name,
                        r.executable_path,
                        r.local_addr,
                        r.remote_addr,
                        r.hostname,
                        r.protocol,
                        r.state,
                        r.direction.value,
                    ]
                ).lower()
                if search not in haystack and not (
                    self._match_ip_range(r.remote_addr, search)
                    or self._match_ip_range(r.local_addr, search)
                ):
                    continue
            filtered.append(r)

        self._filtered = self._sort_records(filtered)
        self._rebuild_rows(force=self._force_next_rows)
        self._force_next_rows = False

    def _sort_records(self, records: list[ConnectionRecord]) -> list[ConnectionRecord]:
        def key_func(r: ConnectionRecord):
            if self._sort_column == "local_endpoint":
                return r.local_endpoint
            if self._sort_column == "remote_endpoint":
                return r.remote_endpoint
            if self._sort_column == "direction":
                return r.direction.value
            if self._sort_column == "last_seen":
                return r.last_seen
            if self._sort_column == "bytes_sent":
                return r.bytes_sent
            if self._sort_column == "bytes_recv":
                return r.bytes_recv
            return getattr(r, self._sort_column, "")

        return sorted(records, key=key_func, reverse=not self._sort_asc)

    def _show_context_menu(self, record: ConnectionRecord) -> None:
        remote = record.remote_addr

        async def copy_ip(_):
            self.on_copy(remote)
            try:
                self.page.pop_dialog()
            except Exception:
                pass

        async def copy_port(_):
            self.on_copy(str(record.remote_port))
            try:
                self.page.pop_dialog()
            except Exception:
                pass

        async def open_browser(_):
            if remote and remote not in ("0.0.0.0", "::", "*"):
                webbrowser.open(f"http://{remote}")
            try:
                self.page.pop_dialog()
            except Exception:
                pass

        async def whois(_):
            self.on_whois(remote)
            try:
                self.page.pop_dialog()
            except Exception:
                pass

        async def geoip(_):
            self.on_geoip(remote)
            try:
                self.page.pop_dialog()
            except Exception:
                pass

        def action_btn(label: str, icon: str, handler) -> ft.Container:
            return ft.Container(
                content=ft.Row(
                    [
                        ft.Icon(icon, size=18, color=ACCENT),
                        ft.Text(label, size=13, color=TEXT_PRIMARY),
                    ],
                    spacing=12,
                ),
                padding=ft.Padding.symmetric(horizontal=12, vertical=10),
                border_radius=8,
                on_click=handler,
            )

        try:
            self.page.show_dialog(
                ft.AlertDialog(
                    title=ft.Text(f"{record.process_name}", weight=ft.FontWeight.W_600),
                    content=ft.Column(
                        [
                            ft.Text(record.remote_endpoint, size=12, color=TEXT_SECONDARY),
                            ft.Container(height=4),
                            action_btn("Copy IP", ft.Icons.CONTENT_COPY, copy_ip),
                            action_btn("Copy Port", ft.Icons.TAG, copy_port),
                            action_btn("Open in Browser", ft.Icons.OPEN_IN_BROWSER, open_browser),
                            action_btn("WHOIS Lookup", ft.Icons.DOMAIN, whois),
                            action_btn("GeoIP Lookup", ft.Icons.PUBLIC, geoip),
                        ],
                        tight=True,
                        spacing=2,
                    ),
                    actions=[
                        ft.TextButton("Close", on_click=lambda _: self.page.pop_dialog()),
                    ],
                    bgcolor=SURFACE,
                )
            )
        except Exception:
            logger.debug("show_dialog failed", exc_info=True)

    def _cell_value(self, record: ConnectionRecord, key: str) -> str:
        if key == "pid":
            return str(record.pid)
        if key == "process_name":
            return record.process_name
        if key == "local_endpoint":
            return record.local_endpoint
        if key == "remote_endpoint":
            return record.remote_endpoint
        if key == "hostname":
            return record.hostname or "—"
        if key == "protocol":
            return record.protocol
        if key == "state":
            return record.state
        if key == "direction":
            return record.direction.value
        if key == "last_seen":
            return record.last_seen.strftime("%H:%M:%S")
        if key == "bytes_sent":
            return _format_bytes(record.bytes_sent)
        if key == "bytes_recv":
            return _format_bytes(record.bytes_recv)
        return ""

    def _on_row_click(self, e: ft.ControlEvent) -> None:
        record = e.control.data
        if not isinstance(record, ConnectionRecord):
            return
        self._selected_key = record.connection_key
        # Rebuild highlight before callback so a single page.update (owned by
        # the app's on_row_select) shows both detail pane and selected row.
        self._rebuild_rows(force=True)
        try:
            self.on_row_select(record)
        except Exception:
            logger.debug("on_row_select failed", exc_info=True)

    def _on_row_long_press(self, e: ft.ControlEvent) -> None:
        record = e.control.data
        if isinstance(record, ConnectionRecord):
            self._show_context_menu(record)

    def _build_row(self, record: ConnectionRecord, index: int) -> ft.Container:
        """Compact row: few controls so tab switches / page.update stay fast."""
        color = record.row_color or TEXT_PRIMARY
        is_selected = record.connection_key == self._selected_key
        bg = SURFACE_HOVER if is_selected else (SURFACE_ELEVATED if index % 2 else None)

        # Single text spans for most columns — far cheaper than 11 nested Containers.
        line = (
            f"{record.pid:<6} {record.process_name[:18]:<18} "
            f"{record.local_endpoint[:18]:<18} {record.remote_endpoint[:18]:<18} "
            f"{(record.hostname or '—')[:16]:<16} {record.protocol:<4} "
            f"{record.state[:12]:<12} {record.direction.value[:8]:<8} "
            f"{record.last_seen.strftime('%H:%M:%S')} "
            f"↑{_format_bytes(record.bytes_sent):>5} ↓{_format_bytes(record.bytes_recv):>5}"
        )

        return ft.Container(
            content=ft.Row(
                [
                    ft.Container(
                        width=3,
                        height=22,
                        bgcolor=color if is_selected else BORDER,
                        border_radius=2,
                    ),
                    ft.Text(
                        line,
                        size=11,
                        color=TEXT_PRIMARY if is_selected else color,
                        font_family="Consolas",
                        max_lines=1,
                        overflow=ft.TextOverflow.ELLIPSIS,
                        expand=True,
                    ),
                ],
                spacing=8,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            bgcolor=bg,
            data=record,
            on_click=self._on_row_click,
            on_long_press=self._on_row_long_press,
            padding=ft.Padding.symmetric(horizontal=8, vertical=6),
            border=ft.Border(bottom=ft.BorderSide(1, BORDER)),
        )

    def _structural_signature(self) -> str:
        """Membership / state / hostname / selection / sort — immediate rebuild."""
        parts = [self._selected_key or "", self._sort_column, str(self._sort_asc)]
        for r in self._filtered[:80]:
            parts.append(f"{r.connection_key}|{r.state}|{r.hostname}")
        return "\n".join(parts)

    def _content_signature(self) -> str:
        """Live fields that change every poll — throttled rebuild only."""
        parts: list[str] = []
        for r in self._filtered[:80]:
            parts.append(
                f"{r.bytes_sent}|{r.bytes_recv}|{r.last_seen.strftime('%H:%M:%S')}"
            )
        return "\n".join(parts)

    def _rebuild_rows(self, force: bool = False) -> None:
        """Mutate list controls only — caller owns page.update().

        Full control rebuild is expensive and steals in-flight row clicks.
        Structural changes (keys, state, hostname, selection, sort) rebuild
        immediately. Byte/timestamp-only churn is throttled.
        """
        # Cap rendered rows — full rebuilds freeze Flet page.update.
        max_rows = 80
        shown = min(len(self._filtered), max_rows)
        total = len(self._records)
        if len(self._filtered) > max_rows:
            self.status_text.value = (
                f"Showing {shown} of {len(self._filtered)} filtered · {total} total"
            )
        else:
            self.status_text.value = f"{len(self._filtered)} shown · {total} total"

        struct = self._structural_signature()
        content = self._content_signature()
        now = time.monotonic()

        if not force and self.list_view.controls:
            if struct == self._struct_sig and content == self._content_sig:
                return
            # Same rows/selection — only live counters changed: throttle.
            if (
                struct == self._struct_sig
                and (now - self._last_rows_rebuild) < self._content_rebuild_min_s
            ):
                return

        self._struct_sig = struct
        self._content_sig = content
        self._last_rows_rebuild = now

        if not self._filtered:
            self.list_view.controls = [
                ft.Container(
                    content=ft.Text(
                        "No connections match your filters",
                        size=12,
                        color=TEXT_SECONDARY,
                    ),
                    padding=24,
                    alignment=ft.Alignment.CENTER,
                )
            ]
        else:
            self.list_view.controls = [
                self._build_row(r, i) for i, r in enumerate(self._filtered[:max_rows])
            ]

    def ingest(self, records: list[ConnectionRecord]) -> None:
        """Store latest records without rebuilding the list (for inactive tab)."""
        self._records = records

    def update(self, records: list[ConnectionRecord]) -> None:
        self._records = records
        # Live polls: rebuild only when signature changes (keeps UI responsive)
        self._force_next_rows = False
        self._apply_filters()

    def set_process_filter(self, process_name: str, apply: bool = True) -> None:
        """Set process filter without forcing UI crash paths."""
        self.process_filter.value = process_name
        if apply:
            self._force_next_rows = True
            self._apply_filters()

    def filter_by_process(self, process_name: str) -> None:
        self.set_process_filter(process_name, apply=True)

    def clear_selection(self) -> None:
        """Clear selected-row highlight without changing filters."""
        if self._selected_key is None:
            return
        self._selected_key = None
        if self.list_view.controls and self._filtered:
            self._rebuild_rows(force=True)
