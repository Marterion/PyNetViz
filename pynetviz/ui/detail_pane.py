from __future__ import annotations

import flet as ft

from pynetviz.models.connection import ConnectionDirection, ConnectionRecord
from pynetviz.ui.theme import (
    ACCENT,
    ACCENT_RED,
    BORDER,
    STATE_ESTABLISHED,
    STATE_INBOUND,
    STATE_LISTEN,
    SURFACE,
    SURFACE_ELEVATED,
    SURFACE_VARIANT,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    badge,
)


def format_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.2f} MB"


def _state_color(record: ConnectionRecord) -> str:
    if record.is_suspicious or record.is_unknown_process:
        return ACCENT_RED
    state = record.state.upper()
    if state == "LISTEN":
        return STATE_LISTEN
    if record.direction == ConnectionDirection.INBOUND:
        return STATE_INBOUND
    if state in {"ESTABLISHED", "SYN_SENT", "SYN_RECV"}:
        return STATE_ESTABLISHED
    return TEXT_SECONDARY


class DetailPane:
    def __init__(self, on_close) -> None:
        self._on_close = on_close
        self.title = ft.Text(
            "Connection Details",
            size=15,
            weight=ft.FontWeight.W_600,
            color=TEXT_PRIMARY,
            expand=True,
            max_lines=1,
            overflow=ft.TextOverflow.ELLIPSIS,
        )
        self.subtitle = ft.Text("", size=11, color=TEXT_SECONDARY)
        self.state_badge_host = ft.Container()
        self.body = ft.Column(spacing=4, scroll=ft.ScrollMode.AUTO, expand=True)
        self.extra_info = ft.Text("", size=11, color=ACCENT, selectable=True)

        self.root = ft.Container(
            content=ft.Column(
                [
                    ft.Row(
                        [
                            ft.Column(
                                [self.title, self.subtitle],
                                spacing=2,
                                expand=True,
                            ),
                            ft.IconButton(
                                icon=ft.Icons.CLOSE_ROUNDED,
                                icon_size=18,
                                icon_color=TEXT_SECONDARY,
                                tooltip="Close",
                                on_click=lambda _: self._on_close(),
                            ),
                        ],
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        vertical_alignment=ft.CrossAxisAlignment.START,
                    ),
                    self.state_badge_host,
                    ft.Divider(height=1, color=BORDER),
                    self.body,
                    ft.Divider(height=1, color=BORDER),
                    ft.Container(
                        content=self.extra_info,
                        bgcolor=SURFACE_ELEVATED,
                        border_radius=8,
                        padding=10,
                        border=ft.Border.all(1, BORDER),
                        visible=False,
                        key="lookup_box",
                    ),
                ],
                expand=True,
                spacing=10,
            ),
            width=360,
            bgcolor=SURFACE,
            border=ft.Border.only(left=ft.BorderSide(1, BORDER)),
            padding=16,
            visible=False,
        )
        self._lookup_box = self.root.content.controls[-1]

    def _field(self, label: str, value: str) -> ft.Container:
        return ft.Container(
            content=ft.Column(
                [
                    ft.Text(label.upper(), size=10, color=TEXT_MUTED, weight=ft.FontWeight.W_600),
                    ft.Text(
                        value or "—",
                        size=12,
                        color=TEXT_PRIMARY,
                        selectable=True,
                        max_lines=3,
                        overflow=ft.TextOverflow.ELLIPSIS,
                    ),
                ],
                spacing=2,
            ),
            padding=ft.Padding.symmetric(vertical=6),
        )

    def _section(self, title: str, fields: list[ft.Control]) -> ft.Container:
        return ft.Container(
            content=ft.Column(
                [
                    ft.Text(title, size=12, weight=ft.FontWeight.W_600, color=TEXT_SECONDARY),
                    ft.Container(
                        content=ft.Column(fields, spacing=0),
                        bgcolor=SURFACE_ELEVATED,
                        border_radius=10,
                        padding=ft.Padding.symmetric(horizontal=12, vertical=6),
                        border=ft.Border.all(1, BORDER),
                    ),
                ],
                spacing=6,
            ),
        )

    def show_connection(self, record: ConnectionRecord, process_detail: dict) -> None:
        self.root.visible = True
        self.title.value = record.process_name
        self.subtitle.value = f"PID {record.pid} · {record.protocol}"
        color = _state_color(record)
        badges = [
            badge(record.state, color=color),
            badge(record.direction.value, color=TEXT_SECONDARY, bgcolor=SURFACE_VARIANT),
        ]
        if record.is_suspicious:
            badges.append(badge("suspicious", color=ACCENT_RED))
        self.state_badge_host.content = ft.Row(badges, spacing=6, wrap=True)

        conn_fields = [
            self._field("Local", record.local_endpoint),
            self._field("Remote", record.remote_endpoint),
            self._field("Hostname", record.hostname or "—"),
            self._field("Protocol", record.protocol),
            self._field("State", record.state),
            self._field("Direction", record.direction.value),
            self._field("Sent", format_bytes(record.bytes_sent)),
            self._field("Received", format_bytes(record.bytes_recv)),
            self._field("Last Seen", record.last_seen.strftime("%H:%M:%S")),
        ]

        process_fields = [
            self._field("Executable", record.executable_path or "N/A"),
        ]
        if process_detail and "error" not in process_detail:
            process_fields.extend(
                [
                    self._field("CPU", f"{process_detail.get('cpu', 0):.1f}%"),
                    self._field("Memory", f"{process_detail.get('memory_mb', 0):.1f} MB"),
                    self._field("Threads", str(process_detail.get("num_threads", "N/A"))),
                    self._field("User", str(process_detail.get("username", "N/A"))),
                    self._field("Status", str(process_detail.get("status", "N/A"))),
                ]
            )

        self.body.controls = [
            self._section("Endpoint", conn_fields),
            self._section("Process", process_fields),
        ]

        if not self.extra_info.value:
            self._lookup_box.visible = False

    def set_lookup_info(self, text: str) -> None:
        self.extra_info.value = text
        self._lookup_box.visible = bool(text)

    def hide(self) -> None:
        self.root.visible = False
        self.extra_info.value = ""
        self._lookup_box.visible = False
