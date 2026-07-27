"""Security monitors tab — ops-center detector cards."""

from __future__ import annotations

from typing import Optional, Sequence

import flet as ft

from pynetviz.security.engine import MonitorSnapshot
from pynetviz.ui.theme import (
    ACCENT,
    ACCENT_GREEN,
    ACCENT_ORANGE,
    ACCENT_RED,
    BORDER,
    SURFACE,
    SURFACE_ELEVATED,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    badge,
    ops_panel,
    ops_section_header,
    status_dot,
)


_STATUS_COLOR = {
    "ok": ACCENT_GREEN,
    "watch": ACCENT_ORANGE,
    "alert": ACCENT_RED,
    "idle": TEXT_MUTED,
    "error": ACCENT_RED,
}


class SecurityView:
    def __init__(self) -> None:
        self.header_status = ft.Text(
            "SECURITY MONITORS",
            size=12,
            weight=ft.FontWeight.W_700,
            color=TEXT_PRIMARY,
            font_family="Consolas",
        )
        self.summary_line = ft.Text(
            "Initializing detectors…",
            size=11,
            color=TEXT_MUTED,
            expand=True,
        )
        self.grid = ft.Column(spacing=10, scroll=ft.ScrollMode.AUTO, expand=True)
        self._sig: str = ""

        self.root = ft.Container(
            content=ft.Column(
                [
                    ft.Container(
                        content=ft.Row(
                            [
                                status_dot(ACCENT),
                                self.header_status,
                                ft.Container(width=8),
                                self.summary_line,
                            ],
                            spacing=8,
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        ),
                        bgcolor=SURFACE_ELEVATED,
                        border=ft.Border.all(1, BORDER),
                        border_radius=8,
                        padding=ft.Padding.symmetric(horizontal=12, vertical=10),
                    ),
                    self.grid,
                ],
                spacing=12,
                expand=True,
            ),
            expand=True,
            padding=ft.Padding.only(top=2),
        )

    def _card(self, snap: MonitorSnapshot) -> ft.Container:
        color = _STATUS_COLOR.get(snap.status, TEXT_MUTED)
        enabled_badge = badge("ON", color=ACCENT_GREEN) if snap.enabled else badge("OFF", color=TEXT_MUTED)
        status_badge = badge(snap.status.upper(), color=color)

        finding_rows: list[ft.Control] = []
        for f in (snap.findings or [])[:5]:
            if str(f.get("title", "")).startswith("ui_only"):
                continue
            lvl = str(f.get("level", "info"))
            lc = {
                "high": ACCENT_RED,
                "warn": ACCENT_ORANGE,
                "info": ACCENT,
            }.get(lvl, TEXT_SECONDARY)
            finding_rows.append(
                ft.Container(
                    content=ft.Column(
                        [
                            ft.Row(
                                [
                                    badge(lvl.upper(), color=lc, size=9),
                                    ft.Text(
                                        str(f.get("title", "")),
                                        size=11,
                                        weight=ft.FontWeight.W_600,
                                        color=TEXT_PRIMARY,
                                        expand=True,
                                        max_lines=1,
                                        overflow=ft.TextOverflow.ELLIPSIS,
                                    ),
                                ],
                                spacing=6,
                            ),
                            ft.Text(
                                str(f.get("body", "")),
                                size=10,
                                color=TEXT_MUTED,
                                max_lines=2,
                                overflow=ft.TextOverflow.ELLIPSIS,
                            ),
                        ],
                        spacing=2,
                    ),
                    bgcolor=SURFACE_ELEVATED,
                    border_radius=6,
                    padding=8,
                    border=ft.Border.all(1, BORDER),
                )
            )
        if not finding_rows:
            finding_rows = [
                ft.Text("No recent findings", size=11, color=TEXT_MUTED, font_family="Consolas")
            ]

        # Device list: show inventory as compact chips when present
        inventory_chips: list[ft.Control] = []
        for f in snap.findings or []:
            fp = str(f.get("title", ""))
            body = str(f.get("body", ""))
            if snap.id == "device_list" and body.startswith("MAC"):
                inventory_chips.append(
                    ft.Container(
                        content=ft.Text(
                            f"{fp} · {body}",
                            size=10,
                            color=TEXT_SECONDARY,
                            font_family="Consolas",
                            max_lines=1,
                        ),
                        bgcolor=SURFACE_ELEVATED,
                        padding=ft.Padding.symmetric(horizontal=8, vertical=4),
                        border_radius=6,
                        border=ft.Border.all(1, BORDER),
                    )
                )
        if inventory_chips:
            finding_rows = [
                ft.Row(inventory_chips[:12], wrap=True, spacing=6),
            ]

        return ops_panel(
            ft.Column(
                [
                    ft.Row(
                        [
                            ops_section_header(snap.name, snap.description, color),
                            ft.Container(expand=True),
                            enabled_badge,
                            status_badge,
                        ],
                        spacing=8,
                        vertical_alignment=ft.CrossAxisAlignment.START,
                    ),
                    ft.Text(
                        snap.summary,
                        size=12,
                        color=TEXT_SECONDARY,
                        max_lines=2,
                    ),
                    ft.Text(
                        f"Last check {snap.last_check}",
                        size=10,
                        color=TEXT_MUTED,
                        font_family="Consolas",
                    ),
                    ft.Column(finding_rows, spacing=6),
                ],
                spacing=8,
            ),
            expand=False,
            accent=color,
        )

    def update(self, snapshots: Optional[Sequence[MonitorSnapshot]] = None) -> None:
        snaps = list(snapshots or [])
        sig = "|".join(
            f"{s.id}:{s.status}:{s.summary}:{s.last_check}:{len(s.findings)}" for s in snaps
        )
        if sig == self._sig:
            return
        self._sig = sig

        if not snaps:
            self.summary_line.value = "No detectors loaded"
            self.grid.controls = [
                ft.Text("Security engine offline", size=12, color=TEXT_MUTED)
            ]
            return

        alerts = sum(1 for s in snaps if s.status == "alert")
        watches = sum(1 for s in snaps if s.status == "watch")
        on = sum(1 for s in snaps if s.enabled)
        self.summary_line.value = (
            f"{on}/{len(snaps)} armed · {alerts} alert · {watches} watch"
        )

        # Two-column wrap via rows of pairs
        cards = [self._card(s) for s in snaps]
        rows: list[ft.Control] = []
        for i in range(0, len(cards), 2):
            chunk = cards[i : i + 2]
            if len(chunk) == 1:
                rows.append(ft.Row([chunk[0], ft.Container(expand=True)], spacing=10))
            else:
                rows.append(
                    ft.Row(
                        [
                            ft.Container(content=chunk[0], expand=True),
                            ft.Container(content=chunk[1], expand=True),
                        ],
                        spacing=10,
                    )
                )
        self.grid.controls = rows
