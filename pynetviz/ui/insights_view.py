"""Insights tab: network digest, risk list, first-seen, alerts."""

from __future__ import annotations

from typing import Callable, Optional

import flet as ft

from pynetviz.analysis.alerts import Alert
from pynetviz.analysis.digest import NetworkDigest
from pynetviz.models.connection import ConnectionRecord
from pynetviz.ui.theme import (
    ACCENT,
    ACCENT_GREEN,
    ACCENT_ORANGE,
    ACCENT_RED,
    BORDER,
    SURFACE,
    SURFACE_ELEVATED,
    SURFACE_VARIANT,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    badge,
    risk_color,
    section_title,
)


class InsightsView:
    def __init__(
        self,
        *,
        on_mark_alerts_read: Optional[Callable[[], None]] = None,
    ) -> None:
        self.on_mark_alerts_read = on_mark_alerts_read

        self.headline = ft.Text(
            "Waiting for analysis…",
            size=15,
            weight=ft.FontWeight.W_600,
            color=TEXT_PRIMARY,
        )
        self.bullets = ft.Column(spacing=6)
        self.risk_list = ft.Column(spacing=6)
        self.first_seen_list = ft.Column(spacing=4)
        self.alerts_list = ft.Column(spacing=6, scroll=ft.ScrollMode.AUTO, expand=True)
        self.alert_count_label = ft.Text("", size=12, color=TEXT_SECONDARY)
        self.generated_label = ft.Text("", size=11, color=TEXT_MUTED)

        mark_btn = ft.TextButton(
            content="Mark alerts read",
            on_click=lambda _: self._mark_read(),
            style=ft.ButtonStyle(color=ACCENT),
        )

        left = ft.Container(
            content=ft.Column(
                [
                    section_title("Network snapshot"),
                    self.generated_label,
                    self.headline,
                    self.bullets,
                    ft.Divider(height=1, color=BORDER),
                    section_title("Elevated risk"),
                    self.risk_list,
                    ft.Divider(height=1, color=BORDER),
                    section_title("First seen (session / store)"),
                    self.first_seen_list,
                ],
                spacing=10,
                scroll=ft.ScrollMode.AUTO,
                expand=True,
            ),
            expand=2,
            bgcolor=SURFACE,
            border=ft.Border.all(1, BORDER),
            border_radius=14,
            padding=14,
        )

        right = ft.Container(
            content=ft.Column(
                [
                    ft.Row(
                        [
                            section_title("Alerts"),
                            ft.Container(expand=True),
                            self.alert_count_label,
                            mark_btn,
                        ],
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    ),
                    self.alerts_list,
                ],
                spacing=10,
                expand=True,
            ),
            expand=1,
            bgcolor=SURFACE,
            border=ft.Border.all(1, BORDER),
            border_radius=14,
            padding=14,
        )

        self.root = ft.Row([left, right], expand=True, spacing=12)

    def _mark_read(self) -> None:
        if self.on_mark_alerts_read:
            self.on_mark_alerts_read()

    def _risk_card(self, name: str, score: int, reason: str) -> ft.Container:
        color = risk_color(score)
        return ft.Container(
            content=ft.Row(
                [
                    badge(str(score), color=color),
                    ft.Column(
                        [
                            ft.Text(name, size=12, weight=ft.FontWeight.W_600, color=TEXT_PRIMARY),
                            ft.Text(reason, size=11, color=TEXT_MUTED, max_lines=1),
                        ],
                        spacing=2,
                        expand=True,
                    ),
                ],
                spacing=10,
            ),
            bgcolor=SURFACE_ELEVATED,
            border=ft.Border.all(1, BORDER),
            border_radius=8,
            padding=10,
        )

    def update(
        self,
        digest: Optional[NetworkDigest],
        *,
        high_risk_records: Optional[list[ConnectionRecord]] = None,
        first_seen_rows: Optional[list[dict]] = None,
        alerts: Optional[list[Alert]] = None,
        unread: int = 0,
    ) -> None:
        if digest is not None:
            self.headline.value = digest.headline
            self.generated_label.value = (
                f"Updated {digest.generated_at.strftime('%H:%M:%S')}"
            )
            self.bullets.controls = [
                ft.Text(f"• {b}", size=12, color=TEXT_SECONDARY) for b in digest.bullets
            ]
            if digest.high_risk:
                self.risk_list.controls = [
                    self._risk_card(n, s, r) for n, s, r in digest.high_risk
                ]
            elif high_risk_records:
                self.risk_list.controls = [
                    self._risk_card(
                        r.process_name,
                        r.risk_score,
                        (r.risk_reasons[0] if r.risk_reasons else "elevated"),
                    )
                    for r in high_risk_records[:8]
                ]
            else:
                self.risk_list.controls = [
                    ft.Text("No elevated-risk connections right now.", size=12, color=TEXT_MUTED)
                ]

        if first_seen_rows is not None:
            if not first_seen_rows:
                self.first_seen_list.controls = [
                    ft.Text("No first-seen events yet.", size=12, color=TEXT_MUTED)
                ]
            else:
                chips = []
                for row in first_seen_rows[:12]:
                    kind = row.get("kind", "")
                    key = row.get("key", "")
                    chips.append(
                        ft.Container(
                            content=ft.Text(
                                f"{kind}: {key}",
                                size=11,
                                color=TEXT_SECONDARY,
                                max_lines=1,
                                overflow=ft.TextOverflow.ELLIPSIS,
                            ),
                            bgcolor=SURFACE_VARIANT,
                            border_radius=6,
                            padding=ft.Padding.symmetric(horizontal=8, vertical=4),
                        )
                    )
                self.first_seen_list.controls = [ft.Row(chips, wrap=True, spacing=6)]

        if alerts is not None:
            self.alert_count_label.value = f"{unread} unread" if unread else "all read"
            if not alerts:
                self.alerts_list.controls = [
                    ft.Text("No alerts yet.", size=12, color=TEXT_MUTED)
                ]
            else:
                items = []
                for a in alerts[:30]:
                    level_color = {
                        "high": ACCENT_RED,
                        "warn": ACCENT_ORANGE,
                        "info": ACCENT_GREEN,
                    }.get(a.level, TEXT_SECONDARY)
                    items.append(
                        ft.Container(
                            content=ft.Column(
                                [
                                    ft.Row(
                                        [
                                            badge(a.level.upper(), color=level_color),
                                            ft.Text(
                                                a.title,
                                                size=12,
                                                weight=ft.FontWeight.W_600,
                                                color=TEXT_PRIMARY,
                                                expand=True,
                                                max_lines=1,
                                            ),
                                        ],
                                        spacing=8,
                                    ),
                                    ft.Text(a.body, size=11, color=TEXT_MUTED, max_lines=2),
                                    ft.Text(a.ts, size=10, color=TEXT_MUTED),
                                ],
                                spacing=4,
                            ),
                            bgcolor=SURFACE_ELEVATED if not a.read else SURFACE,
                            border=ft.Border.all(1, BORDER),
                            border_radius=8,
                            padding=10,
                            opacity=1.0 if not a.read else 0.75,
                        )
                    )
                self.alerts_list.controls = items
