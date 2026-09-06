"""History tab: hourly stats + recent connection samples from SQLite store."""

from __future__ import annotations

from typing import Any, Optional, Sequence

import flet as ft

from pynetviz.ui.theme import (
    ACCENT,
    ACCENT_GREEN,
    ACCENT_ORANGE,
    BORDER,
    SURFACE,
    SURFACE_ELEVATED,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    badge,
    section_title,
)
from pynetviz.utils.formatters import format_rate


class HistoryView:
    def __init__(self) -> None:
        self.hourly_list = ft.Column(spacing=6, scroll=ft.ScrollMode.AUTO, expand=True)
        self.samples_list = ft.Column(spacing=6, scroll=ft.ScrollMode.AUTO, expand=True)
        self.summary = ft.Text(
            "Hourly aggregates and sampled high-risk connections from the local store.",
            size=12,
            color=TEXT_SECONDARY,
        )
        self._sig: str = ""

        left = ft.Container(
            content=ft.Column(
                [
                    section_title("Hourly activity"),
                    ft.Text("Rolling window from analysis.db", size=11, color=TEXT_MUTED),
                    self.hourly_list,
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
        right = ft.Container(
            content=ft.Column(
                [
                    section_title("Recent samples"),
                    ft.Text("High-signal connection snapshots", size=11, color=TEXT_MUTED),
                    self.samples_list,
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

        self.root = ft.Column(
            [
                self.summary,
                ft.Row([left, right], expand=True, spacing=12),
            ],
            expand=True,
            spacing=12,
        )

    def _hour_row(self, row: dict[str, Any]) -> ft.Container:
        hour = str(row.get("hour_ts") or row.get("hour") or "—")
        total = int(row.get("total_connections") or 0)
        established = int(row.get("established") or 0)
        remotes = int(row.get("unique_remotes") or 0)
        up = float(row.get("upload_bps") or 0)
        down = float(row.get("download_bps") or 0)
        return ft.Container(
            content=ft.Column(
                [
                    ft.Row(
                        [
                            ft.Text(hour, size=12, weight=ft.FontWeight.W_600, color=TEXT_PRIMARY),
                            ft.Container(expand=True),
                            badge(f"{total} conn", color=ACCENT),
                        ],
                        spacing=8,
                    ),
                    ft.Row(
                        [
                            ft.Text(f"Est {established}", size=11, color=TEXT_MUTED),
                            ft.Text(f"Remotes {remotes}", size=11, color=TEXT_MUTED),
                            ft.Text(f"↑ {format_rate(up)}", size=11, color=ACCENT),
                            ft.Text(f"↓ {format_rate(down)}", size=11, color=ACCENT_GREEN),
                        ],
                        spacing=12,
                        wrap=True,
                    ),
                ],
                spacing=4,
            ),
            bgcolor=SURFACE_ELEVATED,
            border=ft.Border.all(1, BORDER),
            border_radius=10,
            padding=10,
        )

    def _sample_row(self, row: dict[str, Any]) -> ft.Container:
        score = int(row.get("risk_score") or 0)
        color = ACCENT_ORANGE if score >= 55 else TEXT_SECONDARY
        title = f"{row.get('process_name') or '?'} → {row.get('remote_addr') or '?'}:{row.get('remote_port') or 0}"
        return ft.Container(
            content=ft.Column(
                [
                    ft.Row(
                        [
                            badge(str(score), color=color),
                            ft.Text(
                                title,
                                size=12,
                                color=TEXT_PRIMARY,
                                expand=True,
                                max_lines=1,
                                overflow=ft.TextOverflow.ELLIPSIS,
                            ),
                        ],
                        spacing=8,
                    ),
                    ft.Text(
                        f"{row.get('protocol') or '?'} · {row.get('state') or '?'} · {row.get('ts') or ''}",
                        size=11,
                        color=TEXT_MUTED,
                        max_lines=1,
                    ),
                ],
                spacing=3,
            ),
            bgcolor=SURFACE_ELEVATED,
            border=ft.Border.all(1, BORDER),
            border_radius=10,
            padding=10,
        )

    def update(
        self,
        hourly: Optional[Sequence[dict[str, Any]]] = None,
        samples: Optional[Sequence[dict[str, Any]]] = None,
    ) -> None:
        hourly = list(hourly or [])
        samples = list(samples or [])
        sig = f"{len(hourly)}|{len(samples)}|{hourly[0] if hourly else ''}|{samples[0] if samples else ''}"
        if sig == self._sig:
            return
        self._sig = sig

        if not hourly:
            self.hourly_list.controls = [
                ft.Text("No hourly stats yet — keep the app running.", size=12, color=TEXT_MUTED)
            ]
        else:
            self.hourly_list.controls = [self._hour_row(h) for h in hourly[:48]]

        if not samples:
            self.samples_list.controls = [
                ft.Text("No samples stored yet.", size=12, color=TEXT_MUTED)
            ]
        else:
            self.samples_list.controls = [self._sample_row(s) for s in samples[:40]]
