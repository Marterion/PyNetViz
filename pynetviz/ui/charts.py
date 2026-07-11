from __future__ import annotations

from datetime import datetime
from typing import Sequence

import flet as ft

from pynetviz.ui.theme import (
    ACCENT,
    ACCENT_GREEN,
    BORDER,
    SURFACE,
    SURFACE_ELEVATED,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
)


def _sparkline_bars(
    values: list[float],
    color: str,
    max_height: int = 72,
    bar_width: int = 4,
) -> ft.Row:
    if len(values) < 2:
        values = [0.0, 0.0]
    window = values[-90:]
    peak = max(window) or 1.0
    bars = [
        ft.Container(
            width=bar_width,
            height=max(int((v / peak) * max_height), 2),
            bgcolor=color if v > 0 else TEXT_MUTED,
            border_radius=2,
            opacity=0.95 if v / peak > 0.15 else 0.55,
        )
        for v in window
    ]
    return ft.Row(
        bars,
        spacing=1,
        alignment=ft.MainAxisAlignment.START,
        vertical_alignment=ft.CrossAxisAlignment.END,
        scroll=ft.ScrollMode.AUTO,
        expand=True,
    )


def _chart_shell(title: str, chart_content: ft.Control, subtitle: str = "") -> ft.Container:
    header_row = ft.Row(
        [
            ft.Column(
                [
                    ft.Text(title, size=13, weight=ft.FontWeight.W_600, color=TEXT_PRIMARY),
                    ft.Text(subtitle, size=11, color=TEXT_SECONDARY) if subtitle else ft.Container(height=0),
                ],
                spacing=2,
                expand=True,
            ),
        ],
        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
    )
    return ft.Container(
        content=ft.Column(
            [
                header_row,
                ft.Container(
                    content=chart_content,
                    height=96,
                    bgcolor=SURFACE_ELEVATED,
                    border_radius=8,
                    padding=ft.Padding.symmetric(horizontal=8, vertical=8),
                    border=ft.Border.all(1, BORDER),
                ),
            ],
            spacing=10,
        ),
        bgcolor=SURFACE,
        border=ft.Border.all(1, BORDER),
        border_radius=12,
        padding=14,
        expand=True,
        height=170,
    )


def build_line_chart(
    title: str,
    data_points: Sequence[tuple[datetime, float]],
    color: str = ACCENT,
    y_label: str = "",
) -> ft.Container:
    values = [float(v) for _, v in data_points]
    if values:
        subtitle = y_label or f"latest {int(values[-1])} · peak {int(max(values))}"
    else:
        subtitle = "waiting for samples…"
    return _chart_shell(title, _sparkline_bars(values, color), subtitle)


def build_dual_bandwidth_chart(
    title: str,
    data_points: Sequence[tuple[datetime, float, float]],
) -> ft.Container:
    uploads = [float(p[1]) for p in data_points]
    downloads = [float(p[2]) for p in data_points]
    content = ft.Column(
        [
            ft.Row(
                [
                    ft.Container(width=12, height=3, bgcolor=ACCENT, border_radius=2),
                    ft.Text("Upload", size=10, color=TEXT_SECONDARY),
                    ft.Container(width=8),
                    ft.Container(width=12, height=3, bgcolor=ACCENT_GREEN, border_radius=2),
                    ft.Text("Download", size=10, color=TEXT_SECONDARY),
                ],
                spacing=6,
            ),
            _sparkline_bars(uploads, ACCENT, max_height=32, bar_width=3),
            _sparkline_bars(downloads, ACCENT_GREEN, max_height=32, bar_width=3),
        ],
        spacing=6,
        expand=True,
    )
    latest_up = uploads[-1] if uploads else 0
    latest_down = downloads[-1] if downloads else 0
    subtitle = f"↑ {latest_up / 1024:.1f} KB/s   ↓ {latest_down / 1024:.1f} KB/s"
    return _chart_shell(title, content, subtitle)


def build_process_mini_chart(history: Sequence[tuple[datetime, int]]) -> ft.Container:
    if len(history) < 2:
        history = [(datetime.now(), 0), (datetime.now(), 0)]
    values = [float(count) for _, count in history]
    peak = max(values) or 1
    subtitle = f"peak {int(peak)} · latest {int(values[-1])} · {len(history)} samples"
    return ft.Container(
        content=ft.Column(
            [
                ft.Text("Connections over time", size=11, color=TEXT_SECONDARY),
                ft.Container(
                    content=_sparkline_bars(values, ACCENT, max_height=56, bar_width=4),
                    bgcolor=SURFACE_ELEVATED,
                    border_radius=8,
                    padding=8,
                    border=ft.Border.all(1, BORDER),
                ),
                ft.Text(subtitle, size=10, color=TEXT_MUTED),
            ],
            spacing=6,
        ),
        height=120,
        expand=True,
    )
