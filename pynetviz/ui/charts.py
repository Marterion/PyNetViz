"""Lightweight sparklines for ops-center charts."""

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
    SURFACE_VARIANT,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
)

# Cap sparkline segments — each bar is a Container; 90 was expensive on every paint.
SPARK_MAX_BARS = 36


def _downsample(values: list[float], max_n: int = SPARK_MAX_BARS) -> list[float]:
    if len(values) <= max_n:
        return values
    step = len(values) / max_n
    out: list[float] = []
    i = 0.0
    while len(out) < max_n:
        idx = min(int(i), len(values) - 1)
        out.append(values[idx])
        i += step
    return out


def _sparkline_bars(
    values: list[float],
    color: str,
    max_height: int = 64,
    bar_width: int = 5,
) -> ft.Row:
    if len(values) < 2:
        values = [0.0, 0.0]
    window = _downsample(values[-120:], SPARK_MAX_BARS)
    peak = max(window) or 1.0
    bars = [
        ft.Container(
            width=bar_width,
            height=max(int((v / peak) * max_height), 2),
            bgcolor=color if v > 0 else SURFACE_VARIANT,
            border_radius=2,
            opacity=0.95 if v / peak > 0.12 else 0.4,
        )
        for v in window
    ]
    return ft.Row(
        bars,
        spacing=1,
        alignment=ft.MainAxisAlignment.START,
        vertical_alignment=ft.CrossAxisAlignment.END,
        expand=True,
    )


def _chart_shell(title: str, chart_content: ft.Control, subtitle: str = "") -> ft.Container:
    return ft.Container(
        content=ft.Column(
            [
                ft.Row(
                    [
                        ft.Container(width=3, height=14, bgcolor=ACCENT, border_radius=2),
                        ft.Column(
                            [
                                ft.Text(
                                    title.upper(),
                                    size=11,
                                    weight=ft.FontWeight.W_700,
                                    color=TEXT_PRIMARY,
                                    font_family="Consolas",
                                ),
                                ft.Text(subtitle, size=10, color=TEXT_MUTED)
                                if subtitle
                                else ft.Container(height=0),
                            ],
                            spacing=1,
                            expand=True,
                        ),
                    ],
                    spacing=8,
                ),
                ft.Container(
                    content=chart_content,
                    height=88,
                    bgcolor=SURFACE_ELEVATED,
                    border_radius=8,
                    padding=ft.Padding.symmetric(horizontal=8, vertical=8),
                    border=ft.Border.all(1, BORDER),
                ),
            ],
            spacing=8,
        ),
        bgcolor=SURFACE,
        border=ft.Border.all(1, BORDER),
        border_radius=10,
        padding=12,
        expand=True,
        height=150,
    )


def build_line_chart(
    title: str,
    data_points: Sequence[tuple[datetime, float]],
    color: str = ACCENT,
    y_label: str = "",
) -> ft.Container:
    values = [float(v) for _, v in data_points]
    if values:
        subtitle = y_label or f"now {int(values[-1])}  ·  peak {int(max(values))}"
    else:
        subtitle = "awaiting telemetry…"
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
                    ft.Container(width=10, height=3, bgcolor=ACCENT, border_radius=2),
                    ft.Text("UP", size=9, color=TEXT_SECONDARY, font_family="Consolas"),
                    ft.Container(width=10),
                    ft.Container(width=10, height=3, bgcolor=ACCENT_GREEN, border_radius=2),
                    ft.Text("DOWN", size=9, color=TEXT_SECONDARY, font_family="Consolas"),
                ],
                spacing=6,
            ),
            _sparkline_bars(uploads, ACCENT, max_height=28, bar_width=4),
            _sparkline_bars(downloads, ACCENT_GREEN, max_height=28, bar_width=4),
        ],
        spacing=4,
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
    subtitle = f"peak {int(peak)} · now {int(values[-1])}"
    return ft.Container(
        content=ft.Column(
            [
                ft.Text("ACTIVITY", size=10, color=TEXT_MUTED, font_family="Consolas"),
                ft.Container(
                    content=_sparkline_bars(values, ACCENT, max_height=48, bar_width=4),
                    bgcolor=SURFACE_ELEVATED,
                    border_radius=8,
                    padding=8,
                    border=ft.Border.all(1, BORDER),
                ),
                ft.Text(subtitle, size=10, color=TEXT_MUTED),
            ],
            spacing=6,
        ),
        height=110,
        expand=True,
    )
