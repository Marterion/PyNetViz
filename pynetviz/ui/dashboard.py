from __future__ import annotations

import flet as ft

from pynetviz.models.connection import DashboardStats
from pynetviz.ui.charts import build_dual_bandwidth_chart, build_line_chart
from pynetviz.ui.theme import (
    ACCENT,
    ACCENT_GREEN,
    ACCENT_ORANGE,
    ACCENT_RED,
    BORDER,
    SURFACE,
    SURFACE_VARIANT,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    badge,
    section_title,
    stat_card,
)


def format_bytes_rate(bps: float) -> str:
    if bps < 1024:
        return f"{bps:.0f} B/s"
    if bps < 1024 * 1024:
        return f"{bps / 1024:.1f} KB/s"
    return f"{bps / (1024 * 1024):.2f} MB/s"


class DashboardView:
    def __init__(self) -> None:
        self.total_card = stat_card("Active Connections", "0", ft.Icons.HUB_OUTLINED, ACCENT)
        self.listening_card = stat_card("Listening Ports", "0", ft.Icons.SETTINGS_ETHERNET, ACCENT_ORANGE)
        self.established_card = stat_card("Established", "0", ft.Icons.LINK, ACCENT_GREEN)
        self.upload_card = stat_card("Upload", "0 B/s", ft.Icons.ARROW_UPWARD, ACCENT)
        self.download_card = stat_card("Download", "0 B/s", ft.Icons.ARROW_DOWNWARD, ACCENT_GREEN)

        self.top_processes_list = ft.Column(spacing=6)
        self.warning_banner = ft.Container(visible=False)
        self.connections_chart_host = ft.Container(expand=True)
        self.bandwidth_chart_host = ft.Container(expand=True)
        # Skip chart rebuilds when samples have not changed (page.update cost).
        self._charts_sig: str = ""
        self._top_sig: str = ""

        legend = ft.Row(
            [
                badge("Established", color=ACCENT_GREEN),
                badge("Listening", color="#60A5FA"),
                badge("Inbound", color=ACCENT_ORANGE),
                badge("Suspicious", color=ACCENT_RED),
            ],
            spacing=8,
            wrap=True,
        )

        self.root = ft.Container(
            content=ft.Column(
                [
                    self.warning_banner,
                    ft.Row(
                        [
                            self.total_card,
                            self.listening_card,
                            self.established_card,
                            self.upload_card,
                            self.download_card,
                        ],
                        spacing=12,
                    ),
                    ft.Row(
                        [
                            ft.Container(
                                content=ft.Column(
                                    [
                                        ft.Row(
                                            [
                                                section_title("Top Processes"),
                                                ft.Container(expand=True),
                                                ft.Text("by connection count", size=11, color=TEXT_MUTED),
                                            ],
                                        ),
                                        self.top_processes_list,
                                    ],
                                    spacing=12,
                                ),
                                bgcolor=SURFACE,
                                border=ft.Border.all(1, BORDER),
                                border_radius=12,
                                padding=14,
                                expand=2,
                            ),
                            ft.Container(
                                content=ft.Column(
                                    [
                                        section_title("Legend"),
                                        ft.Text(
                                            "Row colors in the Connections tab",
                                            size=11,
                                            color=TEXT_MUTED,
                                        ),
                                        legend,
                                        ft.Container(height=8),
                                        ft.Text(
                                            "Poll interval ~0.4s · DNS + GeoIP on demand",
                                            size=11,
                                            color=TEXT_MUTED,
                                        ),
                                    ],
                                    spacing=10,
                                ),
                                bgcolor=SURFACE,
                                border=ft.Border.all(1, BORDER),
                                border_radius=12,
                                padding=14,
                                expand=1,
                            ),
                        ],
                        spacing=12,
                    ),
                    ft.Row(
                        [self.connections_chart_host, self.bandwidth_chart_host],
                        spacing=12,
                        expand=True,
                    ),
                ],
                spacing=14,
                expand=True,
                scroll=ft.ScrollMode.AUTO,
            ),
            expand=True,
            padding=ft.Padding.only(top=4),
        )

    def _update_stat_card(self, card: ft.Container, value: str) -> None:
        # Column → [Row(icon, title), Text(value)]
        card.content.controls[1].value = value

    def _build_process_bars(self, top: list[tuple[str, int]]) -> list[ft.Control]:
        if not top:
            return [
                ft.Text("No active processes with network activity", size=12, color=TEXT_SECONDARY),
            ]
        peak = max(count for _, count in top) or 1
        rows: list[ft.Control] = []
        for name, count in top:
            ratio = count / peak
            rows.append(
                ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Text(
                                    name,
                                    size=12,
                                    color=TEXT_PRIMARY,
                                    weight=ft.FontWeight.W_500,
                                    expand=True,
                                    max_lines=1,
                                    overflow=ft.TextOverflow.ELLIPSIS,
                                ),
                                badge(str(count), color=ACCENT),
                            ],
                            spacing=8,
                        ),
                        ft.Container(
                            content=ft.Container(
                                bgcolor=ACCENT,
                                border_radius=4,
                                width=max(int(ratio * 280), 6),
                                height=6,
                            ),
                            bgcolor=SURFACE_VARIANT,
                            border_radius=4,
                            height=6,
                            expand=True,
                        ),
                    ],
                    spacing=4,
                )
            )
        return rows

    def update(self, stats: DashboardStats) -> None:
        self._update_stat_card(self.total_card, str(stats.total_connections))
        self._update_stat_card(self.listening_card, str(stats.listening_ports))
        self._update_stat_card(self.established_card, str(stats.established_connections))
        self._update_stat_card(self.upload_card, format_bytes_rate(stats.upload_bps))
        self._update_stat_card(self.download_card, format_bytes_rate(stats.download_bps))

        top_sig = "|".join(f"{n}:{c}" for n, c in (stats.top_processes or [])[:12])
        if top_sig != self._top_sig:
            self._top_sig = top_sig
            self.top_processes_list.controls = self._build_process_bars(stats.top_processes)

        if stats.permission_warning:
            self.warning_banner.content = ft.Container(
                content=ft.Row(
                    [
                        ft.Icon(ft.Icons.WARNING_AMBER_ROUNDED, color=ACCENT_ORANGE, size=20),
                        ft.Text(stats.permission_warning, color=TEXT_SECONDARY, expand=True, size=12),
                    ],
                    spacing=10,
                ),
                bgcolor="#2A2218",
                border=ft.Border.all(1, ACCENT_ORANGE),
                border_radius=10,
                padding=12,
            )
            self.warning_banner.visible = True
        else:
            self.warning_banner.visible = False

        # Rebuild sparkline trees only when sample count / endpoints move.
        hist = stats.connection_history or []
        bw = stats.bandwidth_history or []
        charts_sig = (
            f"{len(hist)}|{hist[-1][1] if hist else 0}|"
            f"{len(bw)}|{bw[-1][1] if bw else 0}|{bw[-1][2] if bw else 0}"
        )
        if charts_sig == self._charts_sig and self.connections_chart_host.content is not None:
            return
        self._charts_sig = charts_sig

        conn_points = [(ts, float(count)) for ts, count in hist]
        self.connections_chart_host.content = build_line_chart(
            "Connections · last 5 min", conn_points, color=ACCENT
        )

        self.bandwidth_chart_host.content = build_dual_bandwidth_chart(
            "Bandwidth · last 5 min", bw
        )
