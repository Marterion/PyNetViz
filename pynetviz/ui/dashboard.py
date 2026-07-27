"""Operations-center dashboard — SOC-style KPIs, threat mix, telemetry charts."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

import flet as ft

from pynetviz.analysis.aggregates import NetworkAggregates, build_aggregates
from pynetviz.models.connection import ConnectionRecord, DashboardStats
from pynetviz.ui.charts import build_dual_bandwidth_chart, build_line_chart
from pynetviz.ui.theme import (
    ACCENT,
    ACCENT_BLUE,
    ACCENT_GREEN,
    ACCENT_ORANGE,
    ACCENT_PURPLE,
    ACCENT_RED,
    BORDER,
    OPS_AMBER,
    RISK_ELEVATED,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    SURFACE,
    SURFACE_ELEVATED,
    SURFACE_VARIANT,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    badge,
    build_ratio_bar,
    ops_panel,
    ops_section_header,
    stat_card,
    status_dot,
)
from pynetviz.utils.formatters import format_rate
from pynetviz.utils.port_labels import format_port


class DashboardView:
    def __init__(self) -> None:
        self.total_card = stat_card("LINKS LIVE", "0", ft.Icons.HUB_OUTLINED, ACCENT)
        self.listening_card = stat_card("LISTEN", "0", ft.Icons.SETTINGS_ETHERNET, ACCENT_BLUE)
        self.established_card = stat_card("ESTABLISHED", "0", ft.Icons.LINK, ACCENT_GREEN)
        self.risk_card = stat_card("THREAT SCORE", "0", ft.Icons.SHIELD_OUTLINED, ACCENT_RED)
        self.upload_card = stat_card("UPLINK", "0 B/s", ft.Icons.ARROW_UPWARD, ACCENT)
        self.download_card = stat_card("DOWNLINK", "0 B/s", ft.Icons.ARROW_DOWNWARD, ACCENT_GREEN)

        self.mission_status = ft.Text(
            "NOMINAL",
            size=12,
            weight=ft.FontWeight.W_700,
            color=ACCENT_GREEN,
            font_family="Consolas",
        )
        self.mission_clock = ft.Text(
            "--:--:--",
            size=12,
            color=TEXT_SECONDARY,
            font_family="Consolas",
        )
        self.mission_detail = ft.Text(
            "Awaiting telemetry…",
            size=11,
            color=TEXT_MUTED,
            expand=True,
            max_lines=1,
            overflow=ft.TextOverflow.ELLIPSIS,
        )
        self.top_processes_list = ft.Column(spacing=5)
        self.protocol_list = ft.Column(spacing=5)
        self.direction_list = ft.Column(spacing=5)
        self.risk_list = ft.Column(spacing=5)
        self.top_remotes_list = ft.Column(spacing=3)
        self.top_ports_list = ft.Column(spacing=3)
        self.warning_banner = ft.Container(visible=False)
        self.connections_chart_host = ft.Container(expand=True)
        self.bandwidth_chart_host = ft.Container(expand=True)

        self._charts_sig: str = ""
        self._top_sig: str = ""
        self._agg_sig: str = ""
        self._kpi_sig: str = ""
        self._warn_sig: str = ""

        mission_bar = ft.Container(
            content=ft.Row(
                [
                    status_dot(ACCENT_GREEN),
                    ft.Text(
                        "NETWORK OPS CENTER",
                        size=12,
                        weight=ft.FontWeight.W_700,
                        color=TEXT_PRIMARY,
                        font_family="Consolas",
                    ),
                    ft.Container(
                        width=1,
                        height=16,
                        bgcolor=BORDER,
                        margin=ft.Margin.symmetric(horizontal=6),
                    ),
                    ft.Text("STATUS", size=10, color=TEXT_MUTED, font_family="Consolas"),
                    self.mission_status,
                    ft.Container(expand=True),
                    self.mission_detail,
                    ft.Container(width=8),
                    ft.Text("LOCAL", size=10, color=TEXT_MUTED, font_family="Consolas"),
                    self.mission_clock,
                ],
                spacing=8,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            bgcolor=SURFACE_ELEVATED,
            border=ft.Border.all(1, BORDER),
            border_radius=8,
            padding=ft.Padding.symmetric(horizontal=12, vertical=8),
        )

        kpi_row = ft.Row(
            [
                self.total_card,
                self.listening_card,
                self.established_card,
                self.risk_card,
                self.upload_card,
                self.download_card,
            ],
            spacing=8,
        )

        intel_row = ft.Row(
            [
                self._ops_panel(
                    "PROTOCOL MIX",
                    "transport breakdown",
                    self.protocol_list,
                    accent=ACCENT,
                ),
                self._ops_panel(
                    "TRAFFIC VECTOR",
                    "direction map",
                    self.direction_list,
                    accent=ACCENT_BLUE,
                ),
                self._ops_panel(
                    "THREAT LEVELS",
                    "risk distribution",
                    self.risk_list,
                    accent=ACCENT_RED,
                ),
            ],
            spacing=10,
        )

        roster_row = ft.Row(
            [
                ops_panel(
                    ft.Column(
                        [
                            ops_section_header("TOP PROCESSES", "by active links", ACCENT),
                            self.top_processes_list,
                        ],
                        spacing=10,
                    ),
                    expand=2,
                    accent=ACCENT,
                ),
                ops_panel(
                    ft.Column(
                        [
                            ops_section_header("TOP REMOTES", "endpoint pressure", OPS_AMBER),
                            self.top_remotes_list,
                            ft.Container(height=6),
                            ops_section_header("HOT PORTS", "service pressure", ACCENT_PURPLE),
                            self.top_ports_list,
                        ],
                        spacing=8,
                    ),
                    expand=1,
                    accent=OPS_AMBER,
                ),
            ],
            spacing=10,
        )

        charts_row = ft.Row(
            [self.connections_chart_host, self.bandwidth_chart_host],
            spacing=10,
        )

        self.root = ft.Container(
            content=ft.Column(
                [
                    self.warning_banner,
                    mission_bar,
                    kpi_row,
                    intel_row,
                    roster_row,
                    charts_row,
                ],
                spacing=10,
                expand=True,
                scroll=ft.ScrollMode.AUTO,
            ),
            expand=True,
            padding=ft.Padding.only(left=4, right=4, top=2, bottom=8),
        )

    def _ops_panel(
        self,
        title: str,
        subtitle: str,
        body: ft.Control,
        *,
        accent: str,
    ) -> ft.Container:
        return ops_panel(
            ft.Column(
                [ops_section_header(title, subtitle, accent), body],
                spacing=10,
            ),
            expand=True,
            accent=accent,
        )

    def _update_stat_card(self, card: ft.Container, value: str, subtitle: str = "") -> None:
        col = card.content
        if col.controls[1].value != value:
            col.controls[1].value = value
        if len(col.controls) > 2 and subtitle and col.controls[2].value != subtitle:
            col.controls[2].value = subtitle

    def _build_process_bars(self, top: list[tuple[str, int]]) -> list[ft.Control]:
        if not top:
            return [
                ft.Text("No network processes in scope", size=12, color=TEXT_SECONDARY),
            ]
        peak = max(count for _, count in top) or 1
        rows: list[ft.Control] = []
        for i, (name, count) in enumerate(top[:10]):
            ratio = count / peak
            rows.append(
                ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Text(
                                    f"{i + 1:02d}",
                                    size=10,
                                    color=TEXT_MUTED,
                                    font_family="Consolas",
                                    width=22,
                                ),
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
                            spacing=6,
                        ),
                        build_ratio_bar(ratio, color=ACCENT, height=5),
                    ],
                    spacing=3,
                )
            )
        return rows

    def _mix_rows(
        self,
        pairs: list[tuple[str, int]],
        colors: dict[str, str],
    ) -> list[ft.Control]:
        if not pairs:
            return [ft.Text("— no samples —", size=11, color=TEXT_MUTED, font_family="Consolas")]
        total = sum(c for _, c in pairs) or 1
        rows: list[ft.Control] = []
        for name, count in pairs:
            color = colors.get(name, ACCENT)
            pct = int(round(100 * count / total))
            rows.append(
                ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Text(name, size=11, color=TEXT_PRIMARY, expand=True),
                                ft.Text(
                                    f"{pct}%",
                                    size=10,
                                    color=TEXT_MUTED,
                                    font_family="Consolas",
                                ),
                                badge(str(count), color=color),
                            ],
                            spacing=6,
                        ),
                        build_ratio_bar(count / total, color=color, height=5),
                    ],
                    spacing=2,
                )
            )
        return rows

    def _set_mission(self, stats: DashboardStats, agg: NetworkAggregates) -> None:
        elevated = agg.risk.elevated + agg.risk.high
        if stats.permission_warning:
            self.mission_status.value = "DEGRADED"
            self.mission_status.color = OPS_AMBER
        elif elevated >= 5 or agg.risk.high >= 2:
            self.mission_status.value = "ELEVATED"
            self.mission_status.color = ACCENT_RED
        elif elevated > 0:
            self.mission_status.value = "WATCH"
            self.mission_status.color = OPS_AMBER
        else:
            self.mission_status.value = "NOMINAL"
            self.mission_status.color = ACCENT_GREEN

        self.mission_clock.value = datetime.now().strftime("%H:%M:%S")
        self.mission_detail.value = (
            f"{stats.total_connections} links · {agg.unique_remotes} remotes · "
            f"{agg.unique_processes} procs · {elevated} elevated"
        )

    def update(
        self,
        stats: DashboardStats,
        records: Optional[list[ConnectionRecord]] = None,
        aggregates: Optional[NetworkAggregates] = None,
    ) -> None:
        agg = aggregates
        if agg is None and records is not None:
            agg = build_aggregates(records)
        if agg is None:
            agg = NetworkAggregates()

        elevated = agg.risk.elevated + agg.risk.high
        kpi_sig = (
            f"{stats.total_connections}|{stats.listening_ports}|"
            f"{stats.established_connections}|{elevated}|"
            f"{int(stats.upload_bps)}|{int(stats.download_bps)}"
        )
        if kpi_sig != self._kpi_sig:
            self._kpi_sig = kpi_sig
            self._update_stat_card(self.total_card, str(stats.total_connections))
            self._update_stat_card(self.listening_card, str(stats.listening_ports))
            self._update_stat_card(self.established_card, str(stats.established_connections))
            self._update_stat_card(self.upload_card, format_rate(stats.upload_bps))
            self._update_stat_card(self.download_card, format_rate(stats.download_bps))
            self._update_stat_card(
                self.risk_card,
                str(elevated),
                subtitle=f"{agg.unique_remotes} remotes · {agg.unique_processes} procs",
            )

        self._set_mission(stats, agg)

        top_sig = "|".join(f"{n}:{c}" for n, c in (stats.top_processes or [])[:10])
        if top_sig != self._top_sig:
            self._top_sig = top_sig
            self.top_processes_list.controls = self._build_process_bars(
                list(stats.top_processes or [])[:10]
            )

        agg_sig = (
            f"{agg.protocol.tcp}|{agg.protocol.udp}|{agg.protocol.other}|"
            f"{agg.direction.outbound}|{agg.direction.inbound}|"
            f"{agg.direction.listen}|{agg.direction.unknown}|"
            f"{agg.risk.low}|{agg.risk.medium}|{agg.risk.elevated}|{agg.risk.high}|"
            f"{agg.top_remotes[:6]}|{agg.top_ports[:6]}"
        )
        if agg_sig != self._agg_sig:
            self._agg_sig = agg_sig
            self.protocol_list.controls = self._mix_rows(
                agg.protocol.as_pairs(),
                {"TCP": ACCENT, "UDP": ACCENT_PURPLE, "Other": TEXT_SECONDARY},
            )
            self.direction_list.controls = self._mix_rows(
                agg.direction.as_pairs(),
                {
                    "Outbound": ACCENT,
                    "Inbound": ACCENT_ORANGE,
                    "Listen": ACCENT_BLUE,
                    "Unknown": TEXT_MUTED,
                },
            )
            self.risk_list.controls = self._mix_rows(
                agg.risk.as_pairs(),
                {
                    "Low": RISK_LOW,
                    "Medium": RISK_MEDIUM,
                    "Elevated": RISK_ELEVATED,
                    "High": RISK_HIGH,
                },
            )
            if agg.top_remotes:
                self.top_remotes_list.controls = [
                    ft.Row(
                        [
                            ft.Text(
                                endpoint,
                                size=11,
                                color=TEXT_SECONDARY,
                                expand=True,
                                max_lines=1,
                                overflow=ft.TextOverflow.ELLIPSIS,
                                font_family="Consolas",
                            ),
                            badge(str(count), color=OPS_AMBER),
                        ],
                        spacing=6,
                    )
                    for endpoint, count in agg.top_remotes[:8]
                ]
            else:
                self.top_remotes_list.controls = [
                    ft.Text("No remote endpoints", size=11, color=TEXT_MUTED)
                ]

            if agg.top_ports:
                self.top_ports_list.controls = [
                    ft.Row(
                        [
                            ft.Text(
                                format_port(p, with_label=True),
                                size=11,
                                color=TEXT_SECONDARY,
                                expand=True,
                                max_lines=1,
                                overflow=ft.TextOverflow.ELLIPSIS,
                                font_family="Consolas",
                            ),
                            badge(str(c), color=ACCENT_PURPLE),
                        ],
                        spacing=6,
                    )
                    for p, c in agg.top_ports[:6]
                ]
            else:
                self.top_ports_list.controls = [
                    ft.Text("No hot ports yet", size=11, color=TEXT_MUTED)
                ]

        warn = stats.permission_warning or ""
        if warn != self._warn_sig:
            self._warn_sig = warn
            if warn:
                self.warning_banner.content = ft.Container(
                    content=ft.Row(
                        [
                            ft.Icon(ft.Icons.WARNING_AMBER_ROUNDED, color=OPS_AMBER, size=18),
                            ft.Text(warn, color=TEXT_SECONDARY, expand=True, size=12),
                        ],
                        spacing=10,
                    ),
                    bgcolor="#1A1610",
                    border=ft.Border.all(1, OPS_AMBER),
                    border_radius=8,
                    padding=10,
                )
                self.warning_banner.visible = True
            else:
                self.warning_banner.visible = False

        hist = stats.connection_history or []
        bw = stats.bandwidth_history or []
        # Only rebuild chart trees when endpoints move (expensive control trees).
        charts_sig = (
            f"{len(hist)}|{hist[-1][1] if hist else 0}|"
            f"{len(bw)}|{int(bw[-1][1]) if bw else 0}|{int(bw[-1][2]) if bw else 0}"
        )
        if charts_sig == self._charts_sig and self.connections_chart_host.content is not None:
            return
        self._charts_sig = charts_sig

        conn_points = [(ts, float(count)) for ts, count in hist]
        self.connections_chart_host.content = build_line_chart(
            "Link volume · 5 min", conn_points, color=ACCENT
        )
        self.bandwidth_chart_host.content = build_dual_bandwidth_chart(
            "Throughput · 5 min", bw
        )
