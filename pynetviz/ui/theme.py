"""PyNetViz v2 design system — dark monitoring palette + UI primitives."""

from __future__ import annotations

import flet as ft

# ── Ops-center palette ───────────────────────────────────────────────────────
DARK_BG = "#05080D"
SURFACE = "#0B1118"
SURFACE_ELEVATED = "#101820"
SURFACE_VARIANT = "#16202C"
SURFACE_HOVER = "#1C2A38"
SURFACE_ACTIVE = "#243548"
BORDER = "#1E3040"
BORDER_SUBTLE = "#14202C"
BORDER_GLOW = "#1A4A62"
BORDER_FOCUS = "#3D8FB8"
GRID_LINE = "#0F1A24"
TEXT_PRIMARY = "#E6F1FF"
TEXT_SECONDARY = "#7F96B0"
TEXT_MUTED = "#4E6278"
ACCENT = "#2EE6A6"  # ops green-cyan
ACCENT_DIM = "#157A5A"
ACCENT_GLOW = "#2EE6A633"
ACCENT_GREEN = "#3DFF9A"
ACCENT_ORANGE = "#FFB020"
ACCENT_RED = "#FF5C6A"
ACCENT_BLUE = "#4DB7FF"
ACCENT_PURPLE = "#A78BFA"
ACCENT_CYAN = "#22D3EE"
ACCENT_YELLOW = "#FBBF24"
ACCENT_PINK = "#F472B6"
OPS_AMBER = "#FFB020"
OPS_TEAL = "#14B8A6"

# State / semantic
STATE_ESTABLISHED = "#4ADE80"
STATE_LISTEN = "#60A5FA"
STATE_INBOUND = "#FB923C"
STATE_CLOSING = "#F87171"
STATE_UNKNOWN = "#8B9CB3"
STATE_OUTBOUND = "#38BDF8"

# Risk
RISK_LOW = "#4ADE80"
RISK_MEDIUM = "#FBBF24"
RISK_ELEVATED = "#FB923C"
RISK_HIGH = "#F87171"

# Chart
CHART_UP = ACCENT
CHART_DOWN = ACCENT_GREEN

# Sidebar
SIDEBAR_WIDTH = 212
SIDEBAR_COLLAPSED = 64
SIDEBAR_BG = "#060A10"

# Density spacing
DENSITY_PAD = {"comfortable": 14, "compact": 8}
DENSITY_GAP = {"comfortable": 12, "compact": 8}


def apply_dark_theme(page: ft.Page) -> None:
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = DARK_BG
    page.padding = 0
    page.theme = ft.Theme(
        color_scheme_seed=ACCENT,
        font_family="Segoe UI",
    )


def risk_color(score: int) -> str:
    if score >= 75:
        return RISK_HIGH
    if score >= 55:
        return RISK_ELEVATED
    if score >= 40:
        return RISK_MEDIUM
    return RISK_LOW


def surface_card(
    content: ft.Control,
    *,
    padding: int | ft.Padding = 16,
    expand: bool = False,
    height: int | None = None,
    width: int | None = None,
    bgcolor: str = SURFACE,
    border_color: str = BORDER,
    radius: int = 14,
    accent_left: str | None = None,
) -> ft.Container:
    """Elevated surface card used across the app."""
    border = ft.Border.all(1, border_color)
    if accent_left:
        border = ft.Border(
            left=ft.BorderSide(3, accent_left),
            top=ft.BorderSide(1, border_color),
            right=ft.BorderSide(1, border_color),
            bottom=ft.BorderSide(1, border_color),
        )
    return ft.Container(
        content=content,
        bgcolor=bgcolor,
        border=border,
        border_radius=radius,
        padding=padding,
        expand=expand,
        height=height,
        width=width,
    )


def stat_card(
    title: str,
    value: str,
    icon: str,
    color: str = ACCENT,
    *,
    subtitle: str = "",
) -> ft.Container:
    """KPI tile with icon chip and large metric value."""
    controls: list[ft.Control] = [
        ft.Row(
            [
                ft.Container(
                    content=ft.Icon(icon, color=color, size=18),
                    bgcolor=f"{color}22",
                    border_radius=10,
                    padding=9,
                    border=ft.Border.all(1, f"{color}33"),
                ),
                ft.Text(title, size=12, color=TEXT_SECONDARY, expand=True),
            ],
            spacing=10,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        ft.Text(
            value,
            size=24,
            weight=ft.FontWeight.W_700,
            color=TEXT_PRIMARY,
            max_lines=1,
            overflow=ft.TextOverflow.ELLIPSIS,
        ),
        # Always present so callers can mutate subtitle without rebuilding the card.
        ft.Text(subtitle or " ", size=11, color=TEXT_MUTED, max_lines=1),
    ]
    return ft.Container(
        content=ft.Column(controls, spacing=8),
        bgcolor=SURFACE,
        border=ft.Border(
            left=ft.BorderSide(3, color),
            top=ft.BorderSide(1, BORDER),
            right=ft.BorderSide(1, BORDER),
            bottom=ft.BorderSide(1, BORDER),
        ),
        border_radius=14,
        padding=ft.Padding.symmetric(horizontal=14, vertical=14),
        expand=True,
    )


def section_title(text: str) -> ft.Text:
    return ft.Text(text, size=13, weight=ft.FontWeight.W_700, color=TEXT_PRIMARY)


def ops_section_header(title: str, subtitle: str = "", accent: str = ACCENT) -> ft.Control:
    """Uppercase ops-center panel header with accent tick."""
    return ft.Row(
        [
            ft.Container(width=3, height=16, bgcolor=accent, border_radius=2),
            ft.Column(
                [
                    ft.Text(
                        title.upper(),
                        size=11,
                        weight=ft.FontWeight.W_700,
                        color=TEXT_PRIMARY,
                        font_family="Consolas",
                    ),
                    ft.Text(subtitle, size=10, color=TEXT_MUTED) if subtitle else ft.Container(height=0),
                ],
                spacing=1,
                expand=True,
            ),
        ],
        spacing=10,
        vertical_alignment=ft.CrossAxisAlignment.CENTER,
    )


def ops_panel(
    content: ft.Control,
    *,
    expand: bool = True,
    height: int | None = None,
    padding: int = 12,
    accent: str | None = None,
) -> ft.Container:
    """Glowing edge panel for ops-center surfaces."""
    border = ft.Border.all(1, BORDER)
    if accent:
        border = ft.Border(
            left=ft.BorderSide(2, accent),
            top=ft.BorderSide(1, BORDER),
            right=ft.BorderSide(1, BORDER),
            bottom=ft.BorderSide(1, BORDER),
        )
    return ft.Container(
        content=content,
        bgcolor=SURFACE,
        border=border,
        border_radius=10,
        padding=padding,
        expand=expand,
        height=height,
    )


def status_dot(color: str = ACCENT_GREEN, size: int = 8) -> ft.Container:
    return ft.Container(
        width=size,
        height=size,
        bgcolor=color,
        border_radius=size,
        border=ft.Border.all(1, f"{color}66"),
    )


def badge(
    text: str,
    *,
    color: str = ACCENT,
    bgcolor: str | None = None,
    size: int = 10,
) -> ft.Container:
    """Small colored status / count pill."""
    bg = bgcolor or f"{color}22"
    return ft.Container(
        content=ft.Text(
            text,
            size=size,
            color=color,
            weight=ft.FontWeight.W_600,
            max_lines=1,
        ),
        bgcolor=bg,
        border_radius=6,
        padding=ft.Padding.symmetric(horizontal=8, vertical=3),
        border=ft.Border.all(1, f"{color}33"),
    )


def empty_state(message: str, icon: str = ft.Icons.INBOX_OUTLINED) -> ft.Container:
    return ft.Container(
        content=ft.Column(
            [
                ft.Icon(icon, size=40, color=TEXT_MUTED),
                ft.Text(message, size=13, color=TEXT_SECONDARY, text_align=ft.TextAlign.CENTER),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=12,
        ),
        alignment=ft.Alignment.CENTER,
        expand=True,
        padding=28,
    )


def nav_tab(
    label: str,
    icon: str,
    *,
    selected: bool,
    on_click,
    badge_text: str | None = None,
) -> ft.Container:
    """Pill-style navigation tab (top bar / compact)."""
    row_items: list[ft.Control] = [
        ft.Icon(icon, size=16, color=ACCENT if selected else TEXT_SECONDARY),
        ft.Text(
            label,
            size=13,
            weight=ft.FontWeight.W_600 if selected else ft.FontWeight.W_400,
            color=ACCENT if selected else TEXT_SECONDARY,
        ),
    ]
    if badge_text:
        row_items.append(badge(badge_text, color=ACCENT_RED if selected else TEXT_MUTED, size=9))
    return ft.Container(
        content=ft.Row(row_items, spacing=8, tight=True),
        padding=ft.Padding.symmetric(horizontal=14, vertical=9),
        bgcolor=SURFACE_VARIANT if selected else None,
        border=ft.Border.all(1, ACCENT_DIM if selected else BORDER),
        border_radius=10,
        on_click=on_click,
    )


def sidebar_item(
    label: str,
    icon: str,
    *,
    selected: bool,
    on_click,
    badge_text: str | None = None,
    collapsed: bool = False,
) -> ft.Container:
    """Left-rail ops-center navigation item."""
    icon_color = ACCENT if selected else TEXT_SECONDARY
    if collapsed:
        content: ft.Control = ft.Column(
            [
                ft.Icon(icon, size=22, color=icon_color),
                ft.Text(label[:4], size=9, color=icon_color, text_align=ft.TextAlign.CENTER)
                if not badge_text
                else badge(badge_text, color=ACCENT_RED, size=8),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=4,
            tight=True,
        )
        return ft.Container(
            content=content,
            padding=ft.Padding.symmetric(horizontal=8, vertical=12),
            bgcolor=f"{ACCENT}14" if selected else None,
            border=ft.Border(
                left=ft.BorderSide(3, ACCENT) if selected else ft.BorderSide(3, "transparent"),
            ),
            border_radius=ft.BorderRadius.only(top_right=8, bottom_right=8),
            on_click=on_click,
            tooltip=label,
            width=SIDEBAR_COLLAPSED - 4,
        )

    items: list[ft.Control] = [
        ft.Icon(icon, size=18, color=icon_color),
        ft.Text(
            label.upper() if selected else label,
            size=12,
            weight=ft.FontWeight.W_700 if selected else ft.FontWeight.W_500,
            color=TEXT_PRIMARY if selected else TEXT_SECONDARY,
            font_family="Consolas" if selected else None,
            expand=True,
        ),
    ]
    if badge_text:
        items.append(badge(badge_text, color=ACCENT_RED, size=9))
    return ft.Container(
        content=ft.Row(items, spacing=12, vertical_alignment=ft.CrossAxisAlignment.CENTER),
        padding=ft.Padding.symmetric(horizontal=14, vertical=11),
        bgcolor=f"{ACCENT}14" if selected else None,
        border=ft.Border(
            left=ft.BorderSide(3, ACCENT if selected else "transparent"),
        ),
        border_radius=ft.BorderRadius.only(top_right=8, bottom_right=8),
        on_click=on_click,
        margin=ft.Margin.only(right=8),
    )


def filter_field_style() -> dict:
    """Shared kwargs for compact filter controls."""
    return {
        "border_color": BORDER,
        "focused_border_color": ACCENT,
        "bgcolor": SURFACE_ELEVATED,
        "color": TEXT_PRIMARY,
        "label_style": ft.TextStyle(color=TEXT_SECONDARY, size=12),
        "text_size": 13,
        "content_padding": ft.Padding.symmetric(horizontal=12, vertical=10),
        "border_radius": 10,
    }


def progress_bar(ratio: float, *, color: str = ACCENT, height: int = 6) -> ft.Container:
    """Alias for build_ratio_bar (kept for callers)."""
    return build_ratio_bar(ratio, color=color, height=height)


def build_ratio_bar(ratio: float, *, color: str = ACCENT, height: int = 6) -> ft.Container:
    r = max(0.0, min(1.0, float(ratio)))
    fill_pct = max(int(r * 100), 2 if r > 0 else 0)
    return ft.Container(
        content=ft.Row(
            [
                ft.Container(
                    bgcolor=color,
                    border_radius=4,
                    height=height,
                    expand=max(fill_pct, 1) if r > 0 else 0,
                ),
                ft.Container(expand=max(100 - fill_pct, 1) if r < 1 else 0, height=height),
            ],
            spacing=0,
            expand=True,
        ),
        bgcolor=SURFACE_VARIANT,
        border_radius=4,
        height=height,
        expand=True,
        clip_behavior=ft.ClipBehavior.HARD_EDGE,
    )
