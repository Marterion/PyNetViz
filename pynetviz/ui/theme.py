from __future__ import annotations

import flet as ft

# ── Dark palette ─────────────────────────────────────────────────────────────
DARK_BG = "#0B0F14"
SURFACE = "#121820"
SURFACE_ELEVATED = "#18212C"
SURFACE_VARIANT = "#1E2A38"
SURFACE_HOVER = "#243344"
BORDER = "#2A3848"
BORDER_SUBTLE = "#1F2A36"
TEXT_PRIMARY = "#E8EEF6"
TEXT_SECONDARY = "#8B9CB3"
TEXT_MUTED = "#5C6B7F"
ACCENT = "#4FC3F7"
ACCENT_DIM = "#2A7A9A"
ACCENT_GREEN = "#4ADE80"
ACCENT_ORANGE = "#FB923C"
ACCENT_RED = "#F87171"
ACCENT_BLUE = "#60A5FA"
ACCENT_PURPLE = "#A78BFA"
ACCENT_CYAN = "#22D3EE"

# State / semantic colors
STATE_ESTABLISHED = "#4ADE80"
STATE_LISTEN = "#60A5FA"
STATE_INBOUND = "#FB923C"
STATE_CLOSING = "#F87171"
STATE_UNKNOWN = "#8B9CB3"

# Chart / sparkline
CHART_UP = ACCENT
CHART_DOWN = ACCENT_GREEN


def apply_dark_theme(page: ft.Page) -> None:
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = DARK_BG
    page.padding = 0
    page.theme = ft.Theme(
        color_scheme_seed=ACCENT,
        font_family="Segoe UI",
    )


def surface_card(
    content: ft.Control,
    *,
    padding: int | ft.Padding = 16,
    expand: bool = False,
    height: int | None = None,
    width: int | None = None,
    bgcolor: str = SURFACE,
    border_color: str = BORDER,
    radius: int = 12,
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


def stat_card(title: str, value: str, icon: str, color: str = ACCENT) -> ft.Container:
    """KPI tile with icon chip and large metric value."""
    return ft.Container(
        content=ft.Column(
            [
                ft.Row(
                    [
                        ft.Container(
                            content=ft.Icon(icon, color=color, size=18),
                            bgcolor=f"{color}22",
                            border_radius=8,
                            padding=8,
                        ),
                        ft.Text(title, size=12, color=TEXT_SECONDARY, expand=True),
                    ],
                    spacing=10,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                ft.Text(
                    value,
                    size=26,
                    weight=ft.FontWeight.W_700,
                    color=TEXT_PRIMARY,
                    max_lines=1,
                    overflow=ft.TextOverflow.ELLIPSIS,
                ),
            ],
            spacing=10,
        ),
        bgcolor=SURFACE,
        border=ft.Border(
            left=ft.BorderSide(3, color),
            top=ft.BorderSide(1, BORDER),
            right=ft.BorderSide(1, BORDER),
            bottom=ft.BorderSide(1, BORDER),
        ),
        border_radius=12,
        padding=ft.Padding.symmetric(horizontal=14, vertical=14),
        expand=True,
    )


def section_title(text: str) -> ft.Text:
    return ft.Text(text, size=14, weight=ft.FontWeight.W_600, color=TEXT_PRIMARY)


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
    )


def empty_state(message: str, icon: str = ft.Icons.INBOX_OUTLINED) -> ft.Container:
    return ft.Container(
        content=ft.Column(
            [
                ft.Icon(icon, size=36, color=TEXT_MUTED),
                ft.Text(message, size=13, color=TEXT_SECONDARY, text_align=ft.TextAlign.CENTER),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=10,
        ),
        alignment=ft.Alignment.CENTER,
        expand=True,
        padding=24,
    )


def nav_tab(
    label: str,
    icon: str,
    *,
    selected: bool,
    on_click,
) -> ft.Container:
    """Pill-style navigation tab."""
    return ft.Container(
        content=ft.Row(
            [
                ft.Icon(icon, size=16, color=ACCENT if selected else TEXT_SECONDARY),
                ft.Text(
                    label,
                    size=13,
                    weight=ft.FontWeight.W_600 if selected else ft.FontWeight.W_400,
                    color=ACCENT if selected else TEXT_SECONDARY,
                ),
            ],
            spacing=8,
            tight=True,
        ),
        padding=ft.Padding.symmetric(horizontal=14, vertical=9),
        bgcolor=SURFACE_VARIANT if selected else None,
        border=ft.Border.all(1, ACCENT_DIM if selected else BORDER),
        border_radius=10,
        on_click=on_click,
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
