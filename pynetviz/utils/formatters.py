"""Shared display formatters for rates, bytes, durations, and counts."""

from __future__ import annotations

from datetime import datetime
from typing import Optional, Union


def format_bytes(n: Union[int, float], *, precision: int = 1) -> str:
    """Human-readable byte count (B / KB / MB / GB)."""
    try:
        value = float(n)
    except (TypeError, ValueError):
        return "0 B"
    if value < 0:
        value = 0.0
    if value < 1024:
        return f"{int(value)} B"
    if value < 1024 * 1024:
        return f"{value / 1024:.{precision}f} KB"
    if value < 1024 * 1024 * 1024:
        return f"{value / (1024 * 1024):.{precision}f} MB"
    return f"{value / (1024 * 1024 * 1024):.{precision}f} GB"


def format_bytes_compact(n: Union[int, float]) -> str:
    """Ultra-compact table cell format (e.g. 12K, 3M)."""
    try:
        value = int(n)
    except (TypeError, ValueError):
        return "0"
    if value < 0:
        value = 0
    if value < 1024:
        return str(value)
    if value < 1024 * 1024:
        return f"{value // 1024}K"
    if value < 1024 * 1024 * 1024:
        return f"{value // (1024 * 1024)}M"
    return f"{value // (1024 * 1024 * 1024)}G"


def format_rate(bps: Union[int, float], *, precision: int = 1) -> str:
    """Bytes-per-second rate string."""
    try:
        value = float(bps)
    except (TypeError, ValueError):
        return "0 B/s"
    if value < 0:
        value = 0.0
    if value < 1024:
        return f"{value:.0f} B/s"
    if value < 1024 * 1024:
        return f"{value / 1024:.{precision}f} KB/s"
    return f"{value / (1024 * 1024):.{precision}f} MB/s"


def format_count(n: Union[int, float]) -> str:
    """Integer with thousands separators when large."""
    try:
        value = int(n)
    except (TypeError, ValueError):
        return "0"
    if abs(value) < 1000:
        return str(value)
    return f"{value:,}"


def format_duration(seconds: Union[int, float]) -> str:
    """Compact duration from seconds (e.g. 45s, 3m 12s, 1h 02m)."""
    try:
        total = int(max(0, float(seconds)))
    except (TypeError, ValueError):
        return "0s"
    if total < 60:
        return f"{total}s"
    minutes, secs = divmod(total, 60)
    if minutes < 60:
        return f"{minutes}m {secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m"


def format_timestamp(
    dt: Optional[datetime],
    *,
    with_date: bool = False,
) -> str:
    """Local clock string; empty when dt is None."""
    if dt is None:
        return "—"
    if with_date:
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    return dt.strftime("%H:%M:%S")


def format_percent(value: Union[int, float], *, precision: int = 0) -> str:
    try:
        return f"{float(value):.{precision}f}%"
    except (TypeError, ValueError):
        return "0%"
