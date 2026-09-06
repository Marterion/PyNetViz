"""Export connection snapshots to CSV / JSON (no UI dependency)."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Sequence

from pynetviz.models.connection import ConnectionRecord


class ExportFormat(str, Enum):
    CSV = "csv"
    JSON = "json"


EXPORT_COLUMNS: tuple[str, ...] = (
    "pid",
    "process_name",
    "executable_path",
    "local_addr",
    "local_port",
    "remote_addr",
    "remote_port",
    "hostname",
    "protocol",
    "state",
    "direction",
    "bytes_sent",
    "bytes_recv",
    "risk_score",
    "risk_reasons",
    "last_seen",
)


def record_to_row(record: ConnectionRecord) -> dict[str, Any]:
    """Flat serializable dict for one connection."""
    return {
        "pid": record.pid,
        "process_name": record.process_name,
        "executable_path": record.executable_path,
        "local_addr": record.local_addr,
        "local_port": record.local_port,
        "remote_addr": record.remote_addr,
        "remote_port": record.remote_port,
        "hostname": record.hostname,
        "protocol": record.protocol,
        "state": record.state,
        "direction": (
            record.direction.value
            if hasattr(record.direction, "value")
            else str(record.direction)
        ),
        "bytes_sent": record.bytes_sent,
        "bytes_recv": record.bytes_recv,
        "risk_score": record.risk_score,
        "risk_reasons": "; ".join(record.risk_reasons or []),
        "last_seen": (
            record.last_seen.isoformat(timespec="seconds")
            if isinstance(record.last_seen, datetime)
            else str(record.last_seen)
        ),
    }


def records_to_csv(records: Sequence[ConnectionRecord]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(EXPORT_COLUMNS), lineterminator="\n")
    writer.writeheader()
    for rec in records:
        writer.writerow(record_to_row(rec))
    return buf.getvalue()


def records_to_json(records: Sequence[ConnectionRecord], *, pretty: bool = True) -> str:
    payload = {
        "exported_at": datetime.now().isoformat(timespec="seconds"),
        "count": len(records),
        "connections": [record_to_row(r) for r in records],
    }
    if pretty:
        return json.dumps(payload, indent=2)
    return json.dumps(payload, separators=(",", ":"))


def export_records(
    records: Sequence[ConnectionRecord],
    path: Path | str,
    *,
    fmt: Optional[ExportFormat] = None,
) -> Path:
    """Write records to path. Format inferred from suffix when fmt omitted."""
    out = Path(path)
    if fmt is None:
        suffix = out.suffix.lower().lstrip(".")
        if suffix == "json":
            fmt = ExportFormat.JSON
        else:
            fmt = ExportFormat.CSV
    out.parent.mkdir(parents=True, exist_ok=True)
    if fmt == ExportFormat.JSON:
        text = records_to_json(records)
    else:
        text = records_to_csv(records)
    out.write_text(text, encoding="utf-8")
    return out


def default_export_path(fmt: ExportFormat = ExportFormat.CSV) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = fmt.value
    return Path.home() / ".pynetviz" / "exports" / f"connections_{stamp}.{ext}"
