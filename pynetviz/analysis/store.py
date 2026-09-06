"""SQLite event store: first-seen maps, hourly stats, samples, alerts."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional, Sequence

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path.home() / ".pynetviz" / "analysis.db"


def _chunks(seq: Sequence, size: int) -> Iterable[Sequence]:
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


@dataclass
class FirstSeenHit:
    kind: str
    key: str
    first_seen: datetime
    last_seen: datetime
    is_new: bool  # True if first observation in this process lifetime / just inserted


class AnalysisStore:
    """Thread-safe SQLite store for analysis features."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self._lock = threading.RLock()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = self._connect()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA busy_timeout=5000")
        except sqlite3.Error:
            logger.debug("SQLite PRAGMA setup failed", exc_info=True)
        return conn

    @contextmanager
    def _cursor(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            conn = self._conn
            if conn is None:
                raise RuntimeError("AnalysisStore is closed")
            cur = conn.cursor()
            try:
                yield cur
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    def close(self) -> None:
        with self._lock:
            conn = getattr(self, "_conn", None)
            if conn is None:
                return
            try:
                conn.close()
            except sqlite3.Error:
                pass
            self._conn = None  # type: ignore[assignment]

    def _init_db(self) -> None:
        with self._cursor() as cur:
            cur.executescript(
                """
                CREATE TABLE IF NOT EXISTS first_seen (
                    kind TEXT NOT NULL,
                    key TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    process_name TEXT,
                    remote_addr TEXT,
                    remote_port INTEGER,
                    PRIMARY KEY (kind, key)
                );
                CREATE TABLE IF NOT EXISTS hourly_stats (
                    hour_ts TEXT PRIMARY KEY,
                    total_connections INTEGER,
                    established INTEGER,
                    unique_remotes INTEGER,
                    upload_bps REAL,
                    download_bps REAL
                );
                CREATE TABLE IF NOT EXISTS connection_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    process_name TEXT,
                    pid INTEGER,
                    remote_addr TEXT,
                    remote_port INTEGER,
                    protocol TEXT,
                    state TEXT,
                    risk_score INTEGER,
                    risk_reasons TEXT
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    level TEXT NOT NULL,
                    title TEXT NOT NULL,
                    body TEXT NOT NULL,
                    fingerprint TEXT,
                    read INTEGER DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint ON alerts(fingerprint, ts);
                CREATE INDEX IF NOT EXISTS idx_samples_ts ON connection_samples(ts DESC);
                CREATE INDEX IF NOT EXISTS idx_first_seen_last ON first_seen(last_seen);
                """
            )

    @staticmethod
    def _iso(dt: Optional[datetime] = None) -> str:
        return (dt or datetime.now()).isoformat(timespec="seconds")

    @staticmethod
    def _parse(ts: str) -> datetime:
        try:
            return datetime.fromisoformat(ts)
        except ValueError:
            return datetime.now()

    # ── first-seen ───────────────────────────────────────────────────────────

    def observe_first_seen(
        self,
        kind: str,
        key: str,
        *,
        process_name: str = "",
        remote_addr: str = "",
        remote_port: int = 0,
        now: Optional[datetime] = None,
    ) -> FirstSeenHit:
        """Upsert first-seen. is_new=True only when row did not exist."""
        hits = self.observe_first_seen_batch(
            [(kind, key, process_name, remote_addr, remote_port)],
            now=now,
        )
        return hits[(kind, key)]

    def observe_first_seen_batch(
        self,
        items: Sequence[tuple[str, str, str, str, int]],
        *,
        now: Optional[datetime] = None,
    ) -> dict[tuple[str, str], FirstSeenHit]:
        """Upsert many first-seen rows in one transaction.

        Each item is (kind, key, process_name, remote_addr, remote_port).
        """
        if not items:
            return {}
        ts = now or datetime.now()
        iso = self._iso(ts)
        uniq: dict[tuple[str, str], tuple[str, str, str, str, int]] = {}
        for kind, key, process_name, remote_addr, remote_port in items:
            ident = (kind, key)
            if ident not in uniq:
                uniq[ident] = (kind, key, process_name, remote_addr, remote_port)

        results: dict[tuple[str, str], FirstSeenHit] = {}
        keys = list(uniq.keys())
        existing: dict[tuple[str, str], str] = {}
        with self._cursor() as cur:
            for chunk in _chunks(keys, 400):
                placeholders = ",".join("(?,?)" for _ in chunk)
                params: list[str] = [part for pair in chunk for part in pair]
                cur.execute(
                    f"SELECT kind, key, first_seen FROM first_seen "
                    f"WHERE (kind, key) IN ({placeholders})",
                    params,
                )
                for row in cur.fetchall():
                    existing[(row["kind"], row["key"])] = row["first_seen"]

            inserts: list[tuple] = []
            updates: list[tuple] = []
            for ident, (kind, key, process_name, remote_addr, remote_port) in uniq.items():
                first_iso = existing.get(ident)
                if first_iso is None:
                    inserts.append(
                        (kind, key, iso, iso, process_name, remote_addr, remote_port)
                    )
                    results[ident] = FirstSeenHit(
                        kind=kind,
                        key=key,
                        first_seen=ts,
                        last_seen=ts,
                        is_new=True,
                    )
                else:
                    updates.append(
                        (
                            iso,
                            process_name or None,
                            remote_addr or None,
                            remote_port or None,
                            kind,
                            key,
                        )
                    )
                    results[ident] = FirstSeenHit(
                        kind=kind,
                        key=key,
                        first_seen=self._parse(first_iso),
                        last_seen=ts,
                        is_new=False,
                    )

            if inserts:
                cur.executemany(
                    """
                    INSERT INTO first_seen
                    (kind, key, first_seen, last_seen, process_name, remote_addr, remote_port)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    inserts,
                )
            if updates:
                cur.executemany(
                    """
                    UPDATE first_seen SET last_seen=?, process_name=COALESCE(?, process_name),
                    remote_addr=COALESCE(?, remote_addr), remote_port=COALESCE(?, remote_port)
                    WHERE kind=? AND key=?
                    """,
                    updates,
                )
        return results

    def is_known(self, kind: str, key: str) -> bool:
        with self._cursor() as cur:
            cur.execute(
                "SELECT 1 FROM first_seen WHERE kind=? AND key=? LIMIT 1",
                (kind, key),
            )
            return cur.fetchone() is not None

    def recent_first_seen(self, *, kind: Optional[str] = None, limit: int = 20) -> list[dict]:
        with self._cursor() as cur:
            if kind:
                cur.execute(
                    """
                    SELECT kind, key, first_seen, last_seen, process_name, remote_addr, remote_port
                    FROM first_seen WHERE kind=? ORDER BY first_seen DESC LIMIT ?
                    """,
                    (kind, limit),
                )
            else:
                cur.execute(
                    """
                    SELECT kind, key, first_seen, last_seen, process_name, remote_addr, remote_port
                    FROM first_seen ORDER BY first_seen DESC LIMIT ?
                    """,
                    (limit,),
                )
            return [dict(r) for r in cur.fetchall()]

    def count_first_seen_since(self, kind: str, since: datetime) -> int:
        with self._cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS c FROM first_seen WHERE kind=? AND first_seen >= ?",
                (kind, self._iso(since)),
            )
            row = cur.fetchone()
            return int(row["c"] if row else 0)

    # ── hourly stats ─────────────────────────────────────────────────────────

    def record_hourly_snapshot(
        self,
        *,
        total_connections: int,
        established: int,
        unique_remotes: int,
        upload_bps: float,
        download_bps: float,
        now: Optional[datetime] = None,
    ) -> None:
        ts = now or datetime.now()
        hour = ts.replace(minute=0, second=0, microsecond=0)
        with self._cursor() as cur:
            cur.execute(
                """
                INSERT INTO hourly_stats
                (hour_ts, total_connections, established, unique_remotes, upload_bps, download_bps)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(hour_ts) DO UPDATE SET
                    total_connections=excluded.total_connections,
                    established=excluded.established,
                    unique_remotes=excluded.unique_remotes,
                    upload_bps=excluded.upload_bps,
                    download_bps=excluded.download_bps
                """,
                (
                    self._iso(hour),
                    total_connections,
                    established,
                    unique_remotes,
                    upload_bps,
                    download_bps,
                ),
            )

    def recent_hourly(self, hours: int = 24) -> list[dict]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM hourly_stats ORDER BY hour_ts DESC LIMIT ?",
                (hours,),
            )
            return [dict(r) for r in cur.fetchall()]

    # ── connection samples ───────────────────────────────────────────────────

    def sample_connections(self, rows: list[dict[str, Any]], *, max_rows: int = 40) -> None:
        if not rows:
            return
        ts = self._iso()
        payload = rows[:max_rows]
        with self._cursor() as cur:
            cur.executemany(
                """
                INSERT INTO connection_samples
                (ts, process_name, pid, remote_addr, remote_port, protocol, state, risk_score, risk_reasons)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        ts,
                        r.get("process_name", ""),
                        int(r.get("pid") or 0),
                        r.get("remote_addr", ""),
                        int(r.get("remote_port") or 0),
                        r.get("protocol", ""),
                        r.get("state", ""),
                        int(r.get("risk_score") or 0),
                        json.dumps(r.get("risk_reasons") or []),
                    )
                    for r in payload
                ],
            )
            cur.execute("SELECT MAX(id) AS m FROM connection_samples")
            row = cur.fetchone()
            max_id = int(row["m"] or 0) if row else 0
            if max_id > 5000:
                cur.execute(
                    "DELETE FROM connection_samples WHERE id <= ?",
                    (max_id - 5000,),
                )

    def recent_samples(self, limit: int = 40) -> list[dict]:
        """Latest stored connection samples (newest first)."""
        with self._cursor() as cur:
            cur.execute(
                """
                SELECT id, ts, process_name, pid, remote_addr, remote_port,
                       protocol, state, risk_score, risk_reasons
                FROM connection_samples
                ORDER BY id DESC
                LIMIT ?
                """,
                (max(1, int(limit)),),
            )
            return [dict(r) for r in cur.fetchall()]

    # ── alerts ───────────────────────────────────────────────────────────────

    def add_alert(
        self,
        *,
        level: str,
        title: str,
        body: str,
        fingerprint: str = "",
        now: Optional[datetime] = None,
        dedupe_minutes: int = 30,
    ) -> Optional[int]:
        """Insert alert; skip if same fingerprint seen recently. Returns new id or None."""
        ts = now or datetime.now()
        if fingerprint:
            cutoff = self._iso(ts - timedelta(minutes=dedupe_minutes))
            with self._cursor() as cur:
                cur.execute(
                    """
                    SELECT id FROM alerts
                    WHERE fingerprint=? AND ts >= ? LIMIT 1
                    """,
                    (fingerprint, cutoff),
                )
                if cur.fetchone():
                    return None
                cur.execute(
                    """
                    INSERT INTO alerts (ts, level, title, body, fingerprint, read)
                    VALUES (?, ?, ?, ?, ?, 0)
                    """,
                    (self._iso(ts), level, title, body, fingerprint),
                )
                return int(cur.lastrowid)
        with self._cursor() as cur:
            cur.execute(
                """
                INSERT INTO alerts (ts, level, title, body, fingerprint, read)
                VALUES (?, ?, ?, ?, ?, 0)
                """,
                (self._iso(ts), level, title, body, fingerprint),
            )
            return int(cur.lastrowid)

    def recent_alerts(self, limit: int = 50, unread_only: bool = False) -> list[dict]:
        with self._cursor() as cur:
            if unread_only:
                cur.execute(
                    """
                    SELECT id, ts, level, title, body, fingerprint, read
                    FROM alerts WHERE read=0 ORDER BY id DESC LIMIT ?
                    """,
                    (limit,),
                )
            else:
                cur.execute(
                    """
                    SELECT id, ts, level, title, body, fingerprint, read
                    FROM alerts ORDER BY id DESC LIMIT ?
                    """,
                    (limit,),
                )
            return [dict(r) for r in cur.fetchall()]

    def mark_alerts_read(self, alert_ids: Optional[list[int]] = None) -> None:
        with self._cursor() as cur:
            if alert_ids:
                cur.executemany(
                    "UPDATE alerts SET read=1 WHERE id=?",
                    [(i,) for i in alert_ids],
                )
            else:
                cur.execute("UPDATE alerts SET read=1")

    def unread_alert_count(self) -> int:
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM alerts WHERE read=0")
            row = cur.fetchone()
            return int(row["c"] if row else 0)

    def prune_old(self, *, days: int = 14) -> None:
        cutoff = self._iso(datetime.now() - timedelta(days=days))
        with self._cursor() as cur:
            cur.execute("DELETE FROM connection_samples WHERE ts < ?", (cutoff,))
            cur.execute("DELETE FROM alerts WHERE ts < ? AND read=1", (cutoff,))
