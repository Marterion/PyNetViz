from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Deque

import psutil


@dataclass
class BandwidthTracker:
    """Tracks system-wide and per-process network byte counters."""

    history_seconds: int = 300
    _last_io: object = field(default=None, init=False, repr=False)
    _last_time: float = field(default=0.0, init=False, repr=False)
    upload_bps: float = field(default=0.0, init=False)
    download_bps: float = field(default=0.0, init=False)
    bandwidth_history: Deque[tuple[datetime, float, float]] = field(
        default_factory=lambda: deque(maxlen=300), init=False
    )
    _process_io: dict[int, tuple[int, int]] = field(default_factory=dict, init=False, repr=False)

    def update(self) -> None:
        now = time.time()
        counters = psutil.net_io_counters()
        if counters is None:
            return

        if self._last_io is not None and self._last_time > 0:
            dt = max(now - self._last_time, 0.001)
            sent_delta = counters.bytes_sent - self._last_io.bytes_sent
            recv_delta = counters.bytes_recv - self._last_io.bytes_recv
            self.upload_bps = max(sent_delta / dt, 0.0)
            self.download_bps = max(recv_delta / dt, 0.0)
            self.bandwidth_history.append(
                (datetime.now(), self.upload_bps, self.download_bps)
            )

        self._last_io = counters
        self._last_time = now

    def update_process_io(self, pid: int, sent: int, recv: int) -> tuple[int, int]:
        prev = self._process_io.get(pid, (sent, recv))
        delta_sent = max(sent - prev[0], 0)
        delta_recv = max(recv - prev[1], 0)
        self._process_io[pid] = (sent, recv)
        return delta_sent, delta_recv

    def prune_processes(self, active_pids: set[int]) -> None:
        stale = [pid for pid in self._process_io if pid not in active_pids]
        for pid in stale:
            del self._process_io[pid]

    def trim_history(self) -> None:
        cutoff = datetime.now() - timedelta(seconds=self.history_seconds)
        while self.bandwidth_history and self.bandwidth_history[0][0] < cutoff:
            self.bandwidth_history.popleft()