"""Rule-based connection risk scoring with explainable reason chips."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from pynetviz.models.connection import (
    SUSPICIOUS_PORTS,
    ConnectionDirection,
    ConnectionRecord,
)

# Living-off-the-land binaries that rarely need arbitrary outbound sockets
LOLBIN_NAMES = frozenset(
    {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "certutil.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "bitsadmin.exe",
        "curl.exe",
        "wget.exe",
    }
)

RISKY_PATH_MARKERS = (
    "\\temp\\",
    "/temp/",
    "\\tmp\\",
    "/tmp/",
    "\\downloads\\",
    "/downloads/",
    "\\appdata\\local\\temp\\",
)


@dataclass
class RiskAssessment:
    score: int = 0
    reasons: list[str] = field(default_factory=list)
    is_elevated: bool = False  # score >= threshold for red styling

    def to_dict(self) -> dict:
        return {"score": self.score, "reasons": list(self.reasons), "is_elevated": self.is_elevated}


class RiskEngine:
    """Composite risk score (0–100) from local signals + first-seen flags."""

    def __init__(self, elevated_threshold: int = 55) -> None:
        self.elevated_threshold = elevated_threshold

    @staticmethod
    def _is_private_or_local(ip: str) -> bool:
        if not ip or ip in ("0.0.0.0", "::", "*", "127.0.0.1", "::1"):
            return True
        try:
            addr = ipaddress.ip_address(ip.split("%")[0])
            return bool(
                addr.is_private
                or addr.is_loopback
                or addr.is_link_local
                or addr.is_multicast
            )
        except ValueError:
            return False

    @staticmethod
    def _path_risk(path: str) -> Optional[str]:
        if not path:
            return None
        low = path.lower().replace("/", "\\")
        for marker in RISKY_PATH_MARKERS:
            if marker in low:
                return f"path in {marker.strip(chr(92))}"
        # bare downloads folder on desktop-ish
        if re.search(r"\\users\\[^\\]+\\downloads\\", low):
            return "path in user Downloads"
        return None

    def assess(
        self,
        record: ConnectionRecord,
        *,
        first_seen_process: bool = False,
        first_seen_remote: bool = False,
        first_seen_pair: bool = False,
    ) -> RiskAssessment:
        score = 0
        reasons: list[str] = []

        ports = {record.local_port, record.remote_port}
        bad_ports = ports & SUSPICIOUS_PORTS
        if bad_ports:
            score += 35
            reasons.append(f"suspicious port {sorted(bad_ports)[0]}")

        if record.is_unknown_process:
            score += 25
            reasons.append("unknown process")

        name_l = (record.process_name or "").lower()
        if name_l in LOLBIN_NAMES and record.direction == ConnectionDirection.OUTBOUND:
            if not self._is_private_or_local(record.remote_addr):
                score += 30
                reasons.append(f"LOLBin outbound ({record.process_name})")

        path_reason = self._path_risk(record.executable_path or "")
        if path_reason:
            score += 20
            reasons.append(path_reason)

        if first_seen_process:
            score += 15
            reasons.append("new process")
        if first_seen_remote and not self._is_private_or_local(record.remote_addr):
            score += 18
            reasons.append("new remote host")
        if first_seen_pair and not self._is_private_or_local(record.remote_addr):
            score += 10
            reasons.append("new process→remote pair")

        if (
            record.direction == ConnectionDirection.INBOUND
            and (record.state or "").upper() == "ESTABLISHED"
            and not self._is_private_or_local(record.remote_addr)
        ):
            score += 20
            reasons.append("inbound established")

        if record.direction == ConnectionDirection.LISTEN and record.local_port >= 1024:
            # listening on high port is mild; unknown process listening is worse (already counted)
            if record.is_unknown_process or path_reason:
                score += 12
                reasons.append(f"listen on {record.local_port}")

        # Cap and de-dupe reasons
        score = max(0, min(100, score))
        # Keep top reasons by order of discovery
        uniq: list[str] = []
        for r in reasons:
            if r not in uniq:
                uniq.append(r)
        reasons = uniq[:5]

        return RiskAssessment(
            score=score,
            reasons=reasons,
            is_elevated=score >= self.elevated_threshold,
        )

    def apply_to_record(
        self,
        record: ConnectionRecord,
        *,
        first_seen_process: bool = False,
        first_seen_remote: bool = False,
        first_seen_pair: bool = False,
    ) -> RiskAssessment:
        assessment = self.assess(
            record,
            first_seen_process=first_seen_process,
            first_seen_remote=first_seen_remote,
            first_seen_pair=first_seen_pair,
        )
        record.risk_score = assessment.score
        record.risk_reasons = list(assessment.reasons)
        # Recompute color with risk awareness
        record.row_color = record.compute_row_color()
        return assessment
