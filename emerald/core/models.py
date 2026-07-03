"""Core data model. Every scanner - built-in, LLM, or user-supplied - is
normalized into these two structures so results are always comparable."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 0, "": 0}

_SEV_ALIASES = {
    "error": "high", "warning": "medium", "note": "low", "information": "info",
    "moderate": "medium", "severe": "high", "blocker": "critical",
    "critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info",
}


def norm_severity(s: str) -> str:
    """Map any scanner's severity vocabulary onto a common ladder."""
    s = (s or "").strip().lower()
    return _SEV_ALIASES.get(s, s or "unknown")


@dataclass
class Finding:
    rule: str = ""
    severity: str = "unknown"          # critical|high|medium|low|info|unknown
    file: str = ""                     # repo-relative path
    line: int | None = None
    message: str = ""
    scanner: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def key(self) -> tuple:
        """Location-based identity used for cross-scanner overlap/dedup."""
        return ((self.file or "").replace("\\", "/").lower(), self.line, (self.rule or "").lower())

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    scanner: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    seconds: float = 0.0
    ok: bool = True
    error: str = ""
    skipped: str = ""                  # non-empty => not applicable (e.g. wrong language)

    @property
    def count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict:
        return {
            "scanner": self.scanner, "target": self.target, "seconds": self.seconds,
            "ok": self.ok, "error": self.error, "skipped": self.skipped,
            "findings": [f.to_dict() for f in self.findings],
        }
