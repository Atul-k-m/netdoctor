"""Result model shared by every check, the renderer and (later) the verdict engine."""

from __future__ import annotations

import enum
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any


class Status(str, enum.Enum):
    PASS = "pass"
    INFO = "info"
    WARN = "warn"
    FAIL = "fail"
    SKIP = "skip"
    ERROR = "error"  # the check itself crashed; says nothing about the network

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK = {
    Status.SKIP: 0,
    Status.PASS: 1,
    Status.INFO: 2,
    Status.WARN: 3,
    Status.ERROR: 3,
    Status.FAIL: 4,
}


def worst(statuses: Iterable[Status]) -> Status:
    out = Status.SKIP
    for s in statuses:
        if s.rank > out.rank:
            out = s
    return out


@dataclass
class Finding:
    """One machine-readable observation. `code` is stable and is what rules match on."""

    code: str
    status: Status
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "status": self.status.value, "message": self.message}


@dataclass
class Table:
    title: str
    columns: list[str]
    rows: list[list[str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"title": self.title, "columns": self.columns, "rows": self.rows}


@dataclass
class CheckResult:
    id: str
    layer: str
    title: str
    status: Status = Status.PASS
    summary: str = ""
    evidence: list[str] = field(default_factory=list)
    tables: list[Table] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    commands: list[str] = field(default_factory=list)
    duration_ms: float = 0.0

    def add(self, code: str, status: Status, message: str) -> Finding:
        finding = Finding(code, status, message)
        self.findings.append(finding)
        if status.rank > self.status.rank:
            self.status = status
        return finding

    def skip(self, reason: str) -> CheckResult:
        self.status = Status.SKIP
        self.summary = reason
        return self

    def has(self, *codes: str) -> bool:
        return any(f.code in codes for f in self.findings)

    def finding(self, code: str) -> Finding | None:
        return next((f for f in self.findings if f.code == code), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "layer": self.layer,
            "title": self.title,
            "status": self.status.value,
            "summary": self.summary,
            "evidence": self.evidence,
            "tables": [t.to_dict() for t in self.tables],
            "findings": [f.to_dict() for f in self.findings],
            "commands": self.commands,
            "duration_ms": round(self.duration_ms, 1),
            "data": self.data,
        }
