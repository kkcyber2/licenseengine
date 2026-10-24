"""Core data types.

The model is deliberately small: a :class:`Component` is a named dependency with
a licence expression, and the audit reduces the graph to a set of findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable


class Severity(str, Enum):
    """How much a finding should hurt.

    Ordered so that ``max()`` gives the worst finding, which is what the summary
    needs. String values keep JSON output readable.
    """

    OK = "ok"
    NOTICE = "notice"
    WARN = "warn"
    FAIL = "fail"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.OK: 0,
    Severity.NOTICE: 1,
    Severity.WARN: 2,
    Severity.FAIL: 3,
}


@dataclass(frozen=True)
class License:
    """A licence as known to the built-in database.

    ``identifier`` is the SPDX id. Vendors sometimes ship ids that SPDX has since
    deprecated or that are simply typos; those are recorded as unknown rather than
    silently accepted, because a typo in a licence field is a legal risk.
    """

    identifier: str
    name: str
    osi_approved: bool
    copyleft: str  # "none" | "weak" | "strong" | "network"
    patent_grant: bool = False
    attribution_required: bool = True
    notice_file_required: bool = False


@dataclass
class Component:
    """One dependency edge in the audited graph.

    ``depth`` matters: a copyleft dependency pulled in transitively creates the same
    obligation as a direct one, and teams routinely miss that.
    """

    name: str
    version: str = ""
    license_expression: str = ""
    direct: bool = True
    depth: int = 0
    ecosystem: str = ""
    homepage: str = ""

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("component name must not be empty")
        if self.depth < 0:
            raise ValueError("depth must be >= 0")
        # Keep direct/depth consistent rather than trusting two fields to agree.
        if not self.direct:
            self.depth = max(self.depth, 1)


@dataclass
class Policy:
    """What the organisation is willing to ship.

    The defaults are the conservative ones a company with a closed-source product
    would pick, because that is the case where getting this wrong is expensive.
    """

    allowed: tuple[str, ...] = (
        "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "Unlicense",
    )
    denied: tuple[str, ...] = ()
    allow_copyleft: bool = False
    allow_network_copyleft: bool = False
    allow_unknown: bool = False
    require_attribution: bool = True
    max_depth: int = 0  # 0 = unlimited

    def __post_init__(self) -> None:
        if self.max_depth < 0:
            raise ValueError("max_depth must be >= 0")


@dataclass
class Finding:
    """One verdict about one component."""

    component: str
    license_id: str
    severity: Severity
    code: str
    message: str
    direct: bool = True
    depth: int = 0
    remedy: str = ""

    def to_dict(self) -> dict:
        return {
            "component": self.component,
            "license": self.license_id,
            "severity": self.severity.value,
            "code": self.code,
            "message": self.message,
            "direct": self.direct,
            "depth": self.depth,
            "remedy": self.remedy,
        }


@dataclass
class Report:
    """The audit result: findings plus the derived verdict."""

    findings: list[Finding] = field(default_factory=list)
    components: int = 0
    obligations: dict[str, list[str]] = field(default_factory=dict)

    @property
    def verdict(self) -> Severity:
        if not self.findings:
            return Severity.OK
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    @property
    def blocking(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.FAIL]

    @property
    def passed(self) -> bool:
        return not self.blocking

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "passed": self.passed,
            "components": self.components,
            "counts": self.counts(),
            "obligations": self.obligations,
            "findings": [f.to_dict() for f in self.findings],
        }
