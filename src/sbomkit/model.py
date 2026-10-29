"""Core data model: components, findings, severities."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------- severities

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


def severity_at_least(value: str, floor: str) -> bool:
    """True when `value` is at or above `floor`."""
    return SEVERITY_ORDER.get(value, -1) >= SEVERITY_ORDER.get(floor, 99)


# ---------------------------------------------------------------- components


@dataclass
class Component:
    """A single resolved dependency."""

    ecosystem: str  # pypi | npm | golang | cargo
    name: str
    version: str
    direct: bool = True
    license: str | None = None
    license_source: str = ""  # where the license came from (evidence-style)
    source: str = ""  # file the component was read from
    line: int = 0  # 1-based line in `source`
    evidence: str = ""  # the raw line, as read
    locked: bool = False  # came from a lockfile (pinned) vs manifest (range)

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.name.lower(), self.version)

    @property
    def purl(self) -> str:
        return purl(self.ecosystem, self.name, self.version)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "version": self.version,
            "direct": self.direct,
            "license": self.license,
            "license_source": self.license_source,
            "source": self.source,
            "line": self.line,
            "evidence": self.evidence,
            "locked": self.locked,
            "purl": self.purl,
        }


def purl(ecosystem: str, name: str, version: str) -> str:
    """Build a package URL. Keeps the ecosystem-specific quirks in one place."""
    if ecosystem == "npm":
        # scoped packages keep the scope, and the namespace must stay lowercase
        nm = name if name.startswith("@") else name
        return f"pkg:npm/{nm}@{version}" if version else f"pkg:npm/{nm}"
    if ecosystem == "golang":
        return f"pkg:golang/{name}@{version}" if version else f"pkg:golang/{name}"
    if ecosystem == "cargo":
        return f"pkg:cargo/{name}@{version}" if version else f"pkg:cargo/{name}"
    return f"pkg:pypi/{name}@{version}" if version else f"pkg:pypi/{name}"


# ------------------------------------------------------------------ findings


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    detail: str
    file: str = ""
    line: int = 0
    evidence: str = ""
    component: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
            "component": self.component,
        }


@dataclass
class ScanResult:
    root: str
    components: list[Component] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    licenses_resolved: int = 0

    @property
    def counts(self) -> dict[str, int]:
        out = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    @property
    def risk(self) -> int:
        """0-100 score. Only counts real severities, info contributes nothing."""
        weights = {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}
        score = sum(weights.get(f.severity, 0) for f in self.findings)
        return min(100, score)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "files": self.files,
            "counts": self.counts,
            "risk": self.risk,
            "licenses_resolved": self.licenses_resolved,
            "components": [c.to_dict() for c in self.components],
            "findings": [f.to_dict() for f in self.findings],
        }
