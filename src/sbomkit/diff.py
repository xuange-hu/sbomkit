"""SBOM diff: what changed between two builds.

This is the check that belongs in a pull request. A version bump is noise; a
*downgrade*, a new transitive dependency, or a dependency that quietly changed
license from MIT to AGPL is not. Single-snapshot scanners cannot see any of
those, which is why this is a separate pass rather than a scan rule.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import licenses as lic
from .model import Component, severity_at_least
from .versions import compare

KIND_SEVERITY = {
    "added": "low",
    "removed": "info",
    "upgraded": "low",
    "downgraded": "high",
    "license-changed": "medium",
    "scope-changed": "low",
}


@dataclass
class DiffEntry:
    kind: str
    ecosystem: str
    name: str
    old_version: str = ""
    new_version: str = ""
    old_license: str | None = None
    new_license: str | None = None
    severity: str = "info"
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "ecosystem": self.ecosystem,
            "name": self.name,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "old_license": self.old_license,
            "new_license": self.new_license,
            "severity": self.severity,
            "detail": self.detail,
        }


def _index(components: list[Component]) -> dict[tuple[str, str], Component]:
    return {(c.ecosystem, c.name.lower()): c for c in components}


def diff(old: list[Component], new: list[Component]) -> list[DiffEntry]:
    old_idx = _index(old)
    new_idx = _index(new)
    out: list[DiffEntry] = []

    for key, comp in sorted(new_idx.items()):
        eco, name = key
        prev = old_idx.get(key)
        if prev is None:
            severity = "low"
            detail = f"new dependency {comp.name}@{comp.version}"
            if not comp.license:
                severity = "medium"
                detail += " with no resolvable license"
            out.append(
                DiffEntry(
                    kind="added",
                    ecosystem=eco,
                    name=comp.name,
                    new_version=comp.version,
                    new_license=comp.license,
                    severity=severity,
                    detail=detail,
                )
            )
            continue
        if prev.version != comp.version:
            direction = compare(comp.version, prev.version)
            kind = "upgraded" if direction > 0 else "downgraded"
            detail = f"{comp.name}: {prev.version} -> {comp.version}"
            severity = KIND_SEVERITY[kind]
            if kind == "downgraded":
                detail += " (a downgrade can silently reintroduce a fixed bug)"
            out.append(
                DiffEntry(
                    kind=kind,
                    ecosystem=eco,
                    name=comp.name,
                    old_version=prev.version,
                    new_version=comp.version,
                    old_license=prev.license,
                    new_license=comp.license,
                    severity=severity,
                    detail=detail,
                )
            )
        if (prev.license or None) != (comp.license or None):
            before = lic.risk_level(prev.license)
            after = lic.risk_level(comp.license)
            if after > before:
                severity = "high"
                note = "license became more restrictive"
            elif after < before:
                severity = "low"
                note = "license became more permissive"
            else:
                severity = "medium"
                note = "license changed within the same risk class"
            out.append(
                DiffEntry(
                    kind="license-changed",
                    ecosystem=eco,
                    name=comp.name,
                    old_version=prev.version,
                    new_version=comp.version,
                    old_license=prev.license,
                    new_license=comp.license,
                    severity=severity,
                    detail=f"{comp.name}: {prev.license or 'UNKNOWN'} -> {comp.license or 'UNKNOWN'} ({note})",
                )
            )
        if prev.direct != comp.direct:
            out.append(
                DiffEntry(
                    kind="scope-changed",
                    ecosystem=eco,
                    name=comp.name,
                    old_version=prev.version,
                    new_version=comp.version,
                    severity=KIND_SEVERITY["scope-changed"],
                    detail=f"{comp.name} is now {'direct' if comp.direct else 'transitive'}",
                )
            )

    for key, comp in sorted(old_idx.items()):
        if key in new_idx:
            continue
        out.append(
            DiffEntry(
                kind="removed",
                ecosystem=key[0],
                name=comp.name,
                old_version=comp.version,
                old_license=comp.license,
                severity="info",
                detail=f"{comp.name}@{comp.version} is no longer in the tree",
            )
        )

    out.sort(key=lambda d: (d.kind, d.name))
    return out


def worst_severity(entries: list[DiffEntry], floor: str = "low") -> str | None:
    order = ["info", "low", "medium", "high", "critical"]
    present = {e.severity for e in entries}
    for sev in reversed(order):
        if sev in present and severity_at_least(sev, floor):
            return sev
    return None
