"""Directory scan: parse manifests and lockfiles, then apply the rule set."""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import licenses as lic
from . import spdx, typosquat, versions
from .known import known_license
from .model import Component, Finding, ScanResult
from .parsers import (
    LOCKFILES,
    MANIFESTS,
    SKIP_DIRS,
    Declaration,
    ParseResult,
    parse_requirements,
)

# ---------------------------------------------------------------------- rules

RULES: dict[str, tuple[str, str]] = {
    "SBK001": ("medium", "manifest present but no lockfile pins the tree"),
    "SBK002": ("medium", "open-ended version requirement with no lockfile"),
    "SBK003": ("high", "declared dependency is absent from the lockfile"),
    "SBK004": ("info", "lockfile entry is not declared in any manifest (transitive)"),
    "SBK005": ("high", "locked version falls outside the declared constraint"),
    "SBK006": ("critical", "dependency comes from a URL or VCS instead of a registry"),
    "SBK007": ("high", "name resembles a popular package but is not it"),
    "SBK008": ("medium", "license could not be determined"),
    "SBK009": ("high", "license violates the distribution policy"),
    "SBK010": ("medium", "multiple versions of the same package are locked"),
    "SBK011": ("low", "wildcard version specifier"),
    "SBK012": ("medium", "license conflicts between lockfile and local metadata"),
    "SBK013": ("medium", "package resolves from a non-official registry"),
    "SBK014": ("low", "declared in both a runtime and a non-runtime group"),
    "SBK015": ("low", "lockfile has no matching manifest in the project"),
    "SBK016": ("medium", "pinned to a commit pseudo-version rather than a release"),
    "SBK017": ("low", "custom or proprietary license (LicenseRef)"),
}


def rule_ids() -> list[str]:
    return sorted(RULES)


# -------------------------------------------------------------------- options


@dataclass
class Options:
    policy: str = "closed-source"
    license_map: dict[str, dict[str, str]] | None = None
    include_dev: bool = True
    ignore: set[str] = field(default_factory=set)
    offline: bool = True

    def __post_init__(self) -> None:
        # Accept both the nested {"pypi": {...}} form and a flat {"pkg": "MIT"}
        # form; everything downstream only deals with the nested one.
        if self.license_map and not any(isinstance(v, dict) for v in self.license_map.values()):
            self.license_map = {"*": dict(self.license_map)}


def _sev(rule: str, override: str | None = None) -> str:
    return override or RULES[rule][0]


# ------------------------------------------------------------ file discovery


def _handler_for(name: str, is_lock: bool):
    table = LOCKFILES if is_lock else MANIFESTS
    if name in table:
        return table[name]
    if not is_lock and name.startswith("requirements") and name.endswith(".txt"):
        return ("pypi", parse_requirements)
    return None


def discover(root: str) -> tuple[list[tuple[str, str, object]], list[tuple[str, str, object]]]:
    """Return (manifests, lockfiles) as (path, ecosystem, handler) triples."""
    manifests: list[tuple[str, str, object]] = []
    lockfiles: list[tuple[str, str, object]] = []
    base = Path(root)
    if base.is_file():
        hit = _handler_for(base.name, True) or _handler_for(base.name, False)
        if hit:
            (lockfiles if _handler_for(base.name, True) else manifests).append((str(base), hit[0], hit[1]))
        return manifests, lockfiles
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".git")]
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            hit = _handler_for(name, True)
            if hit:
                lockfiles.append((full, hit[0], hit[1]))
                continue
            hit = _handler_for(name, False)
            if hit:
                manifests.append((full, hit[0], hit[1]))
    return manifests, lockfiles


# ------------------------------------------------------------------ installed
# Local, on-disk evidence beats a bundled table. We probe a handful of known
# locations per component rather than walking site-packages / node_modules,
# which would be O(tree) on every scan.


def _installed_license(root: str, component: Component) -> str | None:
    base = Path(root)
    if component.ecosystem == "npm":
        candidate = base / "node_modules" / component.name / "package.json"
        if candidate.is_file():
            try:
                data = json.loads(candidate.read_text(encoding="utf-8", errors="replace"))
            except (json.JSONDecodeError, OSError):
                return None
            value = data.get("license")
            if isinstance(value, dict):
                value = value.get("type")
            if isinstance(value, str):
                return value
        return None
    if component.ecosystem == "pypi":
        for venv in (".venv", "venv", "env"):
            sp = base / venv / "Lib" / "site-packages"
            if not sp.is_dir():
                sp = base / venv / "lib" / f"python3.{_minor()}" / "site-packages"
            if not sp.is_dir():
                continue
            norm = component.name.replace("-", "_").lower()
            for dist in sp.glob("*.dist-info"):
                stem = dist.name.split("-")[0].replace("_", "-").lower()
                if stem != norm:
                    continue
                meta = dist / "METADATA"
                if not meta.is_file():
                    continue
                try:
                    text = meta.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for line in text.splitlines():
                    if line.startswith("License:"):
                        value = line.split(":", 1)[1].strip()
                        if value and value.lower() not in ("unknown", "none"):
                            return value
                    if line.startswith("Classifier: License ::") and "::" in line:
                        tail = line.rsplit("::", 1)[1].strip()
                        if tail and tail.lower() != "osi approved":
                            return tail
        return None
    return None


def _minor() -> int:
    return sys.version_info.minor


# --------------------------------------------------------------- license pass


def resolve_license(root: str, comp: Component, options: Options) -> tuple[str | None, str]:
    """(license expression, where it came from). Never invents a license."""
    if options.license_map:
        table = options.license_map.get(comp.ecosystem) or {}
        hit = table.get(comp.name.lower()) or options.license_map.get("*", {}).get(comp.name.lower())
        if hit:
            return hit, "--license-map"
    # Both sources are probed before deciding: a lockfile that disagrees with
    # the tree actually on disk is itself a finding, and the installed metadata
    # is the stronger evidence of the two.
    lock_expr = lic.normalize(comp.license) if comp.license else None
    local_raw = _installed_license(root, comp)
    local_expr = lic.normalize(local_raw) if local_raw else None
    if local_expr and lock_expr and local_expr != lock_expr:
        return local_expr, "installed metadata (conflicts with lockfile)"
    if lock_expr:
        return lock_expr, f"{os.path.basename(comp.source)} (inline)"
    if local_expr:
        return local_expr, "installed metadata"
    bundled = known_license(comp.ecosystem, comp.name)
    if bundled:
        return bundled, "bundled table"
    return None, ""


# -------------------------------------------------------------------- scanning


def _canon(name: str) -> str:
    return name.strip().lower().replace("_", "-").replace(".", "-")


def scan_path(root: str, options: Options | None = None) -> ScanResult:
    options = options or Options()
    result = ScanResult(root=str(root))
    manifests, lockfiles = discover(root)
    result.files = sorted({p for p, _, _ in manifests} | {p for p, _, _ in lockfiles})

    decls: list[Declaration] = []
    comps: list[Component] = []
    for path, _ecosystem, handler in manifests:
        text = _read(path)
        if text is None:
            continue
        parsed: ParseResult = handler(Path(path), text)  # type: ignore[operator]
        decls.extend(parsed.declarations)
    for path, _ecosystem, handler in lockfiles:
        text = _read(path)
        if text is None:
            continue
        parsed = handler(Path(path), text)  # type: ignore[operator]
        comps.extend(parsed.components)

    if not options.include_dev:
        decls = [d for d in decls if d.kind == "runtime"]

    _mark_direct(decls, comps)
    _apply_licenses(root, comps, options, result)
    result.components = _dedupe(comps)
    result.findings = _rules(root, decls, result.components, manifests, lockfiles, options, result)
    return result


def _read(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _mark_direct(decls: list[Declaration], comps: list[Component]) -> None:
    direct_names: dict[str, set[str]] = {}
    for d in decls:
        direct_names.setdefault(d.ecosystem, set()).add(_canon(d.name))
    for c in comps:
        c.direct = _canon(c.name) in direct_names.get(c.ecosystem, set())


def _apply_licenses(root: str, comps: list[Component], options: Options, result: ScanResult) -> None:
    for c in comps:
        expr, source = resolve_license(root, c, options)
        c.license = expr
        c.license_source = source
        if expr:
            result.licenses_resolved += 1


def _dedupe(comps: list[Component]) -> list[Component]:
    """Collapse identical (ecosystem, name, version); keep the first source."""
    out: list[Component] = []
    seen: set[tuple[str, str, str]] = set()
    for c in sorted(comps, key=lambda c: (c.ecosystem, c.name.lower(), c.version, c.source)):
        key = c.key
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


def _rules(
    root: str,
    decls: list[Declaration],
    comps: list[Component],
    manifests,
    lockfiles,
    options: Options,
    result: ScanResult,
) -> list[Finding]:
    findings: list[Finding] = []

    def add(rule: str, detail: str, *, file: str = "", line: int = 0, evidence: str = "", component: str = "", sev: str | None = None) -> None:
        if rule in options.ignore:
            return
        findings.append(
            Finding(
                rule=rule,
                severity=_sev(rule, sev),
                title=RULES[rule][1],
                detail=detail,
                file=file,
                line=line,
                evidence=evidence,
                component=component,
            )
        )

    locked_by_eco: dict[str, dict[str, list[Component]]] = {}
    for c in comps:
        locked_by_eco.setdefault(c.ecosystem, {}).setdefault(_canon(c.name), []).append(c)
    locked_ecos = {e for e in locked_by_eco if locked_by_eco[e]}
    manifest_ecos = {e for _, e, _ in manifests}

    # ---- SBK001: manifest with no lockfile covering *that directory*.
    # A monorepo whose root has a lockfile still leaves sub-packages unpinned,
    # so this is resolved per directory (walking up to the scan root).
    lock_dirs: dict[str, set[str]] = {}
    for path, eco, _h in lockfiles:
        lock_dirs.setdefault(eco, set()).add(os.path.dirname(os.path.abspath(path)).lower())
    root_abs = os.path.abspath(root).lower()
    unlocked_manifests: set[str] = set()

    def _covered(path: str, eco: str) -> bool:
        probe = os.path.dirname(os.path.abspath(path)).lower()
        while True:
            if probe in lock_dirs.get(eco, set()):
                return True
            if probe == root_abs or os.path.dirname(probe) == probe:
                return False
            probe = os.path.dirname(probe)

    # Only the *runtime* tree has to be reproducible. `[build-system] requires`
    # is resolved by the build frontend and optional extras are not installed by
    # default, so neither is allowed to raise SBK001/SBK002 — otherwise every
    # Python project on earth gets a medium finding for `setuptools>=68`.
    manifests_with_runtime = {os.path.normcase(os.path.abspath(d.file)) for d in decls if d.kind == "runtime"}
    for path, eco, _h in manifests:
        key = os.path.normcase(os.path.abspath(path))
        if key not in manifests_with_runtime:
            continue
        if not _covered(path, eco):
            unlocked_manifests.add(key)
            add(
                "SBK001",
                f"ecosystem '{eco}' has a manifest here but no lockfile in this directory or any parent, "
                "so builds are not reproducible",
                file=path,
            )

    # ---- SBK002 / SBK011 / SBK006 / SBK014: per declaration
    declared_pairs: dict[str, set[str]] = {}
    for d in decls:
        declared_pairs.setdefault(d.ecosystem, set()).add(_canon(d.name))
        has_lock = os.path.normcase(os.path.abspath(d.file)) not in unlocked_manifests
        if "url-dep" in d.flags or "git-dep" in d.flags:
            add(
                "SBK006",
                f"{d.name} is required from {d.constraint} — that ref can move or be hijacked "
                "and bypasses registry review entirely",
                file=d.file,
                line=d.line,
                evidence=d.raw,
                component=d.name,
            )
        if "wildcard" in d.flags:
            add(
                "SBK011",
                f"{d.name} is declared as {d.constraint or '<empty>'} — every install may resolve differently",
                file=d.file,
                line=d.line,
                evidence=d.raw,
                component=d.name,
            )
        if "unpinned" in d.flags and not has_lock and d.kind == "runtime":
            add(
                "SBK002",
                f"{d.name} {d.constraint} is an open range and nothing pins it",
                file=d.file,
                line=d.line,
                evidence=d.raw,
                component=d.name,
            )

    # ---- SBK015: lockfile ecosystems with no manifest
    for eco in sorted({e for _, e, _ in lockfiles} - manifest_ecos):
        sample = next((p for p, e, _ in lockfiles if e == eco), "")
        add("SBK015", f"lockfile for '{eco}' exists but no manifest declares it — likely stale", file=sample)

    # ---- SBK003 / SBK005: declarations vs lock
    for d in decls:
        if d.kind == "build":
            continue
        entries = locked_by_eco.get(d.ecosystem, {}).get(_canon(d.name))
        if not entries:
            if d.ecosystem in locked_ecos:
                add(
                    "SBK003",
                    f"{d.name} ({d.constraint}) is declared in the manifest but never appears in the lockfile",
                    file=d.file,
                    line=d.line,
                    evidence=d.raw,
                    component=d.name,
                )
            continue
        for c in entries:
            if not d.constraint or "@" in d.constraint or "wildcard" in d.flags:
                continue
            ok = versions.satisfies(d.ecosystem, d.constraint, c.version)
            if ok is False:
                add(
                    "SBK005",
                    f"{d.name} is locked at {c.version}, which does not satisfy the declared '{d.constraint}'",
                    file=c.source,
                    line=c.line,
                    evidence=c.evidence,
                    component=d.name,
                )

    # ---- SBK004: lock entries not declared anywhere
    for eco, table in locked_by_eco.items():
        declared = declared_pairs.get(eco, set())
        for canon, entries in table.items():
            if canon in declared:
                continue
            c = entries[0]
            add(
                "SBK004",
                f"{c.name}@{c.version} is pinned in the lockfile but no manifest declares it "
                "(transitive — review whether you actually want it)",
                file=c.source,
                line=c.line,
                evidence=c.evidence,
                component=c.name,
            )

    # ---- SBK010: several versions of one package
    for table in locked_by_eco.values():
        for entries in table.values():
            if len(entries) < 2:
                continue
            vers = sorted({e.version for e in entries})
            add(
                "SBK010",
                f"{entries[0].name} is locked at {len(vers)} versions ({', '.join(vers)}) — "
                "the one you import depends on hoisting order",
                file=entries[0].source,
                line=entries[0].line,
                evidence=entries[0].evidence,
                component=entries[0].name,
            )

    # ---- per-component: typosquat, license, pseudo-version
    for c in comps:
        hit = typosquat.is_suspicious(c.ecosystem, c.name)
        if hit:
            add(
                "SBK007",
                f"'{c.name}' looks like '{hit.lookalike}': {hit.reason}",
                file=c.source,
                line=c.line,
                evidence=c.evidence,
                component=c.name,
            )
        if c.ecosystem == "golang" and re.match(r"^v\d+\.\d+\.\d+-(0\.)?\d{14}-", c.version):
            add(
                "SBK016",
                f"{c.name} is pinned to pseudo-version {c.version} (a commit, not a release tag)",
                file=c.source,
                line=c.line,
                evidence=c.evidence,
                component=c.name,
            )
        if "installed metadata (conflicts" in (c.license_source or ""):
            add(
                "SBK012",
                f"{c.name}: lockfile and locally installed metadata disagree on the license "
                f"({c.license}) — trust neither until checked",
                file=c.source,
                line=c.line,
                evidence=c.evidence,
                component=c.name,
            )
        if not c.license:
            add(
                "SBK008",
                f"{c.name}@{c.version} has no resolvable license; a policy decision is impossible",
                file=c.source,
                line=c.line,
                evidence=c.evidence,
                component=c.name,
            )
            continue
        if c.license.startswith("LicenseRef"):
            add(
                "SBK017",
                f"{c.name}@{c.version} uses a custom license ({c.license}) that needs legal review",
                file=c.source,
                line=c.line,
                evidence=c.evidence,
                component=c.name,
            )
            continue
        decision = spdx.solve(c.license, options.policy)
        if decision.verdict == "deny":
            sev = "critical" if decision.category == lic.NETWORK_COPYLEFT else None
            add(
                "SBK009",
                f"{c.name}@{c.version} is {c.license} ({decision.reason})",
                file=c.source,
                line=c.line,
                evidence=c.evidence,
                component=c.name,
                sev=sev,
            )
        elif decision.verdict == "unknown":
            add(
                "SBK008",
                f"{c.name}@{c.version}: {decision.reason}",
                file=c.source,
                line=c.line,
                evidence=c.evidence,
                component=c.name,
            )

    # ---- SBK014: declared in runtime and elsewhere
    groups: dict[tuple[str, str], set[str]] = {}
    for d in decls:
        if d.kind == "build":
            continue
        groups.setdefault((d.ecosystem, _canon(d.name)), set()).add(d.kind)
    for (eco, canon), kinds in sorted(groups.items()):
        if "runtime" in kinds and len(kinds) > 1:
            name = next(d.name for d in decls if _canon(d.name) == canon and d.ecosystem == eco)
            others = sorted(kinds - {"runtime"})
            add(
                "SBK014",
                f"{name} is declared both as a runtime dependency and as {', '.join(others)}",
                file=root,
                component=name,
            )

    # ---- SBK013: non-official registry provenance (best effort from text)
    for path, _eco, _h in lockfiles:
        text = _read(path)
        if not text:
            continue
        for match in re.finditer(r"(?:registry|source|url|resolved)\"?\s*[:=]\s*\"?(https?://[^\"'\s,]+)", text):
            host = match.group(1)
            if any(official in host for official in ("pypi.org", "npmjs.org", "crates.io", "proxy.golang.org")):
                continue
            add("SBK013", f"lockfile resolves packages from a non-default registry: {host}", file=path, evidence=host)

    findings.sort(key=lambda f: (f.rule, f.file, f.line))
    return findings
