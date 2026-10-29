"""Version comparison and constraint satisfaction, per ecosystem.

Ecosystems disagree about what a bare version means and what ``~=`` / ``^``
mean, so sharing one comparator produces wrong answers:

* PyPI: bare ``requests`` means "any"; ``~=1.4.2`` means ``>=1.4.2, ==1.4.*``.
* npm:  ``^1.2.3`` is ``>=1.2.3 <2.0.0`` but ``^0.2.3`` is ``>=0.2.3 <0.3.0``.
* cargo: a bare ``1.2.3`` is treated exactly like ``^1.2.3``.
* Go:   versions are ``vX.Y.Z`` (or pseudo-versions) and are exact.

``satisfies`` returns ``None`` when it cannot decide; callers must then stay
quiet rather than emit a finding.
"""

from __future__ import annotations

import re

_NUM = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def parse(text: str) -> tuple[int, ...]:
    """Loose numeric tuple. Prerelease/build suffixes are dropped."""
    s = (text or "").strip().lstrip("v=")
    s = re.split(r"[-+]", s, maxsplit=1)[0]
    if not s:
        return ()
    m = _NUM.match(s)
    if not m:
        return ()
    return tuple(int(g) if g else 0 for g in m.groups())


def _pad(t: tuple[int, ...], n: int = 3) -> tuple[int, ...]:
    return tuple(list(t) + [0] * (n - len(t)))[:n]


def compare(a: str, b: str) -> int:
    ta, tb = _pad(parse(a)), _pad(parse(b))
    return (ta > tb) - (ta < tb)


def _upper_caret(ver: str) -> str | None:
    parts = _pad(parse(ver))
    major, minor, _patch = parts
    if major > 0:
        return f"{major + 1}.0.0"
    if minor > 0:
        return f"0.{minor + 1}.0"
    return f"0.0.{parts[2] + 1}"


def _specified_components(ver: str) -> int:
    """How many components the author actually wrote ('1.4' -> 2, '1' -> 1)."""
    return len([p for p in ver.strip().split(".") if p != ""])


def _upper_tilde(ver: str) -> str | None:
    parts = _pad(parse(ver))
    digits = _specified_components(ver)
    if digits >= 2:
        return f"{parts[0]}.{parts[1] + 1}.0"
    return f"{parts[0] + 1}.0.0"


def _upper_compatible(ver: str) -> str | None:
    """PEP 440 ``~=``: drop the last specified component."""
    raw = (ver or "").strip()
    digits = _specified_components(raw)
    parts = _pad(parse(raw))
    if digits >= 3:
        return f"{parts[0]}.{parts[1] + 1}.0"
    if digits == 2:
        return f"{parts[0] + 1}.0.0"
    return None


def _clause(ecosystem: str, clause: str, version: str) -> bool | None:
    clause = clause.strip()
    if not clause:
        return None
    if ecosystem == "pypi":
        m = re.match(r"^(==|!=|>=|<=|~=|>|<|===)\s*(.+)$", clause)
        if not m:
            return None
        op, operand = m.group(1), m.group(2).strip()
        if "*" in operand:
            prefix = operand.rstrip(".*")
            if op in ("==", "==="):
                return version == prefix or version.startswith(prefix + ".")
            if op == "!=":
                return not version.startswith(prefix + ".")
            return None
        if op == "==":
            return compare(version, operand) == 0
        if op == "!=":
            return compare(version, operand) != 0
        if op == ">=":
            return compare(version, operand) >= 0
        if op == "<=":
            return compare(version, operand) <= 0
        if op == ">":
            return compare(version, operand) > 0
        if op == "<":
            return compare(version, operand) < 0
        if op == "~=":
            upper = _upper_compatible(operand)
            if upper is None:
                return None
            return compare(version, operand) >= 0 and compare(version, upper) < 0
        return None

    if ecosystem in ("npm", "cargo"):
        m = re.match(r"^(\^|~|>=|<=|>|<|=)?\s*(.+)$", clause)
        if not m:
            return None
        op, operand = m.group(1) or "", m.group(2).strip()
        if op == "^":
            upper = _upper_caret(operand)
            return compare(version, operand) >= 0 and compare(version, upper) < 0
        if op == "~":
            upper = _upper_tilde(operand)
            return compare(version, operand) >= 0 and compare(version, upper) < 0
        if op == ">=":
            return compare(version, operand) >= 0
        if op == "<=":
            return compare(version, operand) <= 0
        if op == ">":
            return compare(version, operand) > 0
        if op == "<":
            return compare(version, operand) < 0
        if op == "=":
            return compare(version, operand) == 0
        # bare version: == for npm, ^ for cargo
        if ecosystem == "cargo":
            upper = _upper_caret(operand)
            return compare(version, operand) >= 0 and compare(version, upper) < 0
        return compare(version, operand) == 0

    if ecosystem == "golang":
        return compare(version, clause) == 0
    return None


def satisfies(ecosystem: str, constraint: str, version: str) -> bool | None:
    """Does `version` meet `constraint`? None when undecidable."""
    if not constraint or not version:
        return None
    text = constraint.strip()
    if "@" in text or "://" in text or text.startswith("git"):
        return None  # URL / VCS requirement: version comparison is meaningless
    results: list[bool | None] = []
    for group in text.split("||"):
        group = group.strip()
        if not group:
            continue
        clauses = [c for c in re.split(r"[,\s]+", group) if c.strip()] if ecosystem == "pypi" else [
            c for c in re.split(r"\s+(?=[\^~><=]|\d)", group) if c.strip()
        ]
        if not clauses:
            clauses = [group]
        verdicts = [_clause(ecosystem, c, version) for c in clauses]
        if any(v is None for v in verdicts):
            results.append(None)
            continue
        results.append(all(bool(v) for v in verdicts))
    if not results:
        return None
    if any(v is None for v in results):
        return None
    return any(bool(v) for v in results)
