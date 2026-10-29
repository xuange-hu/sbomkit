"""Typosquat detection against the bundled popular-package list.

Registry rules differ per ecosystem, and getting them wrong produces noise:

* PyPI and crates.io *normalise* ``-``, ``_`` and ``.`` in a name, so
  ``python-dotenv`` and ``python.dotenv`` are the same package. A separator-only
  difference is therefore NOT a typosquat there.
* npm and Go do not normalise, so ``cross-env`` vs ``cross_env`` are two
  different packages that a human cannot tell apart at a glance. That IS worth
  reporting.
"""

from __future__ import annotations

from dataclasses import dataclass

from .known import all_known_names

NORMALISES_SEPARATORS = {"pypi", "cargo"}

# Visual confusions that a human reviewer cannot see in a terminal.
HOMOGLYPHS = {
    "0": "o",
    "1": "l",
    "i": "l",
    "l": "i",
    "5": "s",
    "$": "s",
    "3": "e",
    "@": "a",
}


@dataclass
class Typosquat:
    name: str  # the suspicious name as declared
    lookalike: str  # the popular name it resembles
    reason: str
    distance: int

    def to_dict(self) -> dict[str, str | int]:
        return {
            "name": self.name,
            "lookalike": self.lookalike,
            "reason": self.reason,
            "distance": self.distance,
        }


def canonical(name: str) -> str:
    """Lower-case, separator-folded form used for comparisons."""
    out = name.strip().lower()
    for ch in ("-", "_", "."):
        out = out.replace(ch, "-")
    return out


def _fold_homoglyphs(text: str) -> str:
    return "".join(HOMOGLYPHS.get(c, c) for c in text)


def levenshtein(a: str, b: str, limit: int = 3) -> int:
    """Bounded edit distance. Returns ``limit + 1`` for 'too far'."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        worst = i
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            val = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            cur.append(val)
            if val < worst:
                worst = val
        if worst > limit:
            return limit + 1
        prev = cur
    dist = prev[-1]
    return dist if dist <= limit else limit + 1


def _transposition(a: str, b: str) -> bool:
    """Single adjacent-character swap, e.g. 'reqeusts' vs 'requests'."""
    if len(a) != len(b) or a == b:
        return False
    diffs = [i for i in range(len(a)) if a[i] != b[i]]
    if len(diffs) != 2:
        return False
    i, j = diffs
    return j == i + 1 and a[i] == b[j] and a[j] == b[i]


def _decoy_prefix(name: str, lookalike: str) -> str | None:
    """``python-requests`` / ``node-express`` style impersonation."""
    for prefix in ("python-", "py-", "node-", "npm-", "go-", "rust-", "official-", "the-real-"):
        if name.startswith(prefix) and name[len(prefix) :] == lookalike:
            return f"impersonation prefix {prefix!r} on {lookalike!r}"
    for suffix in ("-py", "-python", "-js", "-node", "-official", "-lib", "-pkg"):
        if name.endswith(suffix) and name[: -len(suffix)] == lookalike:
            return f"impersonation suffix {suffix!r} on {lookalike!r}"
    return None


def check(ecosystem: str, name: str) -> list[Typosquat]:
    """Return every plausible lookalike for `name` (usually zero)."""
    if not name:
        return []
    target = canonical(name)
    folded = _fold_homoglyphs(target)
    fold_sep = ecosystem in NORMALISES_SEPARATORS
    out: list[Typosquat] = []
    seen: set[str] = set()

    for popular in all_known_names(ecosystem):
        ref = canonical(popular)
        if ref == target or popular.lower() == name.lower():
            continue  # it *is* the real package

        hit: tuple[str, int] | None = None

        if not fold_sep and ref.replace("-", "") == target.replace("-", ""):
            hit = (f"differs from {popular!r} only by separator characters", 0)
        elif _fold_homoglyphs(ref) == folded:
            hit = (f"{popular!r} after homoglyph folding (0/o, 1/l/i, 5/s)", 0)
        else:
            dist = levenshtein(target, ref, limit=2)
            if dist == 1:
                hit = (f"one edit away from {popular!r}", 1)
            elif dist == 2 and len(ref) >= 8:
                hit = (f"two edits away from {popular!r}", 2)
            elif _transposition(target, ref):
                hit = (f"{popular!r} with two characters swapped", 1)

        if hit is None:
            decoy = _decoy_prefix(target, ref)
            if decoy:
                hit = (decoy, 0)

        if hit and popular.lower() not in seen:
            seen.add(popular.lower())
            out.append(Typosquat(name=name, lookalike=popular, reason=hit[0], distance=hit[1]))

    out.sort(key=lambda t: (t.distance, t.lookalike))
    return out


def is_suspicious(ecosystem: str, name: str) -> Typosquat | None:
    hits = check(ecosystem, name)
    return hits[0] if hits else None
