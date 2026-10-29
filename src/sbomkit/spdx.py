"""SPDX license-expression parser and policy solver.

Most SBOM tooling treats a license field as an opaque string. That is wrong:
real manifests carry expressions such as

    (MIT OR Apache-2.0)
    Apache-2.0 WITH LLVM-exception
    MIT AND (BSD-3-Clause OR ISC)
    GPL-2.0-or-later

and the answer to "may I ship this?" depends on the *structure*. Under ``OR``
you are entitled to pick the friendliest branch; under ``AND`` you inherit the
strictest branch. A tool that string-matches "GPL" anywhere in the field will
reject ``(MIT OR GPL-3.0-only)``, which is a false positive that blocks a
perfectly fine dependency.

This module parses the expression properly and then solves it against a
distribution policy. Grammar (SPDX 2.x/3.x subset, ``AND`` binds tighter than
``OR``)::

    expr     := or_expr
    or_expr  := and_expr (OR  and_expr)*
    and_expr := atom     (AND atom)*
    atom     := '(' expr ')' | id ['+'] [WITH id]
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from . import licenses as lic

# -------------------------------------------------------------------- errors


class LicenseParseError(ValueError):
    """Raised when a license expression cannot be parsed."""


# ----------------------------------------------------------------- tokenizer

_TOKEN_RE = re.compile(
    r"""\s*(?:
        (?P<lpar>\()
      | (?P<rpar>\))
      | (?P<plus>\+)
      | (?P<op>OR|AND|WITH)
      | (?P<id>[A-Za-z0-9][A-Za-z0-9.\-]*)
    )""",
    re.VERBOSE | re.IGNORECASE,
)


@dataclass(frozen=True)
class _Tok:
    kind: str
    value: str


def tokenize(expr: str) -> list[_Tok]:
    out: list[_Tok] = []
    pos = 0
    while pos < len(expr):
        if expr[pos].isspace():
            pos += 1
            continue
        m = _TOKEN_RE.match(expr, pos)
        if not m or m.end() == pos:
            raise LicenseParseError(f"unexpected character {expr[pos]!r} at offset {pos} in {expr!r}")
        for kind in ("lpar", "rpar", "plus", "op", "id"):
            text = m.group(kind)
            if text is not None:
                break
        out.append(_Tok(kind, text))
        pos = m.end()
    return out


# ----------------------------------------------------------------------- AST


@dataclass(frozen=True)
class Leaf:
    ident: str
    plus: bool = False
    exception: str | None = None

    @property
    def text(self) -> str:
        s = self.ident + ("+" if self.plus else "")
        if self.exception:
            s += f" WITH {self.exception}"
        return s

    def children(self) -> tuple:
        return ()


@dataclass(frozen=True)
class And:
    parts: tuple

    @property
    def text(self) -> str:
        return " AND ".join(p.text if isinstance(p, Leaf) else f"({p.text})" for p in self.parts)

    def children(self) -> tuple:
        return self.parts


@dataclass(frozen=True)
class Or:
    parts: tuple

    @property
    def text(self) -> str:
        return " OR ".join(p.text for p in self.parts)

    def children(self) -> tuple:
        return self.parts


Node = Leaf | And | Or


class _Parser:
    def __init__(self, tokens: list[_Tok]) -> None:
        self.toks = tokens
        self.i = 0

    def peek(self) -> _Tok | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def next(self) -> _Tok | None:
        tok = self.peek()
        if tok is not None:
            self.i += 1
        return tok

    def parse(self) -> Node:
        node = self.parse_or()
        if self.peek() is not None:
            tok = self.peek()
            raise LicenseParseError(f"trailing token {tok.value!r} in expression")
        return node

    def parse_or(self) -> Node:
        parts = [self.parse_and()]
        while True:
            tok = self.peek()
            if tok is None or tok.kind != "op" or tok.value.upper() != "OR":
                break
            self.next()
            parts.append(self.parse_and())
        return parts[0] if len(parts) == 1 else Or(tuple(parts))

    def parse_and(self) -> Node:
        parts = [self.parse_atom()]
        while True:
            tok = self.peek()
            if tok is None:
                break
            if tok.kind == "op" and tok.value.upper() == "AND":
                self.next()
                parts.append(self.parse_atom())
                continue
            # SPDX allows a bare juxtaposition inside parentheses only; we
            # treat an unexpected identifier as a syntax error rather than
            # silently concatenating.
            break
        return parts[0] if len(parts) == 1 else And(tuple(parts))

    def parse_atom(self) -> Node:
        tok = self.next()
        if tok is None:
            raise LicenseParseError("unexpected end of expression")
        if tok.kind == "lpar":
            inner = self.parse_or()
            closing = self.next()
            if closing is None or closing.kind != "rpar":
                raise LicenseParseError("unbalanced parenthesis in license expression")
            return inner
        if tok.kind == "id":
            ident = tok.value
            plus = False
            exception = None
            nxt = self.peek()
            if nxt is not None and nxt.kind == "plus":
                self.next()
                plus = True
                nxt = self.peek()
            if nxt is not None and nxt.kind == "op" and nxt.value.upper() == "WITH":
                self.next()
                exc = self.next()
                if exc is None or exc.kind != "id":
                    raise LicenseParseError("WITH must be followed by an exception id")
                exception = exc.value
            ident = lic.normalize(ident) or ident
            return Leaf(ident, plus, exception)
        raise LicenseParseError(f"unexpected token {tok.value!r}")


def parse(expr: str) -> Node:
    """Parse a license expression into an AST. Raises LicenseParseError."""
    text = (expr or "").strip()
    if not text:
        raise LicenseParseError("empty license expression")
    return _Parser(tokenize(text)).parse()


def renders(node: Node) -> str:
    return node.text


# ---------------------------------------------------------------- evaluation


@dataclass
class Decision:
    """Result of solving an expression against a policy."""

    verdict: str  # allow | deny | unknown
    chosen: str  # the branch we would take (for OR), else the whole expr
    category: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {
            "verdict": self.verdict,
            "chosen": self.chosen,
            "category": self.category,
            "reason": self.reason,
        }


def _leaf_category(leaf: Leaf) -> str:
    # A "+" suffix means "or later", which never relaxes the copyleft class.
    return lic.category(leaf.ident)


def ids(node: Node) -> list[str]:
    """Every license id mentioned, in source order, depth-first."""
    out: list[str] = []
    if isinstance(node, Leaf):
        out.append(node.ident)
        if node.exception:
            out.append(node.exception)
    else:
        for part in node.children():  # type: ignore[attr-defined]
            out.extend(ids(part))  # type: ignore[arg-type]
    return out


def evaluate(node: Node, policy: str = "closed-source") -> Decision:
    """Solve `node` against a distribution policy.

    OR  -> pick the least-restrictive *allowed* branch (entitlement to choose).
    AND -> every branch must be allowed; risk is the worst branch.
    """
    if isinstance(node, Leaf):
        cat = _leaf_category(node)
        if cat == lic.UNKNOWN:
            return Decision("unknown", node.text, cat, "license class could not be determined")
        if lic.policy_allows(policy, cat):
            return Decision("allow", node.text, cat, f"{lic.CATEGORY_LABEL[cat]} is allowed under '{policy}'")
        return Decision(
            "deny",
            node.text,
            cat,
            f"{lic.CATEGORY_LABEL[cat]} is not allowed under '{policy}' ({lic.POLICY_NOTE[policy]})",
        )

    if isinstance(node, Or):
        results = [evaluate(p, policy) for p in node.parts]  # type: ignore[attr-defined]
        allowed = [r for r in results if r.verdict == "allow"]
        if allowed:
            best = min(allowed, key=lambda r: lic.CATEGORY_ORDER.get(r.category, 99))
            return Decision(
                "allow",
                best.chosen,
                best.category,
                f"OR-expression: taking the friendliest permitted branch ({best.chosen})",
            )
        unknown = [r for r in results if r.verdict == "unknown"]
        if unknown:
            return Decision("unknown", unknown[0].chosen, lic.UNKNOWN, "OR-expression: no branch is resolvable")
        worst = max(results, key=lambda r: lic.CATEGORY_ORDER.get(r.category, 0))
        return Decision("deny", worst.chosen, worst.category, f"OR-expression: every branch is denied ({worst.reason})")

    results = [evaluate(p, policy) for p in node.parts]  # type: ignore[attr-defined]
    flat: list[Decision] = []
    for r in results:
        flat.append(r)
    if any(r.verdict == "deny" for r in flat):
        worst = max(flat, key=lambda r: lic.CATEGORY_ORDER.get(r.category, 0))
        return Decision("deny", node.text, worst.category, f"AND-expression: blocked by {worst.chosen} ({worst.reason})")
    if any(r.verdict == "unknown" for r in flat):
        return Decision("unknown", node.text, lic.UNKNOWN, "AND-expression: at least one branch is unresolvable")
    worst = max(flat, key=lambda r: lic.CATEGORY_ORDER.get(r.category, 0))
    return Decision("allow", node.text, worst.category, f"AND-expression: all branches permitted (strictest is {worst.chosen})")


def solve(expr: str, policy: str = "closed-source") -> Decision:
    """Parse + evaluate in one call. Unparseable input yields an unknown verdict."""
    try:
        node = parse(expr)
    except LicenseParseError as exc:
        return Decision("unknown", expr or "", lic.UNKNOWN, f"unparseable expression: {exc}")
    return evaluate(node, policy)


def explain(expr: str) -> str:
    """Human-readable breakdown, used by `sbomkit licenses --explain`."""

    def walk(node: Node, depth: int) -> list[str]:
        pad = "  " * depth
        if isinstance(node, Leaf):
            cat = _leaf_category(node)
            extra = " [+or-later]" if node.plus else ""
            exc = f" with {node.exception}" if node.exception else ""
            return [f"{pad}{node.ident}{extra}{exc} -> {lic.CATEGORY_LABEL[cat]}"]
        label = "OR (any one)" if isinstance(node, Or) else "AND (all)"
        lines = [f"{pad}{label}"]
        for part in node.children():  # type: ignore[attr-defined]
            lines.extend(walk(part, depth + 1))  # type: ignore[arg-type]
        return lines

    return "\n".join(walk(parse(expr), 0))
