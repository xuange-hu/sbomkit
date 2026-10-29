"""A small TOML reader with line numbers.

Python 3.11 ships ``tomllib``; this project targets 3.10+ and, more
importantly, needs the *line number* of every value so findings can point at
the exact line in the lockfile (the evidence-style contract every tool in this
family follows). tomllib gives values but no positions, so we read it
ourselves.

Supported subset: tables, arrays of tables, dotted keys, inline tables,
arrays (single and multi-line), basic/literal/multiline strings, integers,
floats, booleans, comments. That covers every manifest and lockfile format we
parse. Anything else raises ``TomlError`` instead of silently returning None.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class TomlError(ValueError):
    """Raised on TOML this reader does not understand."""


@dataclass
class Doc:
    value: dict = field(default_factory=dict)
    lines: dict[str, int] = field(default_factory=dict)  # dotted path -> 1-based line

    def line(self, path: str, default: int = 0) -> int:
        return self.lines.get(path, default)


# ------------------------------------------------------------------ scanning


def _scan(chunk: str, depth: int = 0, triple: str | None = None) -> tuple[int, str | None]:
    """Track bracket depth and triple-quote state across a chunk."""
    i = 0
    n = len(chunk)
    while i < n:
        c = chunk[i]
        if triple is not None:
            if chunk.startswith(triple, i):
                triple = None
                i += 3
                continue
            i += 1
            continue
        if c in "\"'":
            if chunk.startswith(c * 3, i):
                triple = c * 3
                i += 3
                continue
            j = i + 1
            while j < n and chunk[j] != c:
                if c == '"' and chunk[j] == "\\":
                    j += 2
                    continue
                j += 1
            if j >= n:
                # unterminated single-line string: keep it, the caller decides
                i = n
                continue
            i = j + 1
            continue
        if c in "[{":
            depth += 1
        elif c in "]}":
            depth -= 1
        i += 1
    return depth, triple


def _strip_comment(line: str) -> str:
    """Remove a trailing ``#`` comment that is outside any string."""
    out = []
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if c in "\"'":
            if line.startswith(c * 3, i):
                end = line.find(c * 3, i + 3)
                end = n if end < 0 else end + 3
                out.append(line[i:end])
                i = end
                continue
            j = i + 1
            while j < n and line[j] != c:
                if c == '"' and line[j] == "\\":
                    j += 2
                    continue
                j += 1
            out.append(line[i : min(j + 1, n)])
            i = j + 1
            continue
        if c == "#":
            break
        out.append(c)
        i += 1
    return "".join(out)


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Join continuation lines so every entry is one complete statement."""
    out: list[tuple[int, str]] = []
    buf = ""
    start = 0
    depth = 0
    triple: str | None = None
    for idx, raw in enumerate(text.splitlines(), 1):
        chunk = raw if triple is not None else _strip_comment(raw)
        if not buf and not chunk.strip():
            continue
        if not buf:
            start = idx
        buf = f"{buf}\n{chunk}" if buf else chunk
        depth, triple = _scan(buf, 0, None)
        if triple is None and depth <= 0:
            stripped = buf.strip()
            if stripped:
                out.append((start, stripped))
            buf = ""
            depth = 0
    if buf.strip():
        out.append((start, buf.strip()))
    return out


# ------------------------------------------------------------------- values


def _split_top_level(text: str, sep: str = ",") -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    triple: str | None = None
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if triple is not None:
            if text.startswith(triple, i):
                buf.append(triple)
                triple = None
                i += 3
                continue
            buf.append(c)
            i += 1
            continue
        if c in "\"'":
            if text.startswith(c * 3, i):
                triple = c * 3
                buf.append(triple)
                i += 3
                continue
            buf.append(c)
            j = i + 1
            while j < n and text[j] != c:
                if c == '"' and text[j] == "\\":
                    buf.append(text[j : j + 2])
                    j += 2
                    continue
                buf.append(text[j])
                j += 1
            buf.append(c)
            i = j + 1
            continue
        if c in "[{(":
            depth += 1
        elif c in "]})":
            depth -= 1
        if c == sep and depth == 0:
            parts.append("".join(buf).strip())
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def _unescape(text: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            out.append({"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "/": "/"}.get(nxt, nxt))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _parse_string(text: str) -> str:
    text = text.strip()
    if text.startswith('"""') or text.startswith("'''"):
        marker = text[:3]
        body = text[3:-3] if text.endswith(marker) else text[3:]
        if body.startswith("\n"):
            body = body[1:]
        return body if marker == "'''" else _unescape(body)
    if len(text) >= 2 and text[0] in "\"'" and text[-1] == text[0]:
        body = text[1:-1]
        return body if text[0] == "'" else _unescape(body)
    raise TomlError(f"not a string: {text!r}")


def _parse_value(text: str):
    text = text.strip()
    if not text:
        raise TomlError("empty value")
    if text[0] in "\"'":
        return _parse_string(text)
    if text.startswith("["):
        if not text.endswith("]"):
            raise TomlError(f"unterminated array: {text!r}")
        inner = text[1:-1].strip()
        if not inner:
            return []
        return [_parse_value(p) for p in _split_top_level(inner) if p.strip()]
    if text.startswith("{"):
        if not text.endswith("}"):
            raise TomlError(f"unterminated inline table: {text!r}")
        inner = text[1:-1].strip()
        out: dict = {}
        for part in _split_top_level(inner):
            if not part.strip():
                continue
            key, _, val = part.partition("=")
            if not _:
                raise TomlError(f"inline table entry without '=': {part!r}")
            _assign(out, key.strip(), val.strip())
        return out
    low = text.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    try:
        return int(text.replace("_", ""))
    except ValueError:
        pass
    try:
        return float(text.replace("_", ""))
    except ValueError:
        pass
    raise TomlError(f"unsupported TOML value: {text!r}")


def _split_key(text: str) -> list[str]:
    """Split a (possibly dotted / quoted) key into parts."""
    parts: list[str] = []
    buf: list[str] = []
    quoted = False
    i = 0
    while i < len(text):
        c = text[i]
        if c in "\"'":
            j = i + 1
            while j < len(text) and text[j] != c:
                j += 1
            buf.append(text[i + 1 : j])
            quoted = True
            i = j + 1
            continue
        if c == "." and not quoted:
            parts.append("".join(buf).strip())
            buf = []
            quoted = False
            i += 1
            continue
        buf.append(c)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return [p for p in parts if p]


def _assign(target: dict, key: str, value_text: str) -> None:
    parts = _split_key(key)
    if not parts:
        raise TomlError(f"empty key in {key!r}")
    node = target
    for part in parts[:-1]:
        nxt = node.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            node[part] = nxt
        node = nxt
    node[parts[-1]] = _parse_value(value_text)


# ------------------------------------------------------------------ document


def loads(text: str) -> Doc:
    doc = Doc()
    root = doc.value
    # The container for subsequent key/value lines is tracked directly rather
    # than re-resolved from the path each time: re-resolution cannot tell
    # an array-of-tables index from a table key and overwrites the list.
    current: dict = root
    path: list[str] = []
    for lineno, stmt in _logical_lines(text):
        if stmt.startswith("["):
            header = stmt[1:].strip()
            is_aot = header.startswith("[")
            if is_aot:
                header = header[1:].strip()
            if not header.endswith("]"):
                raise TomlError(f"unterminated table header: {stmt!r}")
            header = header[:-1].strip()
            if is_aot:
                if not header.endswith("]"):
                    raise TomlError(f"unterminated array-of-tables header: {stmt!r}")
                header = header[:-1].strip()
            parts = _split_key(header)
            if not parts:
                raise TomlError(f"empty table header: {stmt!r}")
            node = root
            for part in parts[:-1]:
                nxt = node.get(part)
                if not isinstance(nxt, dict):
                    nxt = {}
                    node[part] = nxt
                node = nxt
            last = parts[-1]
            if is_aot:
                bucket = node.get(last)
                if not isinstance(bucket, list):
                    bucket = []
                    node[last] = bucket
                current = {}
                bucket.append(current)
                path = list(parts) + [str(len(bucket) - 1)]
            else:
                target = node.get(last)
                if not isinstance(target, dict):
                    target = {}
                    node[last] = target
                current = target
                path = list(parts)
            doc.lines[".".join(parts)] = lineno
            continue

        key, sep, val = stmt.partition("=")
        if not sep:
            raise TomlError(f"statement without '=': {stmt!r}")
        _assign(current, key.strip(), val.strip())
        doc.lines[".".join(path + _split_key(key.strip()))] = lineno
    return doc


def load(path: str) -> Doc:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return loads(fh.read())
