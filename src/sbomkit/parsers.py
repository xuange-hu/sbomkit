"""Per-ecosystem manifest and lockfile readers.

Every reader returns declarations (what the manifest *asks for*) and
components (what the lockfile *pinned*), each carrying the file and line it
came from so a finding can quote the source.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .model import Component
from .tomlite import loads as toml_loads

# -------------------------------------------------------------------- shared


@dataclass
class Declaration:
    ecosystem: str
    name: str
    constraint: str
    file: str
    line: int
    raw: str = ""
    kind: str = "runtime"  # runtime | dev | optional | peer | build
    flags: list[str] = field(default_factory=list)

    @property
    def pinned(self) -> bool:
        return "unpinned" not in self.flags and "wildcard" not in self.flags


@dataclass
class ParseResult:
    components: list[Component] = field(default_factory=list)
    declarations: list[Declaration] = field(default_factory=list)


# ------------------------------------------------------------ spec heuristics

_URL_RE = re.compile(r"^\w+://|^(git|git\+ssh|git\+https|git\+file)@|^git\+")
_GIT_HOSTS = ("github.com/", "gitlab.com/", "bitbucket.org/", "gitea.")


def spec_flags(ecosystem: str, raw: str) -> list[str]:
    """Reproducibility / provenance problems visible in a version spec alone."""
    spec = (raw or "").strip()
    flags: list[str] = []
    if not spec or spec in ("*", "x", "X", "latest", "next", "any"):
        flags.append("wildcard")
    if spec.startswith("^") or spec.startswith("~") or spec.startswith(">") or spec.startswith("<"):
        flags.append("unpinned")
    if ecosystem == "npm" and spec.startswith(("workspace:", "file:", "link:", "portal:")):
        flags.append("local-ref")
    if ecosystem == "cargo" and spec and not spec.startswith(("=", "^", "~", ">", "<", "*")):
        # Cargo treats a bare `1.0` as `^1.0` — an open range, not a pin.
        flags.append("unpinned")
    if ecosystem == "pypi" and "@" in spec:
        flags.append("url-dep")
    if _URL_RE.search(spec) or any(h in spec for h in _GIT_HOSTS):
        flags.append("url-dep")
    if spec.startswith("git") or "git+" in spec:
        flags.append("git-dep")
    if re.search(r"://[^/]+/(?![^/]*\.(?:whl|tar\.gz|tgz|zip))", spec):
        flags.append("url-dep")
    return sorted(set(flags))


def _pypi_pinned(spec: str) -> bool:
    """PEP 440: an `==` clause with no wildcard is a pin."""
    for part in re.split(r"\s*,\s*", spec):
        part = part.strip()
        if not part:
            continue
        m = re.match(r"^(==|!=|>=|<=|~=|>|<)\s*(.+)$", part)
        if not m:
            return False
        if m.group(1) not in ("==", "==="):
            return False
        if "*" in m.group(2):
            return False
    return bool(spec.strip())


def _npm_pinned(spec: str) -> bool:
    s = spec.strip()
    if not s or s in ("*", "latest", "next", ""):
        return False
    if s.startswith(("^", "~", ">", "<", ">=", "<=")):
        return False
    return bool(re.fullmatch(r"\d+(\.\d+){0,3}(-[\w.\-+]+)?", s))


# -------------------------------------------------------------- requirements


_REQ_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9._-]+)\s*(?P<extras>\[[^\]]*\])?\s*(?P<spec>[^;#]*)?(?:;(?P<marker>.*))?$"
)


def parse_requirements(path: Path, text: str) -> ParseResult:
    """requirements.txt / constraints.txt / requirements/*.txt."""
    res = ParseResult()
    rel = str(path)
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #")[0].strip()
        if not line or line.startswith(("#", "-")):
            continue
        if "\\" in line:
            line = line.replace("\\", "").strip()
        m = _REQ_RE.match(line)
        if not m:
            continue
        name = m.group("name").strip()
        spec = (m.group("spec") or "").strip()
        flags = spec_flags("pypi", spec)
        if spec and _pypi_pinned(spec):
            flags = [f for f in flags if f != "unpinned"]
        res.declarations.append(
            Declaration(
                ecosystem="pypi",
                name=name,
                constraint=spec,
                file=rel,
                line=i,
                raw=raw.strip(),
                flags=flags,
            )
        )
    return res


# --------------------------------------------------------------- pyproject


def _split_requirement(text: str) -> tuple[str, str] | None:
    """PEP 508 requirement -> (name, specifier). Returns None for direct URLs."""
    text = text.strip().strip('"').strip("'")
    if not text:
        return None
    text = text.split(";", 1)[0].strip()  # drop environment markers
    if "@" in text:
        name = text.split("@", 1)[0].strip()
        return name, text.split("@", 1)[1].strip()
    m = re.match(r"^([A-Za-z0-9._-]+)\s*(\[[^\]]*\])?\s*(.*)$", text)
    if not m:
        return None
    return m.group(1), m.group(3).strip()


def parse_pyproject(path: Path, text: str) -> ParseResult:
    """PEP 621 [project] and Poetry [tool.poetry] dependency tables."""
    res = ParseResult()
    rel = str(path)
    try:
        doc = toml_loads(text)
    except Exception:  # noqa: BLE001 - a broken manifest is a finding, not a crash
        return res
    root = doc.value

    def add(name: str, spec: str, kind: str, key: str) -> None:
        flags = spec_flags("pypi", spec)
        if _pypi_pinned(spec):
            flags = [f for f in flags if f != "unpinned"]
        res.declarations.append(
            Declaration(
                ecosystem="pypi",
                name=name,
                constraint=spec,
                file=rel,
                line=doc.line(key),
                raw=f"{name} {spec}".strip(),
                kind=kind,
                flags=flags,
            )
        )

    project = root.get("project") or {}
    for key, kind in (("dependencies", "runtime"),):
        for item in project.get(key) or []:
            parsed = _split_requirement(item)
            if parsed:
                add(parsed[0], parsed[1], kind, f"project.{key}")
    for group, items in (project.get("optional-dependencies") or {}).items():
        for item in items:
            parsed = _split_requirement(item)
            if parsed:
                add(parsed[0], parsed[1], "optional", f"project.optional-dependencies.{group}")
    build = root.get("build-system") or {}
    for item in build.get("requires") or []:
        parsed = _split_requirement(item)
        if parsed:
            add(parsed[0], parsed[1], "build", "build-system.requires")

    poetry = ((root.get("tool") or {}).get("poetry") or {})
    for group in ("dependencies", "dev-dependencies", "group"):
        table = poetry.get(group)
        if not isinstance(table, dict):
            continue
        if group == "group":
            for subgroup, subtable in table.items():
                for name, spec in (subtable.get("dependencies") or {}).items():
                    if name == "python":
                        continue
                    add(name, spec if isinstance(spec, str) else str(spec), "dev", f"tool.poetry.group.{subgroup}")
            continue
        for name, spec in table.items():
            if name == "python":
                continue
            text_spec = spec if isinstance(spec, str) else (spec or {}).get("version", "*")
            add(name, str(text_spec), "dev" if group == "dev-dependencies" else "runtime", f"tool.poetry.{group}")
    return res


# ------------------------------------------------------------------ npm json


def _json_entry_lines(text: str) -> dict[str, int]:
    """Cheap line index for `"key": {` entries so JSON locks still get a line."""
    out: dict[str, int] = {}
    pattern = re.compile(r'^\s*"([^"]+)":\s*\{')
    for i, line in enumerate(text.splitlines(), 1):
        m = pattern.match(line)
        if m:
            out.setdefault(m.group(1), i)
    return out


def parse_package_json(path: Path, text: str) -> ParseResult:
    res = ParseResult()
    rel = str(path)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return res
    lines = _json_entry_lines(text)
    groups = (
        ("dependencies", "runtime"),
        ("devDependencies", "dev"),
        ("optionalDependencies", "optional"),
        ("peerDependencies", "peer"),
    )
    for key, kind in groups:
        table = data.get(key) or {}
        if not isinstance(table, dict):
            continue
        for name, spec in table.items():
            flags = spec_flags("npm", str(spec))
            if _npm_pinned(str(spec)):
                flags = [f for f in flags if f != "unpinned"]
            res.declarations.append(
                Declaration(
                    ecosystem="npm",
                    name=name,
                    constraint=str(spec),
                    file=rel,
                    line=lines.get(key, 0),
                    raw=f'"{name}": "{spec}"',
                    kind=kind,
                    flags=flags,
                )
            )
    return res


def _npm_name_from_path(key: str) -> str:
    """node_modules/a/node_modules/@scope/b -> @scope/b"""
    if "node_modules/" not in key:
        return key
    return key.rsplit("node_modules/", 1)[-1]


def parse_package_lock(path: Path, text: str) -> ParseResult:
    """package-lock.json v1 (dependencies) and v2/v3 (packages)."""
    res = ParseResult()
    rel = str(path)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return res
    lines = _json_entry_lines(text)

    packages = data.get("packages")
    if isinstance(packages, dict):
        root_pkg = packages.get("") or {}
        declared: set[str] = set()
        for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            declared.update((root_pkg.get(key) or {}).keys())
        for key, meta in packages.items():
            if not key or not isinstance(meta, dict):
                continue
            name = meta.get("name") or _npm_name_from_path(key)
            version = meta.get("version")
            if not name or not version:
                continue
            res.components.append(
                Component(
                    ecosystem="npm",
                    name=name,
                    version=str(version),
                    direct=name in declared or (meta.get("dev") is not True and not _npm_is_nested(key)),
                    license=meta.get("license") if isinstance(meta.get("license"), str) else None,
                    license_source="package-lock.json" if meta.get("license") else "",
                    source=rel,
                    line=lines.get(key, 0),
                    evidence=key,
                    locked=True,
                )
            )
        return res

    deps = data.get("dependencies")
    if isinstance(deps, dict):
        for name, meta in deps.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if not version:
                continue
            res.components.append(
                Component(
                    ecosystem="npm",
                    name=name,
                    version=str(version),
                    direct=meta.get("dev") is not True,
                    license=meta.get("license") if isinstance(meta.get("license"), str) else None,
                    license_source="package-lock.json" if meta.get("license") else "",
                    source=rel,
                    line=lines.get(name, 0),
                    evidence=name,
                    locked=True,
                )
            )
    return res


def _npm_is_nested(key: str) -> bool:
    return key.count("node_modules/") > 1


def parse_yarn_lock(path: Path, text: str) -> ParseResult:
    """yarn.lock v1 (the berry YAML dialect is not supported)."""
    res = ParseResult()
    rel = str(path)
    current: list[str] = []
    pending: dict[str, str] = {}
    block_line = 0

    def flush() -> None:
        if not current or not pending.get("version"):
            return
        for spec in current:
            name = spec.rsplit("@", 1)[0] if "@" in spec else spec
            res.components.append(
                Component(
                    ecosystem="npm",
                    name=name.strip('"'),
                    version=pending["version"],
                    direct=True,
                    source=rel,
                    line=block_line,
                    evidence=spec.strip(),
                    locked=True,
                )
            )

    for i, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw.startswith(" "):
            flush()
            current = [s.strip().strip('"') for s in raw.rstrip(":").split(",") if s.strip()]
            pending = {}
            block_line = i
            continue
        stripped = raw.strip()
        if stripped.startswith("version "):
            pending["version"] = stripped.split(" ", 1)[1].strip().strip('"')
    flush()  # the final block has no following header to trigger a flush
    return res


# ------------------------------------------------------------------- golang


def parse_go_mod(path: Path, text: str) -> ParseResult:
    res = ParseResult()
    rel = str(path)
    in_block = False
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split("//")[0].strip()
        if not line:
            continue
        if in_block:
            if line.startswith(")"):
                in_block = False
                continue
            parts = line.split()
            if parts:
                res.declarations.append(
                    Declaration(
                        ecosystem="golang",
                        name=parts[0],
                        constraint=parts[1] if len(parts) > 1 else "",
                        file=rel,
                        line=i,
                        raw=raw.strip(),
                        kind="dev" if "// indirect" in raw else "runtime",
                        flags=spec_flags("golang", parts[1] if len(parts) > 1 else ""),
                    )
                )
            continue
        if line.startswith("require ("):
            in_block = True
            continue
        if line.startswith("require "):
            parts = line.split()[1:]
            if parts:
                res.declarations.append(
                    Declaration(
                        ecosystem="golang",
                        name=parts[0],
                        constraint=parts[1] if len(parts) > 1 else "",
                        file=rel,
                        line=i,
                        raw=raw.strip(),
                        kind="dev" if "// indirect" in raw else "runtime",
                        flags=spec_flags("golang", parts[1] if len(parts) > 1 else ""),
                    )
                )
    return res


def parse_go_sum(path: Path, text: str) -> ParseResult:
    res = ParseResult()
    rel = str(path)
    seen: set[tuple[str, str]] = set()
    for i, raw in enumerate(text.splitlines(), 1):
        parts = raw.split()
        if len(parts) < 2:
            continue
        module, version = parts[0], parts[1]
        # go.sum carries two lines per module; the `/go.mod` variant is a hash
        # of the go.mod only and its version token is the one with the suffix.
        if module.endswith("/go.mod") or version.endswith("/go.mod"):
            continue
        key = (module, version)
        if key in seen:
            continue
        seen.add(key)
        res.components.append(
            Component(
                ecosystem="golang",
                name=module,
                version=version,
                direct=False,
                source=rel,
                line=i,
                evidence=raw.strip(),
                locked=True,
            )
        )
    return res


# -------------------------------------------------------------------- cargo


def parse_cargo_toml(path: Path, text: str) -> ParseResult:
    res = ParseResult()
    rel = str(path)
    try:
        doc = toml_loads(text)
    except Exception:  # noqa: BLE001
        return res
    root = doc.value
    for key, kind in (
        ("dependencies", "runtime"),
        ("dev-dependencies", "dev"),
        ("build-dependencies", "build"),
    ):
        table = root.get(key)
        if not isinstance(table, dict):
            continue
        for name, spec in table.items():
            text_spec = spec if isinstance(spec, str) else (spec or {}).get("version", "*")
            res.declarations.append(
                Declaration(
                    ecosystem="cargo",
                    name=name,
                    constraint=str(text_spec),
                    file=rel,
                    line=doc.line(f"{key}.{name}"),
                    raw=f"{name} = {spec!r}",
                    kind=kind,
                    flags=spec_flags("cargo", str(text_spec)),
                )
            )
    return res


def parse_cargo_lock(path: Path, text: str) -> ParseResult:
    res = ParseResult()
    rel = str(path)
    try:
        doc = toml_loads(text)
    except Exception:  # noqa: BLE001
        return res
    for idx, pkg in enumerate(doc.value.get("package") or []):
        name = pkg.get("name")
        version = pkg.get("version")
        if not name or not version:
            continue
        res.components.append(
            Component(
                ecosystem="cargo",
                name=str(name),
                version=str(version),
                direct=False,
                source=rel,
                line=doc.lines.get(f"package.{idx}.name", doc.lines.get("package", 0)),
                evidence=f"{name} {version}",
                locked=True,
            )
        )
    return res


def _parse_generic_toml_lock(path: Path, text: str, ecosystem: str) -> ParseResult:
    """poetry.lock and uv.lock share the [[package]] name/version shape."""
    res = ParseResult()
    rel = str(path)
    try:
        doc = toml_loads(text)
    except Exception:  # noqa: BLE001
        return res
    for idx, pkg in enumerate(doc.value.get("package") or []):
        name = pkg.get("name")
        version = pkg.get("version")
        if not name or not version:
            continue
        res.components.append(
            Component(
                ecosystem=ecosystem,
                name=str(name),
                version=str(version),
                direct=False,
                source=rel,
                line=doc.lines.get(f"package.{idx}.name", 0),
                evidence=f"{name} {version}",
                locked=True,
            )
        )
    return res


def parse_poetry_lock(path: Path, text: str) -> ParseResult:
    return _parse_generic_toml_lock(path, text, "pypi")


def parse_uv_lock(path: Path, text: str) -> ParseResult:
    return _parse_generic_toml_lock(path, text, "pypi")


# ------------------------------------------------------------------ registry

MANIFESTS: dict[str, tuple[str, object]] = {
    "requirements.txt": ("pypi", parse_requirements),
    "requirements-dev.txt": ("pypi", parse_requirements),
    "requirements-dev.lock": ("pypi", parse_requirements),
    "constraints.txt": ("pypi", parse_requirements),
    "pyproject.toml": ("pypi", parse_pyproject),
    "package.json": ("npm", parse_package_json),
    "go.mod": ("golang", parse_go_mod),
    "Cargo.toml": ("cargo", parse_cargo_toml),
}

LOCKFILES: dict[str, tuple[str, object]] = {
    "package-lock.json": ("npm", parse_package_lock),
    "npm-shrinkwrap.json": ("npm", parse_package_lock),
    "yarn.lock": ("npm", parse_yarn_lock),
    "Cargo.lock": ("cargo", parse_cargo_lock),
    "poetry.lock": ("pypi", parse_poetry_lock),
    "uv.lock": ("pypi", parse_uv_lock),
    "go.sum": ("golang", parse_go_sum),
}

# Directories that are dependencies of the project, not the project itself.
SKIP_DIRS = {
    "node_modules",
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    "target",
    ".tox",
    "site-packages",
    ".idea",
    ".vscode",
}
