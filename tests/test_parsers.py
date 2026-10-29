import json
from pathlib import Path

from sbomkit import parsers
from sbomkit.scan import _handler_for


def _parse(fn, text, name="x"):
    return fn(Path(name), text)


# ------------------------------------------------------------- requirements


def test_requirements_basic():
    res = _parse(parsers.parse_requirements, "requests==2.31.0\nflask>=2.0\n")
    assert [(d.name, d.constraint) for d in res.declarations] == [("requests", "==2.31.0"), ("flask", ">=2.0")]


def test_requirements_line_numbers():
    res = _parse(parsers.parse_requirements, "# comment\nrequests==1.0\n\nflask==2.0\n")
    assert [d.line for d in res.declarations] == [2, 4]


def test_requirements_skips_options_and_comments():
    res = _parse(parsers.parse_requirements, "-r base.txt\n# note\n--index-url https://x\n")
    assert res.declarations == []


def test_requirements_url_dependency_flagged():
    res = _parse(parsers.parse_requirements, "tooling @ git+https://github.com/a/b.git\n")
    decl = res.declarations[0]
    assert decl.name == "tooling"
    assert "url-dep" in decl.flags


def test_requirements_environment_marker_is_ignored():
    res = _parse(parsers.parse_requirements, 'tomli==2.0 ; python_version < "3.11"\n')
    assert res.declarations[0].name == "tomli"


def test_requirements_extras_are_stripped():
    res = _parse(parsers.parse_requirements, "uvicorn[standard]==0.24.0\n")
    assert res.declarations[0].name == "uvicorn"


def test_requirements_pinned_flag():
    res = _parse(parsers.parse_requirements, "requests==2.31.0\nflask>=2.0\n")
    assert res.declarations[0].pinned is True
    assert res.declarations[1].pinned is False


# ---------------------------------------------------------------- pyproject


def test_pyproject_pep621():
    text = '[project]\nname = "x"\ndependencies = [\n  "requests>=2.0",\n  "flask==3.0",\n]\n'
    res = _parse(parsers.parse_pyproject, text)
    assert {d.name for d in res.declarations} == {"requests", "flask"}


def test_pyproject_line_numbers_point_at_the_requirement():
    text = '[project]\ndependencies = [\n  "requests>=2.0",\n]\n'
    res = _parse(parsers.parse_pyproject, text)
    assert res.declarations[0].line >= 1


def test_pyproject_optional_dependencies():
    text = '[project.optional-dependencies]\ntest = ["pytest==7.0"]\n'
    res = _parse(parsers.parse_pyproject, text)
    assert res.declarations[0].kind == "optional"


def test_pyproject_build_requires():
    text = '[build-system]\nrequires = ["setuptools>=68", "wheel"]\n'
    res = _parse(parsers.parse_pyproject, text)
    assert {d.kind for d in res.declarations} == {"build"}


def test_pyproject_poetry_style():
    text = '[tool.poetry.dependencies]\nflask = "^2.0"\n\n[tool.poetry.dev-dependencies]\npytest = "^7"\n'
    res = _parse(parsers.parse_pyproject, text)
    kinds = {d.name: d.kind for d in res.declarations}
    assert kinds == {"flask": "runtime", "pytest": "dev"}


def test_pyproject_poetry_table_form():
    text = '[tool.poetry.dependencies]\nflask = { version = "^2.0", optional = true }\n'
    res = _parse(parsers.parse_pyproject, text)
    assert res.declarations[0].constraint == "^2.0"


def test_pyproject_skips_python_entry():
    text = '[tool.poetry.dependencies]\npython = "^3.10"\n'
    assert _parse(parsers.parse_pyproject, text).declarations == []


def test_pyproject_broken_toml_does_not_raise():
    assert _parse(parsers.parse_pyproject, "[project\ndependencies = [").declarations == []


# --------------------------------------------------------------------- npm


def test_package_json_groups():
    text = json.dumps(
        {
            "dependencies": {"express": "^4.18.0"},
            "devDependencies": {"jest": "^29"},
            "optionalDependencies": {"fsevents": "^2"},
            "peerDependencies": {"react": "^18"},
        }
    )
    res = _parse(parsers.parse_package_json, text)
    assert {d.kind for d in res.declarations} == {"runtime", "dev", "optional", "peer"}


def test_package_json_pinned_detection():
    text = json.dumps({"dependencies": {"a": "1.2.3", "b": "^1.2.3", "c": "*"}})
    res = _parse(parsers.parse_package_json, text)
    flags = {d.name: d.flags for d in res.declarations}
    assert flags["a"] == []
    assert "unpinned" in flags["b"]
    assert "wildcard" in flags["c"]


def test_package_json_invalid_json():
    assert _parse(parsers.parse_package_json, "{not json").declarations == []


def test_package_lock_v3_packages():
    text = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"express": "^4"}},
                "node_modules/express": {"version": "4.18.2", "license": "MIT"},
                "node_modules/a/node_modules/left-pad": {"version": "1.3.0"},
            },
        }
    )
    res = _parse(parsers.parse_package_lock, text)
    names = {c.name for c in res.components}
    assert names == {"express", "left-pad"}
    assert all(c.locked for c in res.components)


def test_package_lock_v3_nested_name_extraction():
    text = json.dumps({"packages": {"node_modules/@scope/pkg": {"version": "1.0.0"}}})
    res = _parse(parsers.parse_package_lock, text)
    assert res.components[0].name == "@scope/pkg"


def test_package_lock_v1_dependencies():
    text = json.dumps({"dependencies": {"express": {"version": "4.18.2", "license": "MIT"}}})
    res = _parse(parsers.parse_package_lock, text)
    assert res.components[0].name == "express"
    assert res.components[0].license == "MIT"


def test_package_lock_line_numbers():
    text = json.dumps(
        {"packages": {"": {}, "node_modules/express": {"version": "1.0.0"}}},
        indent=2,
    )
    res = _parse(parsers.parse_package_lock, text)
    assert res.components[0].line >= 1


def test_yarn_lock_v1():
    text = '# yarn lockfile v1\n\nexpress@^4.18.0:\n  version "4.18.2"\n  resolved "https://r/x"\n'
    res = _parse(parsers.parse_yarn_lock, text)
    assert res.components[0].name == "express"
    assert res.components[0].version == "4.18.2"


def test_yarn_lock_scoped_and_multi_spec():
    text = '"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.22.0"\n'
    res = _parse(parsers.parse_yarn_lock, text)
    assert res.components[0].name == "@babel/core"


# ------------------------------------------------------------------ golang


def test_go_mod_single_require():
    res = _parse(parsers.parse_go_mod, "module x\n\ngo 1.21\n\nrequire github.com/a/b v1.2.3\n")
    assert res.declarations[0].name == "github.com/a/b"
    assert res.declarations[0].constraint == "v1.2.3"


def test_go_mod_require_block():
    text = "module x\n\nrequire (\n\tgithub.com/a/b v1.0.0\n\tgithub.com/c/d v2.0.0 // indirect\n)\n"
    res = _parse(parsers.parse_go_mod, text)
    assert len(res.declarations) == 2
    assert res.declarations[1].kind == "dev"


def test_go_sum_skips_gomod_lines():
    text = "github.com/a/b v1.0.0 h1:aaa=\ngithub.com/a/b v1.0.0/go.mod h1:bbb=\n"
    res = _parse(parsers.parse_go_sum, text)
    assert len(res.components) == 1
    assert res.components[0].version == "v1.0.0"


def test_go_sum_deduplicates():
    text = "github.com/a/b v1.0.0 h1:aaa=\ngithub.com/a/b v1.0.0 h1:ccc=\n"
    assert len(_parse(parsers.parse_go_sum, text).components) == 1


# ------------------------------------------------------------------- cargo


def test_cargo_toml_groups():
    text = '[dependencies]\nserde = "1.0"\n\n[dev-dependencies]\nserde = "1.0"\n\n[build-dependencies]\ncc = "1"\n'
    res = _parse(parsers.parse_cargo_toml, text)
    assert {d.kind for d in res.declarations} == {"runtime", "dev", "build"}


def test_cargo_toml_bare_version_is_unpinned():
    res = _parse(parsers.parse_cargo_toml, '[dependencies]\nserde = "1.0"\n')
    assert "unpinned" in res.declarations[0].flags


def test_cargo_toml_table_spec():
    text = '[dependencies]\nserde = { version = "1.0", features = ["derive"] }\n'
    assert _parse(parsers.parse_cargo_toml, text).declarations[0].constraint == "1.0"


def test_cargo_lock():
    text = 'version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.190"\n'
    res = _parse(parsers.parse_cargo_lock, text)
    assert res.components[0].name == "serde"
    assert res.components[0].ecosystem == "cargo"


def test_poetry_lock_uses_pypi_ecosystem():
    text = '[[package]]\nname = "requests"\nversion = "2.31.0"\n'
    res = _parse(parsers.parse_poetry_lock, text)
    assert res.components[0].ecosystem == "pypi"


def test_uv_lock_uses_pypi_ecosystem():
    text = '[[package]]\nname = "anyio"\nversion = "4.0.0"\n'
    assert _parse(parsers.parse_uv_lock, text).components[0].ecosystem == "pypi"


# ---------------------------------------------------------------- registry


def test_registry_has_four_ecosystems():
    ecos = {v[0] for v in parsers.MANIFESTS.values()} | {v[0] for v in parsers.LOCKFILES.values()}
    assert ecos == {"pypi", "npm", "golang", "cargo"}


def test_handler_for_named_requirements_files():
    hit = _handler_for("requirements-dev.txt", is_lock=False)
    assert hit is not None and hit[0] == "pypi"


def test_handler_returns_none_for_unknown():
    assert _handler_for("README.md", is_lock=False) is None


def test_skip_dirs_contains_the_usual_hiders():
    for name in ("node_modules", ".venv", "site-packages", "target"):
        assert name in parsers.SKIP_DIRS


def test_spec_flags_npm_workspace():
    assert "local-ref" in parsers.spec_flags("npm", "workspace:*")


def test_spec_flags_empty_is_wildcard():
    assert "wildcard" in parsers.spec_flags("npm", "")
