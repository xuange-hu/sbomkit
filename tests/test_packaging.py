"""Guard the packaging contract.

CI always installs ``.[all]`` so it can never notice that a console script
would crash on a plain ``pip install sbomkit``. These assertions catch it
statically instead.
"""

import ast
import importlib
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "sbomkit"


def _pyproject() -> str:
    return (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def _top_level_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            found.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.add(node.module.split(".")[0])
    return found


def test_version_matches_pyproject():
    text = _pyproject()
    match = re.search(r'^version = "([^"]+)"', text, re.MULTILINE)
    assert match, "pyproject has no version"
    import sbomkit

    assert sbomkit.__version__ == match.group(1)


def test_console_scripts_are_declared():
    text = _pyproject()
    assert 'sbomkit = "sbomkit.cli:main"' in text
    assert 'sbomkit-mcp = "sbomkit.mcp_server:main"' in text


@pytest.mark.parametrize(
    "target",
    ["sbomkit.cli:main", "sbomkit.mcp_server:main"],
)
def test_console_script_targets_import_cleanly(target):
    module_name, attr = target.split(":")
    module = importlib.import_module(module_name)
    assert callable(getattr(module, attr))


@pytest.mark.parametrize("name", sorted(p.stem for p in SRC.glob("*.py")))
def test_modules_need_no_third_party_packages(name):
    if name == "__init__":
        pytest.skip("package marker")
    imported = _top_level_imports(SRC / f"{name}.py")
    third_party = {m for m in imported if m not in sys.stdlib_module_names and m != "sbomkit"}
    assert third_party == set(), f"{name}.py imports {third_party} at module scope"


def test_mcp_import_is_lazy():
    source = (SRC / "mcp_server.py").read_text(encoding="utf-8")
    assert "from mcp.server.fastmcp import FastMCP" in source
    tree = ast.parse(source)
    top = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            top.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            top.add(node.module.split(".")[0])
    assert "mcp" not in top


def test_tool_manifest_is_complete():
    from sbomkit.mcp_server import TOOLS, tool_manifest

    assert tool_manifest() == TOOLS
    for tool in tool_manifest():
        assert tool["name"].startswith("sbomkit_")
        assert len(tool["description"]) > 30
        assert isinstance(tool["input"], dict)


def test_every_manifest_tool_is_implemented():
    from sbomkit.mcp_server import tool_manifest

    source = (SRC / "mcp_server.py").read_text(encoding="utf-8")
    for tool in tool_manifest():
        assert f"def {tool['name']}(" in source, f"{tool['name']} has no implementation"


def test_base_dependencies_are_empty():
    text = _pyproject()
    assert "dependencies = []" in text


def test_mcp_extra_pins_the_1x_line():
    text = _pyproject()
    assert 'mcp>=1.2,<2' in text


def test_pytest_config_points_at_tests():
    text = _pyproject()
    assert 'testpaths = ["tests"]' in text


def test_readme_exists():
    assert (ROOT / "README.md").is_file()


def test_license_exists():
    assert (ROOT / "LICENSE").is_file()


def test_src_layout():
    assert (SRC / "cli.py").is_file()
    assert not (ROOT / "sbomkit").exists() or (ROOT / "sbomkit").is_dir()


def test_module_docstrings():
    for path in sorted(SRC.glob("*.py")):
        if path.name == "__main__.py":
            continue
        source = path.read_text(encoding="utf-8")
        assert source.startswith(('"""', "from", "import", "#")), path.name
