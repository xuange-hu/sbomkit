from sbomkit import demo
from sbomkit.scan import RULES, Options, scan_path


def test_demo_files_are_written(tmp_path):
    root = demo.write(str(tmp_path / "proj"))
    for rel in (
        "requirements.txt",
        "poetry.lock",
        "package.json",
        "package-lock.json",
        "Cargo.toml",
        "services/worker/Cargo.lock",
        "services/worker/go.sum",
        "services/api/pyproject.toml",
    ):
        assert (tmp_path / "proj" / rel).is_file(), rel
    assert root.endswith("proj") or "proj" in root


def test_demo_hits_every_rule(tmp_path):
    root = demo.write(str(tmp_path / "proj"))
    result = scan_path(root, Options())
    hit = {f.rule for f in result.findings}
    missing = {r for r in RULES if r not in hit}
    assert not missing, f"rules never demonstrated: {sorted(missing)}"


def test_demo_produces_components(tmp_path):
    root = demo.write(str(tmp_path / "proj"))
    result = scan_path(root, Options())
    assert len(result.components) >= 15


def test_demo_has_four_ecosystems(tmp_path):
    root = demo.write(str(tmp_path / "proj"))
    result = scan_path(root, Options())
    assert {c.ecosystem for c in result.components} == {"pypi", "npm", "golang", "cargo"}


def test_demo_dual_license_stays_allowed(tmp_path):
    root = demo.write(str(tmp_path / "proj"))
    result = scan_path(root, Options())
    dual = [c for c in result.components if c.name == "dual-ok"]
    assert dual and dual[0].license == "(MIT OR GPL-3.0-only)"
    assert not any(f.rule == "SBK009" and f.component == "dual-ok" for f in result.findings)


def test_demo_agpl_is_critical(tmp_path):
    root = demo.write(str(tmp_path / "proj"))
    result = scan_path(root, Options())
    agpl = [f for f in result.findings if f.component == "agpl-chart" and f.rule == "SBK009"]
    assert agpl and agpl[0].severity == "critical"


def test_demo_is_idempotent(tmp_path):
    first = scan_path(demo.write(str(tmp_path / "a")), Options())
    second = scan_path(demo.write(str(tmp_path / "a")), Options())
    assert len(first.components) == len(second.components)
    assert {f.rule for f in first.findings} == {f.rule for f in second.findings}


def test_demo_root_has_a_default():
    assert demo.demo_root().endswith("sbomkit-demo")
