import json
from pathlib import Path

from sbomkit.model import Component
from sbomkit.scan import Options, scan_path


def _rules_of(result):
    return {f.rule for f in result.findings}


def _write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# ------------------------------------------------------------------ basics


def test_empty_directory_is_clean(tmp_path):
    result = scan_path(str(tmp_path), Options())
    assert result.components == []
    assert result.findings == []
    assert result.risk == 0


def test_missing_path_returns_nothing(tmp_path):
    result = scan_path(str(tmp_path / "nope"), Options())
    assert result.files == []


def test_single_file_target(tmp_path):
    _write(tmp_path, "requirements.txt", "requests==2.31.0\n")
    result = scan_path(str(tmp_path / "requirements.txt"), Options())
    assert result.components == []
    assert "SBK001" in _rules_of(result)


def test_manifest_without_lock_is_reported(tmp_path):
    _write(tmp_path, "requirements.txt", "requests==2.31.0\n")
    result = scan_path(str(tmp_path), Options())
    assert "SBK001" in _rules_of(result)


def test_lockfile_silences_sb001(tmp_path):
    _write(tmp_path, "requirements.txt", "requests==2.31.0\n")
    _write(tmp_path, "poetry.lock", '[[package]]\nname = "requests"\nversion = "2.31.0"\n')
    result = scan_path(str(tmp_path), Options())
    assert "SBK001" not in _rules_of(result)


def test_root_lock_covers_subdirectory_manifests(tmp_path):
    _write(tmp_path, "poetry.lock", '[[package]]\nname = "requests"\nversion = "2.31.0"\n')
    _write(tmp_path, "svc/api/requirements.txt", "requests==2.31.0\n")
    result = scan_path(str(tmp_path), Options())
    assert "SBK001" not in _rules_of(result)


def test_lock_in_a_sibling_directory_does_not_cover_the_root(tmp_path):
    _write(tmp_path, "Cargo.toml", '[dependencies]\nserde = "1.0"\n')
    _write(tmp_path, "svc/worker/Cargo.lock", '[[package]]\nname = "serde"\nversion = "1.0.190"\n')
    result = scan_path(str(tmp_path), Options())
    assert "SBK001" in _rules_of(result)


# ------------------------------------------------------------------ drift


def test_declared_but_not_locked(tmp_path):
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"left-pad": "1.3.0"}}))
    _write(tmp_path, "package-lock.json", json.dumps({"packages": {"": {}, "node_modules/x": {"version": "1.0.0"}}}))
    result = scan_path(str(tmp_path), Options())
    assert "SBK003" in _rules_of(result)


def test_locked_outside_constraint(tmp_path):
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"axios": ">=1.0.0"}}))
    _write(
        tmp_path,
        "package-lock.json",
        json.dumps({"packages": {"": {"dependencies": {"axios": ">=1.0.0"}}, "node_modules/axios": {"version": "0.27.2"}}}),
    )
    result = scan_path(str(tmp_path), Options())
    assert "SBK005" in _rules_of(result)


def test_matching_version_is_not_reported(tmp_path):
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"axios": ">=1.0.0"}}))
    _write(
        tmp_path,
        "package-lock.json",
        json.dumps({"packages": {"": {"dependencies": {"axios": ">=1.0.0"}}, "node_modules/axios": {"version": "1.5.0"}}}),
    )
    result = scan_path(str(tmp_path), Options())
    assert "SBK005" not in _rules_of(result)


def test_transitive_is_informational(tmp_path):
    _write(tmp_path, "package.json", json.dumps({"dependencies": {}}))
    _write(tmp_path, "package-lock.json", json.dumps({"packages": {"": {}, "node_modules/deep": {"version": "1.0.0"}}}))
    result = scan_path(str(tmp_path), Options())
    assert "SBK004" in _rules_of(result)


def test_multiple_versions(tmp_path):
    _write(
        tmp_path,
        "package-lock.json",
        json.dumps(
            {
                "packages": {
                    "": {},
                    "node_modules/dup": {"version": "1.0.0"},
                    "node_modules/a/node_modules/dup": {"version": "2.0.0"},
                }
            }
        ),
    )
    result = scan_path(str(tmp_path), Options())
    assert "SBK010" in _rules_of(result)


# ----------------------------------------------------------------- licenses


def test_unknown_license_is_medium(tmp_path):
    _write(tmp_path, "poetry.lock", '[[package]]\nname = "who-knows-this"\nversion = "1.0.0"\n')
    result = scan_path(str(tmp_path), Options())
    assert "SBK008" in _rules_of(result)


def test_bundled_table_resolves_license(tmp_path):
    _write(tmp_path, "poetry.lock", '[[package]]\nname = "requests"\nversion = "2.31.0"\n')
    result = scan_path(str(tmp_path), Options())
    assert result.components[0].license == "Apache-2.0"
    assert result.components[0].license_source == "bundled table"


def test_copyleft_is_denied_under_closed_source(tmp_path):
    _write(tmp_path, "poetry.lock", '[[package]]\nname = "python-can"\nversion = "4.3.0"\n')
    result = scan_path(str(tmp_path), Options(policy="closed-source"))
    assert "SBK009" in _rules_of(result)


def test_weak_copyleft_allowed_under_weak_ok(tmp_path):
    _write(tmp_path, "poetry.lock", '[[package]]\nname = "python-can"\nversion = "4.3.0"\n')
    result = scan_path(str(tmp_path), Options(policy="weak-ok"))
    assert "SBK009" not in _rules_of(result)


def test_dual_license_is_not_denied(tmp_path):
    _write(
        tmp_path,
        "package-lock.json",
        json.dumps({"packages": {"": {}, "node_modules/dual": {"version": "1.0.0", "license": "(MIT OR GPL-3.0-only)"}}}),
    )
    result = scan_path(str(tmp_path), Options())
    assert "SBK009" not in _rules_of(result)


def test_licenseref_is_flagged(tmp_path):
    _write(
        tmp_path,
        "package-lock.json",
        json.dumps({"packages": {"": {}, "node_modules/sdk": {"version": "1.0.0", "license": "LicenseRef-proprietary"}}}),
    )
    result = scan_path(str(tmp_path), Options())
    assert "SBK017" in _rules_of(result)


def test_license_map_overrides_everything(tmp_path):
    _write(tmp_path, "poetry.lock", '[[package]]\nname = "internal"\nversion = "1.0.0"\n')
    result = scan_path(str(tmp_path), Options(license_map={"pypi": {"internal": "GPL-3.0-only"}}))
    assert result.components[0].license == "GPL-3.0-only"
    assert "SBK009" in _rules_of(result)


def test_license_map_flat_form(tmp_path):
    _write(tmp_path, "poetry.lock", '[[package]]\nname = "internal"\nversion = "1.0.0"\n')
    result = scan_path(str(tmp_path), Options(license_map={"internal": "MIT"}))
    assert result.components[0].license == "MIT"


def test_installed_metadata_conflict(tmp_path):
    _write(
        tmp_path,
        "package-lock.json",
        json.dumps({"packages": {"": {}, "node_modules/drift": {"version": "1.0.0", "license": "MIT"}}}),
    )
    _write(tmp_path, "node_modules/drift/package.json", json.dumps({"name": "drift", "license": "GPL-3.0-only"}))
    result = scan_path(str(tmp_path), Options())
    assert "SBK012" in _rules_of(result)
    assert result.components[0].license == "GPL-3.0-only"


def test_installed_metadata_used_when_lock_silent(tmp_path):
    _write(tmp_path, "poetry.lock", '[[package]]\nname = "mystery"\nversion = "1.0.0"\n')
    meta = "Metadata-Version: 2.1\nName: mystery\nLicense: BSD-3-Clause\n"
    _write(tmp_path, ".venv/Lib/site-packages/mystery-1.0.0.dist-info/METADATA", meta)
    result = scan_path(str(tmp_path), Options())
    assert result.components[0].license == "BSD-3-Clause"
    assert result.components[0].license_source == "installed metadata"


# ------------------------------------------------------------- provenance


def test_url_dependency_is_critical(tmp_path):
    _write(tmp_path, "requirements.txt", "tooling @ git+https://github.com/a/b.git\n")
    result = scan_path(str(tmp_path), Options())
    assert "SBK006" in _rules_of(result)


def test_typosquat_is_high(tmp_path):
    _write(tmp_path, "poetry.lock", '[[package]]\nname = "reqeusts"\nversion = "2.31.0"\n')
    result = scan_path(str(tmp_path), Options())
    assert "SBK007" in _rules_of(result)


def test_non_official_registry(tmp_path):
    _write(
        tmp_path,
        "package-lock.json",
        json.dumps(
            {
                "packages": {
                    "": {},
                    "node_modules/m": {
                        "version": "1.0.0",
                        "resolved": "https://npm.internal.corp/m/-/m-1.0.0.tgz",
                    },
                }
            }
        ),
    )
    result = scan_path(str(tmp_path), Options())
    assert "SBK013" in _rules_of(result)


def test_orphan_lockfile(tmp_path):
    _write(tmp_path, "go.sum", "github.com/a/b v1.0.0 h1:aaa=\n")
    result = scan_path(str(tmp_path), Options())
    assert "SBK015" in _rules_of(result)


def test_go_pseudo_version(tmp_path):
    _write(tmp_path, "go.sum", "github.com/a/b v0.0.0-20240115120000-abcdefabcdef h1:aaa=\n")
    result = scan_path(str(tmp_path), Options())
    assert "SBK016" in _rules_of(result)


def test_runtime_and_dev_overlap(tmp_path):
    text = "[dependencies]\nserde = \"1.0\"\n\n[dev-dependencies]\nserde = \"1.0\"\n"
    _write(tmp_path, "Cargo.toml", text)
    _write(tmp_path, "Cargo.lock", '[[package]]\nname = "serde"\nversion = "1.0.190"\n')
    result = scan_path(str(tmp_path), Options())
    assert "SBK014" in _rules_of(result)


# ----------------------------------------------------------------- options


def test_ignore_suppresses_a_rule(tmp_path):
    _write(tmp_path, "requirements.txt", "requests==2.31.0\n")
    result = scan_path(str(tmp_path), Options(ignore={"SBK001"}))
    assert "SBK001" not in _rules_of(result)


def test_no_dev_drops_dev_declarations(tmp_path):
    text = '[project]\ndependencies = ["requests==2.31.0"]\n\n[project.optional-dependencies]\ntest = ["pytest==7"]\n'
    _write(tmp_path, "pyproject.toml", text)
    _write(tmp_path, "poetry.lock", '[[package]]\nname = "requests"\nversion = "2.31.0"\n')
    everything = scan_path(str(tmp_path), Options())
    runtime_only = scan_path(str(tmp_path), Options(include_dev=False))
    assert len(runtime_only.findings) <= len(everything.findings)
    assert "SBK003" in _rules_of(everything)
    assert "SBK003" not in _rules_of(runtime_only)


def test_risk_score_is_capped():
    from sbomkit.model import Finding, ScanResult

    result = ScanResult(root=".")
    result.findings = [Finding(rule="X", severity="critical", title="t", detail="d") for _ in range(20)]
    assert result.risk == 100


def test_build_system_requires_never_raises_reproducibility_rules(tmp_path):
    # every Python project declares setuptools in [build-system]; treating that
    # as an unpinned runtime requirement floods the report
    text = '[build-system]\nrequires = ["setuptools>=68", "wheel"]\n'
    _write(tmp_path, "pyproject.toml", text)
    result = scan_path(str(tmp_path), Options())
    assert not _rules_of(result) & {"SBK001", "SBK002", "SBK003"}


def test_optional_extras_alone_do_not_demand_a_lockfile(tmp_path):
    text = '[project.optional-dependencies]\nmcp = ["mcp>=1.2,<2"]\n'
    _write(tmp_path, "pyproject.toml", text)
    result = scan_path(str(tmp_path), Options())
    assert "SBK001" not in _rules_of(result)


def test_runtime_requirements_still_raise(tmp_path):
    text = '[project]\ndependencies = ["requests>=2.0"]\n'
    _write(tmp_path, "pyproject.toml", text)
    result = scan_path(str(tmp_path), Options())
    assert {"SBK001", "SBK002"} <= _rules_of(result)


def test_self_scan_is_clean():
    """The repository must not report on itself — a noisy self-scan is a smell."""
    import sbomkit

    root = Path(sbomkit.__file__).resolve().parents[2]
    result = scan_path(str(root), Options())
    assert [f"{f.rule} {f.component}" for f in result.findings] == []


def test_components_carry_evidence(tmp_path):
    _write(tmp_path, "poetry.lock", '[[package]]\nname = "requests"\nversion = "2.31.0"\n')
    result = scan_path(str(tmp_path), Options())
    comp = result.components[0]
    assert comp.line >= 1
    assert "poetry.lock" in comp.source


def test_direct_flag_follows_declarations(tmp_path):
    _write(tmp_path, "requirements.txt", "requests==2.31.0\n")
    _write(
        tmp_path,
        "poetry.lock",
        '[[package]]\nname = "requests"\nversion = "2.31.0"\n\n[[package]]\nname = "urllib3"\nversion = "2.0.0"\n',
    )
    result = scan_path(str(tmp_path), Options())
    flags = {c.name: c.direct for c in result.components}
    assert flags == {"requests": True, "urllib3": False}


def test_dedupe_identical_entries(tmp_path):
    _write(tmp_path, "poetry.lock", '[[package]]\nname = "requests"\nversion = "2.31.0"\n')
    _write(tmp_path, "uv.lock", '[[package]]\nname = "requests"\nversion = "2.31.0"\n')
    result = scan_path(str(tmp_path), Options())
    assert len(result.components) == 1


def test_purl_generation():
    assert Component(ecosystem="pypi", name="Requests", version="1.0").purl == "pkg:pypi/Requests@1.0"
    assert Component(ecosystem="npm", name="@scope/pkg", version="1.0").purl == "pkg:npm/@scope/pkg@1.0"
    assert Component(ecosystem="golang", name="github.com/a/b", version="v1").purl == "pkg:golang/github.com/a/b@v1"


def test_node_modules_is_not_scanned_for_manifests(tmp_path):
    _write(tmp_path, "node_modules/thing/package.json", json.dumps({"name": "thing", "version": "1.0.0"}))
    result = scan_path(str(tmp_path), Options())
    assert result.files == []


def test_findings_sorted_by_rule(tmp_path):
    _write(tmp_path, "requirements.txt", "requests==2.31.0\n")
    result = scan_path(str(tmp_path), Options())
    rules = [f.rule for f in result.findings]
    assert rules == sorted(rules)


def test_result_to_dict_shape(tmp_path):
    _write(tmp_path, "requirements.txt", "requests==2.31.0\n")
    payload = scan_path(str(tmp_path), Options()).to_dict()
    for key in ("root", "files", "counts", "risk", "components", "findings", "licenses_resolved"):
        assert key in payload

def test_wildcard_version_specifier(tmp_path):
    _write(tmp_path, "package.json", '{"dependencies": {"lodash": "*"}}')
    result = scan_path(str(tmp_path), Options())
    assert "SBK011" in _rules_of(result)


def test_pinned_version_is_not_a_wildcard(tmp_path):
    _write(tmp_path, "package.json", '{"dependencies": {"lodash": "4.17.21"}}')
    result = scan_path(str(tmp_path), Options())
    assert "SBK011" not in _rules_of(result)
