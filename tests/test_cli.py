import json

from sbomkit import cli


def test_scan_human_output(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    code = cli.main(["scan", str(tmp_path), "--no-color"])
    out = capsys.readouterr().out
    assert code == 0
    assert "sbomkit" in out and "SBK001" in out


def test_scan_json_output(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    cli.main(["scan", str(tmp_path), "--json", "--no-color"])
    payload = json.loads(capsys.readouterr().out)
    assert "findings" in payload and "components" in payload


def test_scan_sarif_output(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    cli.main(["scan", str(tmp_path), "--sarif", "--no-color"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["version"] == "2.1.0"


def test_scan_missing_path_is_exit_two(tmp_path, capsys):
    code = cli.main(["scan", str(tmp_path / "nope"), "--no-color"])
    assert code == 2


def test_fail_on_triggers_exit_one(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    assert cli.main(["scan", str(tmp_path), "--fail-on", "medium", "--no-color"]) == 1
    capsys.readouterr()


def test_fail_on_high_is_zero_when_only_medium(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    assert cli.main(["scan", str(tmp_path), "--fail-on", "high", "--no-color"]) == 0
    capsys.readouterr()


def test_fail_on_none_never_fails(tmp_path, capsys):
    """`none` is the report-only gate: findings exist, the exit code stays 0."""
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    # the same input exits 1 at medium, so there is something to suppress
    assert cli.main(["scan", str(tmp_path), "--fail-on", "none", "--no-color"]) == 0
    capsys.readouterr()


def test_ignore_rule_via_cli(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    cli.main(["scan", str(tmp_path), "--ignore", "SBK001", "--json", "--no-color"])
    payload = json.loads(capsys.readouterr().out)
    assert all(f["rule"] != "SBK001" for f in payload["findings"])


def test_sbom_cyclonedx_to_stdout(tmp_path, capsys):
    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "requests"\nversion = "2.31.0"\n', encoding="utf-8")
    cli.main(["sbom", str(tmp_path), "--no-color"])
    assert json.loads(capsys.readouterr().out)["bomFormat"] == "CycloneDX"


def test_sbom_spdx_to_file(tmp_path, capsys):
    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "requests"\nversion = "2.31.0"\n', encoding="utf-8")
    out = tmp_path / "bom.spdx"
    cli.main(["sbom", str(tmp_path), "--format", "spdx", "-o", str(out), "--no-color"])
    assert "SPDXVersion" in out.read_text(encoding="utf-8")
    capsys.readouterr()


def test_diff_identical_is_exit_zero(tmp_path, capsys):
    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "requests"\nversion = "2.31.0"\n', encoding="utf-8")
    bom = tmp_path / "bom.json"
    cli.main(["sbom", str(tmp_path), "-o", str(bom), "--no-color"])
    capsys.readouterr()
    assert cli.main(["diff", str(bom), str(bom), "--no-color"]) == 0
    assert "no change" in capsys.readouterr().out


def test_diff_with_changes(tmp_path, capsys):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [
                    {"name": "a", "version": "2.0.0", "purl": "pkg:pypi/a@2.0.0", "licenses": [{"expression": "MIT"}]}
                ],
            }
        ),
        encoding="utf-8",
    )
    new.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [
                    {"name": "a", "version": "1.0.0", "purl": "pkg:pypi/a@1.0.0", "licenses": [{"expression": "MIT"}]}
                ],
            }
        ),
        encoding="utf-8",
    )
    cli.main(["diff", str(old), str(new), "--no-color"])
    assert "downgraded" in capsys.readouterr().out


def test_diff_fail_on(tmp_path, capsys):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}), encoding="utf-8")
    new.write_text(
        json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "a", "version": "1.0.0", "purl": "pkg:pypi/a@1.0.0"}]}),
        encoding="utf-8",
    )
    assert cli.main(["diff", str(old), str(new), "--fail-on", "low", "--no-color"]) == 1
    capsys.readouterr()


def test_diff_bad_input_is_exit_two(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"hello": 1}), encoding="utf-8")
    code = cli.main(["diff", str(bad), str(bad), "--no-color"])
    assert code == 2
    capsys.readouterr()


def test_licenses_explain(tmp_path, capsys):
    code = cli.main(["licenses", "(MIT OR GPL-3.0-only)", "--no-color"])
    out = capsys.readouterr().out
    assert code == 0
    assert "OR (any one)" in out and "ALLOW" in out


def test_licenses_bad_expression(tmp_path, capsys):
    code = cli.main(["licenses", "MIT AND (", "--no-color"])
    assert code == 2
    capsys.readouterr()


def test_licenses_without_expression(tmp_path, capsys):
    code = cli.main(["licenses", "--no-color"])
    assert code == 2
    capsys.readouterr()


def test_licenses_list(tmp_path, capsys):
    cli.main(["licenses", "--list", "--no-color"])
    out = capsys.readouterr().out
    assert "closed-source" in out and "MIT" in out


def test_rules_listing(capsys):
    code = cli.main(["rules", "--no-color"])
    out = capsys.readouterr().out
    assert code == 0 and "SBK001" in out


def test_rules_json(capsys):
    cli.main(["rules", "--json", "--no-color"])
    payload = json.loads(capsys.readouterr().out)
    assert "SBK001" in payload and "severity" in payload["SBK001"]


def test_check_lists_mcp_tools(capsys):
    code = cli.main(["check", "--no-color"])
    out = capsys.readouterr().out
    assert code == 0 and "sbomkit_scan" in out


def test_demo_runs_and_reports_coverage(tmp_path, capsys):
    code = cli.main(["demo", "--dir", str(tmp_path / "demo"), "--no-color"])
    out = capsys.readouterr().out
    assert code == 0
    assert "rule coverage" in out


def test_version_flag(capsys):
    try:
        cli.main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    capsys.readouterr()


def test_no_subcommand_exits(capsys):
    try:
        cli.main([])
    except SystemExit as exc:
        assert exc.code == 2
    capsys.readouterr()


def test_license_map_file(tmp_path, capsys):
    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "internal"\nversion = "1.0.0"\n', encoding="utf-8")
    mapping = tmp_path / "map.json"
    mapping.write_text(json.dumps({"internal": "MIT"}), encoding="utf-8")
    cli.main(["scan", str(tmp_path), "--license-map", str(mapping), "--json", "--no-color"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["components"][0]["license"] == "MIT"


def test_no_evidence_hides_source_lines(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    cli.main(["scan", str(tmp_path), "--no-evidence", "--no-color"])
    assert "|" not in capsys.readouterr().out.split("SBK001")[0]


def test_policy_flag_is_accepted(tmp_path, capsys):
    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "python-can"\nversion = "4.3.0"\n', encoding="utf-8")
    cli.main(["scan", str(tmp_path), "--policy", "weak-ok", "--json", "--no-color"])
    payload = json.loads(capsys.readouterr().out)
    assert all(f["rule"] != "SBK009" for f in payload["findings"])


def test_render_scan_on_empty_result(capsys):
    from sbomkit.model import ScanResult

    text = cli.render_scan(ScanResult(root="."))
    assert "no findings" in text
