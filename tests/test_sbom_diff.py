import json

from sbomkit import diff as diffmod
from sbomkit import sarif as sarifmod
from sbomkit import sbom as sbommod
from sbomkit.model import Component, ScanResult
from sbomkit.scan import Options, scan_path

_LOCK = '[[package]]\nname = "requests"\nversion = "2.31.0"\n\n[[package]]\nname = "flask"\nversion = "3.0.0"\n'


def _result(tmp_path):
    (tmp_path / "poetry.lock").write_text(_LOCK, encoding="utf-8")
    return scan_path(str(tmp_path), Options())


# ------------------------------------------------------------------ cyclonedx


def test_cyclonedx_envelope(tmp_path):
    doc = sbommod.cyclonedx(_result(tmp_path), "demo")
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert len(doc["components"]) == 2


def test_cyclonedx_component_shape(tmp_path):
    doc = sbommod.cyclonedx(_result(tmp_path), "demo")
    comp = next(c for c in doc["components"] if c["name"] == "requests")
    assert comp["type"] == "library"
    assert comp["purl"].startswith("pkg:pypi/")
    assert comp["licenses"][0]["expression"] == "Apache-2.0"
    names = {p["name"] for p in comp["properties"]}
    assert "sbomkit:direct" in names and "sbomkit:source" in names


def test_cyclonedx_marks_unknown_license(tmp_path):
    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "mystery"\nversion = "1.0.0"\n', encoding="utf-8")
    doc = sbommod.cyclonedx(scan_path(str(tmp_path), Options()), "demo")
    assert doc["components"][0]["licenses"][0]["license"]["name"] == "NOASSERTION"


def test_cyclonedx_metadata_carries_risk(tmp_path):
    doc = sbommod.cyclonedx(_result(tmp_path), "demo")
    props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert "sbomkit:risk" in props


def test_cyclonedx_is_json_serialisable(tmp_path):
    json.dumps(sbommod.cyclonedx(_result(tmp_path), "demo"))


# ----------------------------------------------------------------------- spdx


def test_spdx_header():
    text = sbommod.spdx_tagvalue(ScanResult(root="demo"), "demo")
    assert text.startswith("SPDXVersion: SPDX-2.3")
    assert "DataLicense: CC0-1.0" in text
    assert "SPDXID: SPDXRef-DOCUMENT" in text


def test_spdx_packages_and_relationships(tmp_path):
    text = sbommod.spdx_tagvalue(_result(tmp_path), "demo")
    assert "PackageName: requests" in text
    assert 'ExternalRef: PACKAGE-MANAGER purl "pkg:pypi/requests@2.31.0"' in text
    assert text.count("Relationship: SPDXRef-Package-root DEPENDS_ON") == 2


def test_spdx_unknown_license_is_noassertion(tmp_path):
    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "mystery"\nversion = "1.0.0"\n', encoding="utf-8")
    text = sbommod.spdx_tagvalue(scan_path(str(tmp_path), Options()), "demo")
    assert "PackageLicenseDeclared: NOASSERTION" in text


def test_spdx_id_is_safe():
    comp = Component(ecosystem="npm", name="@scope/pkg", version="1.0.0")
    assert sbommod.spdx_id(comp) == "SPDXRef-npm-scope-pkg-1.0.0"


# ---------------------------------------------------------------- round trip


def test_round_trip_preserves_components(tmp_path):
    result = _result(tmp_path)
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(sbommod.cyclonedx(result, "demo")), encoding="utf-8")
    loaded = sbommod.load_cyclonedx(str(path))
    assert {(c.name, c.version) for c in loaded} == {(c.name, c.version) for c in result.components}


def test_round_trip_preserves_license(tmp_path):
    result = _result(tmp_path)
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(sbommod.cyclonedx(result, "demo")), encoding="utf-8")
    loaded = sbommod.load_cyclonedx(str(path))
    assert {c.name: c.license for c in loaded}["requests"] == "Apache-2.0"


def test_round_trip_direct_flag(tmp_path):
    result = _result(tmp_path)
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(sbommod.cyclonedx(result, "demo")), encoding="utf-8")
    loaded = sbommod.load_any(str(path))
    assert all(c.direct is False for c in loaded)


def test_load_any_rejects_non_sbom(tmp_path):
    path = tmp_path / "x.json"
    path.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    try:
        sbommod.load_any(str(path))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ----------------------------------------------------------------------- diff


def _comp(name, version, license_="MIT", direct=True):
    return Component(ecosystem="pypi", name=name, version=version, license=license_, direct=direct)


def test_diff_detects_added():
    entries = diffmod.diff([_comp("a", "1.0.0")], [_comp("a", "1.0.0"), _comp("b", "2.0.0")])
    added = [e for e in entries if e.kind == "added"]
    assert added and added[0].name == "b"


def test_diff_detects_removed():
    entries = diffmod.diff([_comp("a", "1.0.0"), _comp("b", "2.0.0")], [_comp("a", "1.0.0")])
    assert any(e.kind == "removed" and e.name == "b" for e in entries)


def test_diff_detects_downgrade_as_high():
    entries = diffmod.diff([_comp("a", "2.0.0")], [_comp("a", "1.0.0")])
    down = [e for e in entries if e.kind == "downgraded"]
    assert down and down[0].severity == "high"


def test_diff_upgrade_is_low():
    entries = diffmod.diff([_comp("a", "1.0.0")], [_comp("a", "2.0.0")])
    assert [e for e in entries if e.kind == "upgraded"][0].severity == "low"


def test_diff_license_becoming_restrictive_is_high():
    entries = diffmod.diff([_comp("a", "1.0.0", "MIT")], [_comp("a", "1.0.0", "AGPL-3.0-only")])
    change = [e for e in entries if e.kind == "license-changed"]
    assert change and change[0].severity == "high"


def test_diff_license_becoming_permissive_is_low():
    entries = diffmod.diff([_comp("a", "1.0.0", "GPL-3.0-only")], [_comp("a", "1.0.0", "MIT")])
    assert [e for e in entries if e.kind == "license-changed"][0].severity == "low"


def test_diff_scope_change():
    entries = diffmod.diff([_comp("a", "1.0.0", direct=False)], [_comp("a", "1.0.0", direct=True)])
    assert any(e.kind == "scope-changed" for e in entries)


def test_diff_identical_is_empty():
    assert diffmod.diff([_comp("a", "1.0.0")], [_comp("a", "1.0.0")]) == []


def test_diff_is_case_insensitive_on_names():
    entries = diffmod.diff([_comp("Requests", "1.0.0")], [_comp("requests", "1.0.0")])
    assert entries == []


def test_added_without_license_is_medium():
    entries = diffmod.diff([], [Component(ecosystem="pypi", name="x", version="1.0.0")])
    assert entries[0].severity == "medium"


def test_worst_severity_respects_floor():
    entries = diffmod.diff([_comp("a", "1.0.0")], [_comp("a", "2.0.0")])
    assert diffmod.worst_severity(entries, "high") is None
    assert diffmod.worst_severity(entries, "low") == "low"


def test_worst_severity_of_empty_is_none():
    assert diffmod.worst_severity([]) is None


def test_diff_entry_to_dict():
    entries = diffmod.diff([], [_comp("a", "1.0.0")])
    payload = entries[0].to_dict()
    assert payload["kind"] == "added" and payload["name"] == "a"


# ---------------------------------------------------------------------- sarif


def test_sarif_envelope(tmp_path):
    doc = sarifmod.build(_result(tmp_path))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "sbomkit"


def test_sarif_levels(tmp_path):
    doc = sarifmod.build(_result(tmp_path))
    for item in doc["runs"][0]["results"]:
        assert item["level"] in ("error", "warning", "note")
        assert item["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_sarif_rules_are_deduplicated(tmp_path):
    doc = sarifmod.build(_result(tmp_path))
    ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
    assert len(ids) == len(set(ids))


def test_sarif_critical_is_error(tmp_path):
    (tmp_path / "requirements.txt").write_text("x @ git+https://github.com/a/b.git\n", encoding="utf-8")
    doc = sarifmod.build(scan_path(str(tmp_path), Options()))
    levels = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
    assert levels.get("SBK006") == "error"


def test_sarif_is_json_serialisable(tmp_path):
    json.dumps(sarifmod.build(_result(tmp_path)))
