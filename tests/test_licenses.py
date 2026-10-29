from sbomkit import licenses as lic


def test_normalise_common_spellings():
    assert lic.normalize("MIT License") == "MIT"
    assert lic.normalize("Apache 2") == "Apache-2.0"
    assert lic.normalize("BSD") == "BSD-3-Clause"
    assert lic.normalize("GPLv3") == "GPL-3.0-only"
    assert lic.normalize("AGPLv3") == "AGPL-3.0-only"


def test_normalise_plus_suffix():
    assert lic.normalize("GPL-3.0+") == "GPL-3.0-or-later"
    assert lic.normalize("LGPL-2.1+") == "LGPL-2.1-or-later"


def test_normalise_empty_and_markers():
    assert lic.normalize("") is None
    assert lic.normalize(None) is None
    assert lic.normalize("NOASSERTION") is None
    assert lic.normalize("SEE LICENSE IN LICENSE") is None


def test_normalise_keeps_expressions_intact():
    for expr in ("MIT OR Apache-2.0", "(MIT OR GPL-3.0-only)", "GPL-3.0-only AND MIT"):
        assert lic.normalize(expr) == expr


def test_normalise_unlicensed_is_proprietary():
    assert lic.normalize("UNLICENSED") == "LicenseRef-proprietary"


def test_categories():
    assert lic.category("MIT") == lic.PERMISSIVE
    assert lic.category("Apache-2.0") == lic.PERMISSIVE
    assert lic.category("MPL-2.0") == lic.WEAK_COPYLEFT
    assert lic.category("GPL-3.0-only") == lic.STRONG_COPYLEFT
    assert lic.category("AGPL-3.0-only") == lic.NETWORK_COPYLEFT
    assert lic.category("CC0-1.0") == lic.PUBLIC_DOMAIN
    assert lic.category(None) == lic.UNKNOWN


def test_category_suffix_fallback():
    assert lic.category("GPL-9.9-custom") == lic.STRONG_COPYLEFT
    assert lic.category("SomeAGPLThing") == lic.NETWORK_COPYLEFT


def test_licenseref_is_other():
    assert lic.category("LicenseRef-anything") == lic.OTHER


def test_risk_level_ordering():
    assert lic.risk_level("MIT") < lic.risk_level("MPL-2.0")
    assert lic.risk_level("MPL-2.0") < lic.risk_level("GPL-3.0-only")
    assert lic.risk_level("GPL-3.0-only") < lic.risk_level("AGPL-3.0-only")


def test_policy_defaults_present():
    assert set(lic.DEFAULT_POLICIES) == {"closed-source", "weak-ok", "oss", "strict"}


def test_policy_allows():
    assert lic.policy_allows("closed-source", lic.PERMISSIVE)
    assert not lic.policy_allows("closed-source", lic.STRONG_COPYLEFT)
    assert lic.policy_allows("oss", lic.STRONG_COPYLEFT)


def test_unknown_policy_defaults_to_closed_source():
    assert not lic.policy_allows("nonexistent-policy", lic.STRONG_COPYLEFT)


def test_policy_note_covers_every_policy():
    assert set(lic.POLICY_NOTE) == set(lic.DEFAULT_POLICIES)


def test_category_order_has_every_category():
    assert set(lic.CATEGORY_ORDER) == set(lic.CATEGORY_LABEL)


def test_every_cited_license_has_a_category():
    for ident, cat in lic._CATEGORIES.items():
        assert cat in lic.CATEGORY_ORDER, ident


def test_normalize_collapses_whitespace():
    assert lic.normalize("  The MIT License  ") == "MIT"


def test_normalize_python_psf_spelling():
    assert lic.normalize("Python Software Foundation License") == "Python-2.0"


def test_normalize_boost():
    assert lic.normalize("Boost Software License") == "BSL-1.0"


def test_normalize_proprietary_markers():
    assert lic.normalize("Proprietary") == "LicenseRef-proprietary"
    assert lic.normalize("commercial") == "LicenseRef-proprietary"


def test_normalize_unknown_token_returned_as_is():
    assert lic.normalize("Weird-License-7") == "Weird-License-7"


def test_all_alias_targets_are_known():
    for target in lic._ALIASES.values():
        assert target in lic._CATEGORIES or target.startswith("LicenseRef-"), target
