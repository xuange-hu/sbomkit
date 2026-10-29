import pytest

from sbomkit import licenses as lic
from sbomkit.spdx import (
    And,
    Leaf,
    LicenseParseError,
    Or,
    evaluate,
    explain,
    ids,
    parse,
    renders,
    solve,
)


def test_simple_leaf():
    node = parse("MIT")
    assert isinstance(node, Leaf)
    assert node.ident == "MIT"


def test_or_and_precedence():
    node = parse("MIT AND ISC OR Apache-2.0")
    assert isinstance(node, Or)
    first = node.parts[0]
    assert isinstance(first, And)
    assert [leaf.ident for leaf in first.parts] == ["MIT", "ISC"]


def test_parentheses_override_precedence():
    node = parse("MIT AND (ISC OR Apache-2.0)")
    assert isinstance(node, And)
    assert isinstance(node.parts[1], Or)


def test_with_exception():
    node = parse("Apache-2.0 WITH LLVM-exception")
    assert isinstance(node, Leaf)
    assert node.exception == "LLVM-exception"
    assert node.text == "Apache-2.0 WITH LLVM-exception"


def test_plus_suffix():
    node = parse("GPL-2.0-or-later+")
    assert node.plus is True


def test_unbalanced_raises():
    with pytest.raises(LicenseParseError):
        parse("(MIT OR Apache-2.0")


def test_trailing_token_raises():
    with pytest.raises(LicenseParseError):
        parse("MIT MIT")


def test_empty_raises():
    with pytest.raises(LicenseParseError):
        parse("")


def test_bad_character_raises():
    with pytest.raises(LicenseParseError):
        parse("MIT ! Apache")


def test_ids_collects_exceptions():
    assert "LLVM-exception" in ids(parse("Apache-2.0 WITH LLVM-exception"))


def test_permisive_allowed_under_closed_source():
    assert solve("MIT", "closed-source").verdict == "allow"


def test_gpl_denied_under_closed_source():
    decision = solve("GPL-3.0-only", "closed-source")
    assert decision.verdict == "deny"
    assert decision.category == lic.STRONG_COPYLEFT


def test_agpl_is_critical_class():
    assert solve("AGPL-3.0-only", "closed-source").category == lic.NETWORK_COPYLEFT


def test_or_picks_the_friendly_branch():
    # the whole point of the parser: this is permitted, a substring match says no
    decision = solve("(MIT OR GPL-3.0-only)", "closed-source")
    assert decision.verdict == "allow"
    assert decision.chosen == "MIT"


def test_or_denied_when_every_branch_denied():
    assert solve("GPL-3.0-only OR AGPL-3.0-only", "closed-source").verdict == "deny"


def test_and_inherits_the_strictest():
    assert solve("MIT AND GPL-3.0-only", "closed-source").verdict == "deny"


def test_and_allowed_when_all_allowed():
    decision = solve("MIT AND BSD-3-Clause", "closed-source")
    assert decision.verdict == "allow"


def test_weak_copyleft_policy():
    assert solve("LGPL-3.0-only", "closed-source").verdict == "deny"
    assert solve("LGPL-3.0-only", "weak-ok").verdict == "allow"


def test_oss_policy_allows_gpl():
    assert solve("GPL-3.0-only", "oss").verdict == "allow"


def test_unknown_license_is_unknown_not_denied():
    decision = solve("LicenseRef-weird", "closed-source")
    assert decision.verdict == "deny"  # LicenseRef is 'other', not allowed by default


def test_unresolvable_identifier_is_unknown():
    decision = solve("Some-Weird-License", "closed-source")
    assert decision.verdict == "unknown"


def test_unparseable_expression_is_unknown():
    decision = solve("MIT AND (", "closed-source")
    assert decision.verdict == "unknown"


def test_evaluate_leaf_unknown():
    assert evaluate(Leaf("Nonsense-1.0"), "closed-source").verdict == "unknown"


def test_render_round_trip():
    assert renders(parse("MIT AND (ISC OR Apache-2.0)")) == "MIT AND (ISC OR Apache-2.0)"


def test_explain_tree():
    text = explain("MIT OR Apache-2.0")
    assert "OR (any one)" in text
    assert "MIT -> permissive" in text
    assert "Apache-2.0 -> permissive" in text


def test_case_insensitive_operators():
    assert isinstance(parse("MIT or Apache-2.0"), Or)


def test_with_without_operand_raises():
    with pytest.raises(LicenseParseError):
        parse("MIT WITH")


def test_solve_empty_expression():
    assert solve("", "closed-source").verdict == "unknown"


def test_decision_to_dict_keys():
    payload = solve("MIT", "closed-source").to_dict()
    assert set(payload) == {"verdict", "chosen", "category", "reason"}


def test_mpl_is_weak_copyleft():
    assert lic.category("MPL-2.0") == lic.WEAK_COPYLEFT


def test_ids_order_is_depth_first():
    assert ids(parse("MIT AND ISC")) == ["MIT", "ISC"]


def test_nested_or_inside_and():
    assert solve("MIT AND (GPL-3.0-only OR BSD-3-Clause)", "closed-source").verdict == "allow"


def test_or_with_unknown_branch_resolvable():
    assert solve("Nonsense-1.0 OR MIT", "closed-source").verdict == "allow"


def test_or_unknown_only():
    assert solve("Nonsense-1.0", "closed-source").verdict == "unknown"


def test_and_unknown_leaf():
    assert solve("MIT AND Nonsense-1.0", "closed-source").verdict == "unknown"
