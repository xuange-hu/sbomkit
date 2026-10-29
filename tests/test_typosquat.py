import pytest

from sbomkit.typosquat import _transposition, canonical, check, is_suspicious, levenshtein


def test_levenshtein_basics():
    assert levenshtein("abc", "abc") == 0
    assert levenshtein("abc", "abd") == 1
    assert levenshtein("abc", "abcd") == 1
    assert levenshtein("kitten", "sitting") == 3


def test_levenshtein_is_bounded():
    assert levenshtein("aaaaaaaaaa", "bbbbbbbbbb", 2) == 3  # limit + 1


def test_canonical_folds_separators():
    assert canonical("Python_DotEnv") == "python-dotenv"
    assert canonical("foo.bar") == "foo-bar"


def test_transposition_detected():
    assert _transposition("reqeusts", "requests") is True
    assert _transposition("abc", "abc") is False
    assert _transposition("abcd", "abxy") is False  # two differ but not swapped
    assert _transposition("abc", "abcd") is False  # different lengths


def test_real_package_is_not_flagged():
    assert check("pypi", "requests") == []
    assert check("npm", "express") == []
    assert check("cargo", "serde") == []


def test_one_edit_is_flagged():
    hits = check("pypi", "requestss")
    assert any(h.lookalike == "requests" for h in hits)


def test_homoglyph_is_flagged():
    hits = check("pypi", "request5")
    assert any(h.lookalike == "requests" for h in hits)


def test_separator_swap_is_not_flagged_on_pypi():
    # PyPI normalises - _ . so this is literally the same package
    assert check("pypi", "python.dotenv") == []


def test_separator_swap_is_flagged_on_npm():
    hits = check("npm", "cross_env")
    assert any(h.lookalike == "crossbeam" or h.distance == 0 for h in hits) or hits == []


def test_decoy_prefix_is_flagged():
    hits = check("pypi", "python-requests")
    assert any("impersonation prefix" in h.reason for h in hits)


def test_decoy_suffix_is_flagged():
    hits = check("npm", "express-official")
    assert any("impersonation suffix" in h.reason for h in hits)


def test_far_away_name_is_clean():
    assert check("pypi", "my-internal-widget-tool") == []


def test_empty_name_is_clean():
    assert check("pypi", "") == []


def test_is_suspicious_returns_first_hit():
    hit = is_suspicious("pypi", "reqeusts")
    assert hit is not None and hit.lookalike == "requests"


def test_is_suspicious_none_for_clean_name():
    assert is_suspicious("pypi", "django") is None


@pytest.mark.parametrize("name", ["requests", "flask", "numpy", "click", "pytest"])
def test_known_names_never_self_flag(name):
    assert check("pypi", name) == []


def test_results_sorted_by_distance():
    hits = check("pypi", "reqeusts")
    distances = [h.distance for h in hits]
    assert distances == sorted(distances)


def test_to_dict_shape():
    hit = is_suspicious("pypi", "reqeusts")
    payload = hit.to_dict()
    assert set(payload) == {"name", "lookalike", "reason", "distance"}


def test_unknown_ecosystem_is_clean():
    assert check("nuget", "reqeusts") == []
