import pytest

from sbomkit.versions import compare, parse, satisfies


@pytest.mark.parametrize(
    "text,expected",
    [
        ("1.2.3", (1, 2, 3)),
        ("v1.2.3", (1, 2, 3)),
        ("1.2", (1, 2, 0)),
        ("2", (2, 0, 0)),
        ("1.2.3-rc1", (1, 2, 3)),
        ("1.2.3+build.5", (1, 2, 3)),
        ("", ()),
    ],
)
def test_parse(text, expected):
    assert parse(text) == expected


@pytest.mark.parametrize(
    "a,b,expected",
    [
        ("1.0.0", "1.0.0", 0),
        ("1.0.1", "1.0.0", 1),
        ("1.0.0", "1.0.1", -1),
        ("2.0.0", "10.0.0", -1),
        ("v1.2.3", "1.2.3", 0),
    ],
)
def test_compare(a, b, expected):
    assert compare(a, b) == expected


def test_pypi_exact():
    assert satisfies("pypi", "==1.2.3", "1.2.3") is True
    assert satisfies("pypi", "==1.2.3", "1.2.4") is False


def test_pypi_wildcard():
    assert satisfies("pypi", "==1.4.*", "1.4.7") is True
    assert satisfies("pypi", "==1.4.*", "1.5.0") is False


def test_pypi_comparisons():
    assert satisfies("pypi", ">=1.0", "2.0") is True
    assert satisfies("pypi", "<2.0", "2.0") is False
    assert satisfies("pypi", "!=1.0", "1.1") is True


def test_pypi_comma_is_and():
    assert satisfies("pypi", ">=1.0,<2.0", "1.5") is True
    assert satisfies("pypi", ">=1.0,<2.0", "2.5") is False


def test_pypi_compatible_release():
    assert satisfies("pypi", "~=1.4.2", "1.4.9") is True
    assert satisfies("pypi", "~=1.4.2", "1.5.0") is False
    assert satisfies("pypi", "~=1.4", "1.9.0") is True
    assert satisfies("pypi", "~=1.4", "2.0.0") is False


def test_npm_caret():
    assert satisfies("npm", "^1.2.3", "1.9.0") is True
    assert satisfies("npm", "^1.2.3", "2.0.0") is False
    assert satisfies("npm", "^0.2.3", "0.2.9") is True
    assert satisfies("npm", "^0.2.3", "0.3.0") is False


def test_npm_tilde():
    assert satisfies("npm", "~1.2.3", "1.2.9") is True
    assert satisfies("npm", "~1.2.3", "1.3.0") is False


def test_npm_range_with_space():
    assert satisfies("npm", ">=1.0.0 <2.0.0", "1.5.0") is True
    assert satisfies("npm", ">=1.0.0 <2.0.0", "2.1.0") is False


def test_npm_or():
    assert satisfies("npm", "^1.0.0 || ^2.0.0", "2.3.0") is True
    assert satisfies("npm", "^1.0.0 || ^2.0.0", "3.0.0") is False


def test_npm_bare_version_is_exact():
    assert satisfies("npm", "1.3.0", "1.3.0") is True
    assert satisfies("npm", "1.3.0", "1.3.1") is False


def test_cargo_bare_version_is_caret():
    assert satisfies("cargo", "1.17", "1.18.0") is True
    assert satisfies("cargo", "1.17", "2.0.0") is False


def test_cargo_explicit_equals():
    assert satisfies("cargo", "=1.17.0", "1.17.0") is True
    assert satisfies("cargo", "=1.17.0", "1.18.0") is False


def test_golang_exact():
    assert satisfies("golang", "v1.4.2", "v1.4.2") is True
    assert satisfies("golang", "v1.4.2", "v1.5.0") is False


def test_url_constraint_is_undecidable():
    assert satisfies("pypi", "@ git+https://example.com/x.git", "1.0.0") is None
    assert satisfies("npm", "git+ssh://git@github.com/a/b.git", "1.0.0") is None


def test_empty_inputs_are_undecidable():
    assert satisfies("pypi", "", "1.0.0") is None
    assert satisfies("pypi", ">=1.0", "") is None


def test_garbage_constraint_is_undecidable():
    assert satisfies("pypi", "???", "1.0.0") is None


def test_unknown_ecosystem_is_undecidable():
    assert satisfies("nuget", "1.0.0", "1.0.0") is None


def test_prerelease_suffix_ignored():
    assert satisfies("pypi", "==1.2.3", "1.2.3-rc1") is True


def test_wildcard_only_pypi():
    assert satisfies("pypi", "*", "9.9.9") is None or satisfies("pypi", "*", "9.9.9") is True
