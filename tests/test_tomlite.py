import pytest

from sbomkit.tomlite import TomlError, loads


def test_scalars():
    doc = loads('a = 1\nb = 2.5\nc = true\nd = "x"\ne = \'y\'\n')
    assert doc.value == {"a": 1, "b": 2.5, "c": True, "d": "x", "e": "y"}


def test_table_and_line_numbers():
    doc = loads("[project]\nname = 'demo'\nversion = '1.0'\n")
    assert doc.value["project"]["name"] == "demo"
    assert doc.lines["project"] == 1
    assert doc.lines["project.name"] == 2
    assert doc.lines["project.version"] == 3


def test_array_of_tables():
    text = '[[package]]\nname = "a"\nversion = "1"\n\n[[package]]\nname = "b"\nversion = "2"\n'
    doc = loads(text)
    pkgs = doc.value["package"]
    assert isinstance(pkgs, list) and len(pkgs) == 2
    assert [p["name"] for p in pkgs] == ["a", "b"]
    assert doc.lines["package.1.name"] == 6


def test_array_of_tables_keeps_order_with_interleaved_keys():
    # regression: the container used to be re-resolved from the path, which
    # turned the list back into a dict and silently dropped every package
    doc = loads('[[package]]\nname = "a"\nversion = "1"\noptional = false\n')
    assert doc.value["package"][0] == {"name": "a", "version": "1", "optional": False}


def test_multiline_array():
    doc = loads('deps = [\n  "a",\n  "b",\n]\n')
    assert doc.value["deps"] == ["a", "b"]
    assert doc.lines["deps"] == 1


def test_inline_table():
    doc = loads('pkg = { name = "a", version = "1" }\n')
    assert doc.value["pkg"] == {"name": "a", "version": "1"}


def test_comments_are_stripped_outside_strings():
    doc = loads('a = "has # inside"  # real comment\nb = 2 # another\n')
    assert doc.value["a"] == "has # inside"
    assert doc.value["b"] == 2


def test_multiline_string():
    doc = loads('text = """\nhello\nworld\n"""\n')
    assert doc.value["text"].strip() == "hello\nworld"


def test_literal_string_keeps_backslashes():
    doc = loads(r"path = 'C:\new\table'" + "\n")
    assert doc.value["path"] == "C:\\new\\table"


def test_dotted_keys():
    doc = loads("a.b.c = 1\n")
    assert doc.value["a"]["b"]["c"] == 1


def test_nested_table_header():
    doc = loads("[tool.poetry.dependencies]\nflask = '^2'\n")
    assert doc.value["tool"]["poetry"]["dependencies"]["flask"] == "^2"
    assert doc.lines["tool.poetry.dependencies.flask"] == 2


def test_negative_and_underscored_numbers():
    doc = loads("a = -1\nb = 1_000\n")
    assert doc.value["a"] == -1
    assert doc.value["b"] == 1000


def test_empty_array():
    assert loads("a = []\n").value["a"] == []


def test_escaped_quotes():
    assert loads(r'a = "say \"hi\""' + "\n").value["a"] == 'say "hi"'


def test_unterminated_table_raises():
    with pytest.raises(TomlError):
        loads("[project\n")


def test_statement_without_equals_raises():
    with pytest.raises(TomlError):
        loads("this is not toml\n")


def test_unbalanced_parenthesis_in_array_raises():
    with pytest.raises(TomlError):
        loads("a = [1, 2\n")


def test_unsupported_bare_value_raises():
    with pytest.raises(TomlError):
        loads("a = ???\n")


def test_blank_lines_and_indentation_are_ignored():
    doc = loads("\n\n   \n[  a  ]\n   b   =   1   \n\n")
    assert doc.value == {"a": {"b": 1}}


def test_line_map_covers_every_scalar():
    text = "[project]\nname = 'x'\ndeps = ['a']\n\n[tool]\nflag = true\n"
    doc = loads(text)
    for key in ("project.name", "project.deps", "tool.flag"):
        assert key in doc.lines


def test_cargo_lock_shape():
    text = (
        "version = 3\n\n"
        '[[package]]\nname = "serde"\nversion = "1.0.190"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n\n'
        '[[package]]\nname = "tokio"\nversion = "1.33.0"\n'
    )
    doc = loads(text)
    assert doc.value["version"] == 3
    assert len(doc.value["package"]) == 2
    assert doc.value["package"][1]["name"] == "tokio"


def test_top_level_key_before_any_table():
    doc = loads("version = 3\n\n[[package]]\nname = 'a'\n")
    assert doc.value["version"] == 3
    assert doc.value["package"][0]["name"] == "a"


def test_two_arrays_same_document():
    doc = loads("[[a]]\nx = 1\n[[b]]\ny = 2\n")
    assert doc.value["a"][0]["x"] == 1
    assert doc.value["b"][0]["y"] == 2


def test_quoted_key_with_dots():
    doc = loads('"a.b" = 1\n')
    assert doc.value["a.b"] == 1
