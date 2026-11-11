"""MCP surface: the served names must match the manifest, with descriptions."""

from __future__ import annotations

import asyncio
import json

import pytest

from sbomkit import mcp_server


def test_served_tools_match_manifest_with_descriptions():
    """The names an agent calls must be the names the manifest promises, and
    FastMCP serves an empty description when the registered function has no
    docstring - an unidentified tool is an uncallable tool."""
    pytest.importorskip("mcp")
    server = mcp_server.build_server()
    tools = asyncio.run(server.list_tools())
    served = {t.name for t in tools}
    manifest = {t["name"] for t in mcp_server.tool_manifest()}
    assert served == manifest, f"only served: {served - manifest}; only manifest: {manifest - served}"
    for t in tools:
        assert (t.description or "").strip(), f"{t.name} has no description"


def test_demo_tool_scans_its_own_corpus():
    """One call must produce a real report plus honest rule coverage."""
    pytest.importorskip("mcp")
    payload = mcp_server._demo("closed-source")
    assert payload["findings"] >= 1
    assert any(payload["coverage"].values()), "the demo corpus must hit at least one rule"
    # every coverage value must be a bool, not a count or a string
    assert all(isinstance(v, bool) for v in payload["coverage"].values())
    json.dumps(payload)  # must stay JSON-serialisable for FastMCP
