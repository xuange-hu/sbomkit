"""MCP server: six tools over the same engine the CLI uses.

The ``mcp`` package is imported lazily so the CLI keeps working (and stays
dependency-free) when the extra is not installed.
"""

from __future__ import annotations

from typing import Any

__all__ = ["main", "tool_manifest", "build_server"]

TOOLS = [
    {
        "name": "sbomkit_scan",
        "description": (
            "Audit a project's manifests and lockfiles. Returns components, license "
            "policy verdicts and findings with file:line evidence."
        ),
        "input": {"path": "str (file or directory)", "policy": "str (optional: closed-source|weak-ok|oss|strict)"},
    },
    {
        "name": "sbomkit_sbom",
        "description": "Emit a CycloneDX 1.6 or SPDX 2.3 SBOM for a project.",
        "input": {"path": "str", "format": "str (cyclonedx|spdx)"},
    },
    {
        "name": "sbomkit_diff",
        "description": "Diff two CycloneDX SBOMs: additions, removals, upgrades, downgrades and license changes.",
        "input": {"old": "str (path to SBOM)", "new": "str (path to SBOM)"},
    },
    {
        "name": "sbomkit_explain_license",
        "description": (
            "Explain an SPDX license expression and decide whether a distribution policy permits it. "
            "Handles OR/AND/WITH correctly, so '(MIT OR GPL-3.0-only)' is permitted."
        ),
        "input": {"expression": "str", "policy": "str (optional)"},
    },
    {
        "name": "sbomkit_licenses_of",
        "description": "List every package in a project together with its resolved license and where that value came from.",
        "input": {"path": "str"},
    },
    {
        "name": "sbomkit_rules",
        "description": "List the rule catalogue: id, severity, title.",
        "input": {},
    },
]


def tool_manifest() -> list[dict[str, Any]]:
    return list(TOOLS)


def _scan(path: str, policy: str) -> dict[str, Any]:
    from .scan import Options, scan_path

    return scan_path(path, Options(policy=policy or "closed-source")).to_dict()


def _sbom(path: str, fmt: str) -> Any:
    from . import sbom as sbommod
    from .scan import Options, scan_path

    result = scan_path(path, Options())
    if fmt == "spdx":
        return {"format": "spdx", "document": sbommod.spdx_tagvalue(result)}
    return {"format": "cyclonedx", "document": sbommod.cyclonedx(result)}


def _diff(old: str, new: str) -> dict[str, Any]:
    from . import diff as diffmod
    from . import sbom as sbommod

    entries = diffmod.diff(sbommod.load_any(old), sbommod.load_any(new))
    return {
        "count": len(entries),
        "worst": diffmod.worst_severity(entries),
        "changes": [e.to_dict() for e in entries],
    }


def _explain(expression: str, policy: str) -> dict[str, Any]:
    from . import spdx

    try:
        tree = spdx.explain(expression)
    except spdx.LicenseParseError as exc:
        return {"expression": expression, "error": str(exc)}
    decision = spdx.solve(expression, policy or "closed-source")
    return {
        "expression": expression,
        "policy": policy or "closed-source",
        "tree": tree,
        "verdict": decision.verdict,
        "chosen": decision.chosen,
        "category": decision.category,
        "reason": decision.reason,
    }


def _licenses_of(path: str) -> dict[str, Any]:
    from .scan import Options, scan_path

    result = scan_path(path, Options())
    return {
        "count": len(result.components),
        "resolved": result.licenses_resolved,
        "packages": [
            {
                "ecosystem": c.ecosystem,
                "name": c.name,
                "version": c.version,
                "license": c.license,
                "source_of_truth": c.license_source or "unresolved",
                "direct": c.direct,
                "purl": c.purl,
            }
            for c in result.components
        ],
    }


def _rules() -> dict[str, Any]:
    from .scan import RULES

    return {
        "total": len(RULES),
        "rules": [{"id": k, "severity": v[0], "title": v[1]} for k, v in sorted(RULES.items())],
    }


def build_server():
    """Build the MCP server. Requires the optional ``mcp`` extra."""
    try:
        from mcp.server.fastmcp import FastMCP  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - only when the extra is missing
        raise SystemExit("sbomkit-mcp needs the mcp extra: pip install 'sbomkit[mcp]'") from exc

    server = FastMCP("sbomkit")

    @server.tool()
    def sbomkit_scan(path: str = ".", policy: str = "closed-source") -> dict:
        """Audit manifests and lockfiles, returning findings and license verdicts."""
        return _scan(path, policy)

    @server.tool()
    def sbomkit_sbom(path: str = ".", format: str = "cyclonedx") -> dict:
        """Emit a CycloneDX or SPDX SBOM for the project."""
        return _sbom(path, format)

    @server.tool()
    def sbomkit_diff(old: str = "", new: str = "") -> dict:
        """Diff two CycloneDX SBOMs and classify every change."""
        return _diff(old, new)

    @server.tool()
    def sbomkit_explain_license(expression: str = "", policy: str = "closed-source") -> dict:
        """Explain an SPDX expression and decide whether a policy permits it."""
        return _explain(expression, policy)

    @server.tool()
    def sbomkit_licenses_of(path: str = ".") -> dict:
        """List every package with its resolved license and provenance of that value."""
        return _licenses_of(path)

    @server.tool()
    def sbomkit_rules() -> dict:
        """List the rule catalogue."""
        return _rules()

    return server


def main() -> None:
    server = build_server()
    server.run()
