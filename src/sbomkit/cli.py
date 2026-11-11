"""Command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

from . import __version__, spdx
from . import diff as diffmod
from . import licenses as lic
from . import sarif as sarifmod
from . import sbom as sbommod
from .model import severity_at_least
from .scan import RULES, Options, scan_path

# ------------------------------------------------------------------ palette

_USE_COLOR = True

CODES = {
    "critical": "\033[1;35m",
    "high": "\033[1;31m",
    "medium": "\033[1;33m",
    "low": "\033[36m",
    "info": "\033[90m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m",
    "green": "\033[32m",
}


def set_color(enabled: bool) -> None:
    global _USE_COLOR
    _USE_COLOR = enabled


def _c(text: str, *styles: str) -> str:
    if not _USE_COLOR or not sys.stdout.isatty():
        return text
    prefix = "".join(CODES.get(s, "") for s in styles)
    return f"{prefix}{text}{CODES['reset']}"


# ------------------------------------------------------------------ rendering


def render_scan(result, show_evidence: bool = True) -> str:
    out: list[str] = []
    out.append(_c("sbomkit", "bold") + f" {__version__} — supply-chain vet")
    out.append(f"  target   : {result.root}")
    out.append(f"  files    : {len(result.files)} manifest/lockfile(s)")
    out.append(f"  packages : {len(result.components)} ({result.licenses_resolved} with a resolved license)")
    counts = result.counts
    summary = "  ".join(f"{k}={counts[k]}" for k in ("critical", "high", "medium", "low", "info") if counts[k])
    out.append(f"  findings : {len(result.findings)}  {summary}")
    out.append(f"  risk     : {result.risk}/100")
    out.append("")
    if not result.findings:
        out.append(_c("  no findings", "green", "bold"))
        return "\n".join(out)

    by_rule: dict[str, list] = {}
    for f in result.findings:
        by_rule.setdefault(f.rule, []).append(f)
    for rule in sorted(by_rule):
        items = by_rule[rule]
        first = items[0]
        out.append(_c(f"  [{first.severity.upper():<8}] {rule}  {first.title}", first.severity, "bold"))
        for f in items:
            where = f"{f.file}:{f.line}" if f.line else f.file
            if where:
                out.append(f"      {_c(where, 'dim')}  {f.detail}")
            else:
                out.append(f"      {f.detail}")
            if show_evidence and f.evidence:
                out.append(f"      {_c('| ' + f.evidence[:110], 'dim')}")
        out.append("")
    return "\n".join(out)


def render_diff(entries) -> str:
    out = [_c("sbomkit diff", "bold") + f" — {len(entries)} change(s)", ""]
    if not entries:
        out.append(_c("  no change", "green", "bold"))
        return "\n".join(out)
    for e in entries:
        out.append(_c(f"  [{e.severity.upper():<8}] {e.kind:<16} {e.name}", e.severity, "bold"))
        out.append(f"      {e.detail}")
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------- helpers


def _load_license_map(path: str | None) -> dict | None:
    if not path:
        return None
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("--license-map must be a JSON object")
    # Accept either {"pypi": {...}} or a flat {"name": "MIT"} form.
    if any(isinstance(v, dict) for v in data.values()):
        return data
    return {"*": data}


def _exit_for(result, fail_on: str | None) -> int:
    if not fail_on or fail_on == "none":
        return 0
    hit = any(severity_at_least(f.severity, fail_on) for f in result.findings)
    return 1 if hit else 0


# ------------------------------------------------------------------ commands


def cmd_scan(args: argparse.Namespace) -> int:
    options = Options(
        policy=args.policy,
        license_map=_load_license_map(args.license_map),
        include_dev=not args.no_dev,
        ignore=set(args.ignore or []),
    )
    target = args.path
    if not os.path.exists(target):
        print(f"sbomkit: no such path: {target}", file=sys.stderr)
        return 2
    result = scan_path(target, options)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    elif args.sarif:
        print(json.dumps(sarifmod.build(result), indent=2))
    else:
        print(render_scan(result, show_evidence=not args.no_evidence))
    return _exit_for(result, args.fail_on)


def cmd_sbom(args: argparse.Namespace) -> int:
    options = Options(
        policy=args.policy,
        license_map=_load_license_map(args.license_map),
        include_dev=not args.no_dev,
        ignore=set(args.ignore or []),
    )
    result = scan_path(args.path, options)
    if args.format == "spdx":
        payload = sbommod.spdx_tagvalue(result, args.name)
    else:
        payload = json.dumps(sbommod.cyclonedx(result, args.name), indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(payload)
        print(f"wrote {args.out} ({len(result.components)} components)")
    else:
        print(payload)
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    try:
        old = sbommod.load_any(args.old)
        new = sbommod.load_any(args.new)
    except (OSError, ValueError) as exc:
        print(f"sbomkit: {exc}", file=sys.stderr)
        return 2
    entries = diffmod.diff(old, new)
    if args.json:
        print(json.dumps([e.to_dict() for e in entries], indent=2))
    else:
        print(render_diff(entries))
    if args.fail_on and args.fail_on != "none":
        worst = diffmod.worst_severity(entries, args.fail_on)
        return 1 if worst else 0
    return 0


def cmd_licenses(args: argparse.Namespace) -> int:
    if args.list:
        print(f"policies: {', '.join(sorted(lic.DEFAULT_POLICIES))}")
        print("")
        for name in sorted(lic._CATEGORIES):
            print(f"  {name:<32} {lic.CATEGORY_LABEL[lic._CATEGORIES[name]]}")
        return 0
    expr = args.expression
    if not expr:
        print("sbomkit licenses: give an expression or use --list", file=sys.stderr)
        return 2
    try:
        print(spdx.explain(expr))
    except spdx.LicenseParseError as exc:
        print(f"sbomkit: {exc}", file=sys.stderr)
        return 2
    for policy in args.policies.split(","):
        decision = spdx.solve(expr, policy.strip())
        mark = {"allow": "ALLOW", "deny": "DENY", "unknown": "UNKNOWN"}[decision.verdict]
        print(f"  {policy.strip():<14} {mark:<8} {decision.chosen}  ({decision.reason})")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    from .mcp_server import tool_manifest

    tools = tool_manifest()
    print(f"sbomkit {__version__} — {len(tools)} MCP tools\n")
    for tool in tools:
        print(f"  {tool['name']}")
        print(f"      {tool['description'].strip()}")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    if args.json:
        print(json.dumps({k: {"severity": v[0], "title": v[1]} for k, v in RULES.items()}, indent=2))
        return 0
    print(f"sbomkit {__version__} — {len(RULES)} rules\n")
    for rule in sorted(RULES):
        sev, title = RULES[rule]
        print(f"  {rule}  {sev:<8}  {title}")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    from . import demo

    root = args.dir or os.path.join(tempfile.gettempdir(), "sbomkit-demo")
    demo.write(root)
    print(f"demo project written to {root}\n")
    result = scan_path(root, Options(policy=args.policy))
    print(render_scan(result))
    print(_c("rule coverage", "bold"))
    hit = {f.rule for f in result.findings}
    for rule in sorted(RULES):
        print(f"  {rule}  {'hit' if rule in hit else '-   ':<5}  {RULES[rule][1]}")
    return 0


# ----------------------------------------------------------------- argparse


def build_parser() -> argparse.ArgumentParser:
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("--no-color", action="store_true", help="disable ANSI colour")

    parser = argparse.ArgumentParser(
        prog="sbomkit",
        description="Zero-dependency supply-chain vet for lockfiles: SBOM, license policy, drift, and PR-gate diffs.",
        parents=[shared],
    )
    parser.add_argument("--version", action="version", version=f"sbomkit {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--policy", default="closed-source", choices=sorted(lic.DEFAULT_POLICIES))
        p.add_argument("--license-map", default=None, help="JSON file: {\"pypi\": {\"pkg\": \"MIT\"}}")
        p.add_argument("--no-dev", action="store_true", help="ignore dev/optional dependency groups")
        p.add_argument("--ignore", action="append", default=[], help="rule id to suppress (repeatable)")

    p_scan = sub.add_parser("scan", parents=[shared], help="audit a directory or single file")
    p_scan.add_argument("path", nargs="?", default=".")
    p_scan.add_argument("--json", action="store_true")
    p_scan.add_argument("--sarif", action="store_true")
    p_scan.add_argument("--fail-on", default=None, choices=list(("none", "info", "low", "medium", "high", "critical")))
    p_scan.add_argument("--no-evidence", action="store_true", help="hide the source line under each finding")
    add_common(p_scan)
    p_scan.set_defaults(func=cmd_scan)

    p_sbom = sub.add_parser("sbom", parents=[shared], help="emit an SBOM")
    p_sbom.add_argument("path", nargs="?", default=".")
    p_sbom.add_argument("--format", default="cyclonedx", choices=("cyclonedx", "spdx"))
    p_sbom.add_argument("--name", default=None, help="component name for the project itself")
    p_sbom.add_argument("-o", "--out", default=None)
    add_common(p_sbom)
    p_sbom.set_defaults(func=cmd_sbom)

    p_diff = sub.add_parser("diff", parents=[shared], help="diff two CycloneDX SBOMs")
    p_diff.add_argument("old")
    p_diff.add_argument("new")
    p_diff.add_argument("--json", action="store_true")
    p_diff.add_argument("--fail-on", default=None, choices=list(("none", "info", "low", "medium", "high", "critical")))
    p_diff.set_defaults(func=cmd_diff)

    p_lic = sub.add_parser("licenses", parents=[shared], help="explain a license expression")
    p_lic.add_argument("expression", nargs="?", default="")
    p_lic.add_argument("--policy", "--policies", dest="policies", default="closed-source,weak-ok,oss")
    p_lic.add_argument("--list", action="store_true", help="list known licenses and categories")
    p_lic.set_defaults(func=cmd_licenses)

    p_check = sub.add_parser("check", parents=[shared], help="print the MCP tool manifest")
    p_check.set_defaults(func=cmd_check)

    p_rules = sub.add_parser("rules", parents=[shared], help="list rules")
    p_rules.add_argument("--json", action="store_true")
    p_rules.set_defaults(func=cmd_rules)

    p_demo = sub.add_parser("demo", parents=[shared], help="generate and scan a synthetic project")
    p_demo.add_argument("--dir", default=None)
    p_demo.add_argument("--policy", default="closed-source", choices=sorted(lic.DEFAULT_POLICIES))
    p_demo.set_defaults(func=cmd_demo)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    set_color(not args.no_color)
    try:
        return int(args.func(args))
    except (OSError, ValueError) as exc:
        print(f"sbomkit: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
