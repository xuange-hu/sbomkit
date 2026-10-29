"""SARIF 2.1.0 output, so findings land in GitHub code scanning."""

from __future__ import annotations

from .model import ScanResult
from .scan import RULES

_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def build(result: ScanResult) -> dict:
    rules = []
    seen: list[str] = []
    for f in result.findings:
        if f.rule in seen:
            continue
        seen.append(f.rule)
        rules.append(
            {
                "id": f.rule,
                "name": f.rule,
                "shortDescription": {"text": RULES.get(f.rule, ("", "unknown rule"))[1]},
                "fullDescription": {"text": RULES.get(f.rule, ("", "unknown rule"))[1]},
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(f.severity, "warning")},
                "properties": {"tags": ["supply-chain", "sbom", "license"]},
            }
        )

    results = []
    for f in result.findings:
        uri = f.file.replace("\\", "/") if f.file else result.root.replace("\\", "/")
        region = {"startLine": max(1, f.line)} if f.line else {"startLine": 1}
        results.append(
            {
                "ruleId": f.rule,
                "level": _SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": f"{f.detail}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": region,
                        }
                    }
                ],
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sbomkit",
                        "informationUri": "https://github.com/xuange-hu/sbomkit",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
