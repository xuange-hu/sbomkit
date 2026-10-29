"""SBOM emission (CycloneDX 1.6 JSON and SPDX 2.3 tag-value) and re-reading.

Round-tripping matters because `sbomkit diff` compares two SBOMs, not two
directories: the PR gate needs to diff the SBOM that was published on `main`
against the one the branch produces.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone

from .model import Component, ScanResult

SPEC_CYCLONEDX = "1.6"
SPEC_SPDX = "SPDX-2.3"

_SAFE = re.compile(r"[^A-Za-z0-9.\-]")


def _ts() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def spdx_id(component: Component) -> str:
    raw = _SAFE.sub("-", f"{component.ecosystem}-{component.name}-{component.version}")
    return "SPDXRef-" + re.sub(r"-{2,}", "-", raw).strip("-")


def cyclonedx(result: ScanResult, name: str | None = None) -> dict:
    project = name or (result.root.rstrip("\\/").rsplit("\\", 1)[-1].rsplit("/", 1)[-1] or "project")
    components = []
    for c in result.components:
        entry: dict = {
            "type": "library",
            "bom-ref": c.purl,
            "name": c.name,
            "version": c.version,
            "purl": c.purl,
        }
        if c.license:
            entry["licenses"] = [{"expression": c.license}]
        else:
            entry["licenses"] = [{"license": {"name": "NOASSERTION"}}]
        entry["properties"] = [
            {"name": "sbomkit:ecosystem", "value": c.ecosystem},
            {"name": "sbomkit:direct", "value": "true" if c.direct else "false"},
            {"name": "sbomkit:locked", "value": "true" if c.locked else "false"},
            {"name": "sbomkit:source", "value": c.source},
            {"name": "sbomkit:line", "value": str(c.line)},
        ]
        components.append(entry)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_CYCLONEDX,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _ts(),
            "component": {"type": "application", "bom-ref": f"pkg:generic/{project}", "name": project},
            "tools": [{"vendor": "sbomkit", "name": "sbomkit", "version": __import__("sbomkit").__version__}],
            "properties": [
                {"name": "sbomkit:risk", "value": str(result.risk)},
                {"name": "sbomkit:findings", "value": str(len(result.findings))},
            ],
        },
        "components": components,
    }


def spdx_tagvalue(result: ScanResult, name: str | None = None) -> str:
    project = name or (result.root.rstrip("\\/").rsplit("\\", 1)[-1].rsplit("/", 1)[-1] or "project")
    lines = [
        f"SPDXVersion: {SPEC_SPDX}",
        "DataLicense: CC0-1.0",
        "SPDXID: SPDXRef-DOCUMENT",
        f"DocumentName: {project}",
        "DocumentNamespace: https://sbomkit.dev/spdx/" + uuid.uuid4().hex,
        f"Creator: Tool: sbomkit-{__import__('sbomkit').__version__}",
        f"Created: {_ts()}",
        "",
        f"PackageName: {project}",
        "SPDXID: SPDXRef-Package-root",
        "PackageDownloadLocation: NOASSERTION",
        "FilesAnalyzed: false",
        "",
    ]
    for c in result.components:
        lines.extend(
            [
                f"PackageName: {c.name}",
                f"SPDXID: {spdx_id(c)}",
                f"PackageVersion: {c.version}",
                "PackageDownloadLocation: NOASSERTION",
                "FilesAnalyzed: false",
                f"PackageLicenseDeclared: {c.license or 'NOASSERTION'}",
                f"PackageLicenseConcluded: {c.license or 'NOASSERTION'}",
                "PackageSupplier: NOASSERTION",
                f"ExternalRef: PACKAGE-MANAGER purl \"{c.purl}\"",
                "",
            ]
        )
    for c in result.components:
        lines.append(f"Relationship: SPDXRef-Package-root DEPENDS_ON {spdx_id(c)}")
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ reading


def load_cyclonedx(path: str) -> list[Component]:
    """Read back a CycloneDX document (ours or a third party's)."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    out: list[Component] = []
    for entry in doc.get("components") or []:
        purl = entry.get("purl") or entry.get("bom-ref") or ""
        ecosystem = "pypi"
        name = entry.get("name", "")
        version = str(entry.get("version", ""))
        if purl.startswith("pkg:"):
            rest = purl[4:]
            ecosystem = rest.split("/", 1)[0]
            tail = rest.split("/", 1)[1] if "/" in rest else name
            if "@" in tail:
                name, version = tail.rsplit("@", 1)
        lic = None
        for item in entry.get("licenses") or []:
            if isinstance(item, dict):
                if item.get("expression"):
                    lic = item["expression"]
                elif item.get("license", {}).get("id"):
                    lic = item["license"]["id"]
                elif item.get("license", {}).get("name") and item["license"]["name"] != "NOASSERTION":
                    lic = item["license"]["name"]
        direct = True
        for prop in entry.get("properties") or []:
            if prop.get("name") == "sbomkit:direct":
                direct = str(prop.get("value")).lower() == "true"
        out.append(Component(ecosystem=ecosystem, name=name, version=version, direct=direct, license=lic))
    return out


def load_any(path: str) -> list[Component]:
    with open(path, encoding="utf-8") as fh:
        head = fh.read(4096)
    if '"bomFormat"' in head or '"CycloneDX"' in head:
        return load_cyclonedx(path)
    raise ValueError(f"{path}: not a CycloneDX JSON SBOM (SPDX tag-value diff input is not supported yet)")
