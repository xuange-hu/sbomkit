# sbomkit

[![tests](https://img.shields.io/badge/tests-315-brightgreen)](https://github.com/xuange-hu/sbomkit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](pyproject.toml)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Zero-dependency supply-chain vet for lockfiles.** Reads what your project
actually pins, turns it into a CycloneDX or SPDX SBOM, decides whether you are
allowed to ship it, and diffs two SBOMs so a pull request can fail on a
downgrade or a license change.

```bash
pip install sbomkit        # no third-party packages
sbomkit scan .
```

---

## Contents

- [Why not just use an existing SBOM tool?](#why-not-just-use-an-existing-sbom-tool)
- [Quick start](#quick-start)
- [Example](#example)
- [SBOM output](#sbom-output)
- [Gate a pull request](#gate-a-pull-request)
- [Supported inputs](#supported-inputs)
- [Rules](#rules)
- [Policies](#policies)
- [Where license data comes from](#where-license-data-comes-from)
- [MCP server](#mcp-server)
- [Limitations](#limitations)
- [Development](#development)
- [License](#license)

## Why not just use an existing SBOM tool?

Three things most scanners in this space get wrong, and sbomkit exists to get
right.

**1. Licenses are expressions, not strings.**

Most tools substring-match the license field. That produces a false positive on
the single most common real-world case:

```
(MIT OR GPL-3.0-only)
```

You are entitled to pick either branch, so this dependency is fine for a
proprietary product. A tool that greps for `GPL` blocks it anyway. sbomkit
parses the SPDX grammar properly — `AND` binds tighter than `OR`, `WITH`
carries an exception — and then *solves* it against a distribution policy:

```console
$ sbomkit licenses "(MIT OR GPL-3.0-only)"
OR (any one)
  MIT -> permissive
  GPL-3.0-only -> strong copyleft
  closed-source  ALLOW    MIT  (OR-expression: taking the friendliest permitted branch (MIT))
  weak-ok        ALLOW    MIT  (OR-expression: taking the friendliest permitted branch (MIT))
  oss            ALLOW    MIT  (OR-expression: taking the friendliest permitted branch (MIT))
```

`MIT AND GPL-3.0-only` under the same policy is **DENY** — under `AND` you
inherit the strictest branch.

**2. The risk is in the *change*, not the snapshot.**

A version bump is noise. A *downgrade*, a new transitive dependency, or a
package that quietly moved from MIT to AGPL is not. Single-snapshot scanners
cannot see any of those. `sbomkit diff` compares two SBOMs and grades every
change:

| change | severity | why |
|---|---|---|
| `downgraded` | high | can silently reintroduce a fixed bug |
| `license-changed` (more restrictive) | high | a legal regression, not a refactor |
| `added` | low / medium | medium when the new package has no resolvable license |
| `upgraded` | low | expected, still worth a line in the PR |
| `scope-changed` | low | a transitive dep became direct (or vice versa) |
| `removed` | info | informational |

**3. Every conclusion shows its source.**

No network calls, no model, no guessing. Each finding carries the file, the
line, and the raw line that produced it, so you can check the tool instead of
trusting it. When a license cannot be determined the answer is `unknown`, not
"probably fine".

---

## Quick start

```bash
pip install sbomkit
sbomkit scan .
sbomkit sbom . -o bom.json          # CycloneDX 1.6
sbomkit rules                        # the 17 rules
```

`uvx` works too, no install:

```bash
uvx --from sbomkit sbomkit scan .
```

## Example

A small Node service. `axios` is dual-licensed, `chart-kit` is AGPL, and
`minimist` is in the lockfile but declared nowhere:

```console
$ sbomkit scan ./checkout-service
sbomkit 0.1.0 — supply-chain vet
  target   : ./checkout-service
  files    : 2 manifest/lockfile(s)
  packages : 4 (4 with a resolved license)
  findings : 2  critical=1  info=1
  risk     : 25/100

  [INFO    ] SBK004  lockfile entry is not declared in any manifest (transitive)
      package-lock.json:9  minimist@1.2.8 is pinned in the lockfile but no manifest declares it
      | node_modules/minimist

  [CRITICAL] SBK009  license violates the distribution policy
      package-lock.json:8  chart-kit@1.2.0 is AGPL-3.0-only (network copyleft is not
                           allowed under 'closed-source')
      | node_modules/chart-kit
```

`axios` is not reported: `(MIT OR Apache-2.0)` resolves to `MIT`.

## SBOM output

```bash
sbomkit sbom . --format cyclonedx -o bom.json   # CycloneDX 1.6 JSON
sbomkit sbom . --format spdx      -o bom.spdx   # SPDX 2.3 tag-value
```

Both carry one `properties` block per component with `sbomkit:direct`,
`sbomkit:locked`, `sbomkit:source` and `sbomkit:line`, so a downstream consumer
can trace any component back to the exact line that introduced it. The
CycloneDX output round-trips through `sbomkit diff`.

## Gate a pull request

```bash
# on main: publish the baseline
sbomkit sbom . -o baseline.json

# in the PR
sbomkit sbom . -o candidate.json
sbomkit diff baseline.json candidate.json --fail-on high
```

Exit codes: `0` clean, `1` something at or above `--fail-on`, `2` bad input.
`sbomkit scan --fail-on high` behaves the same way for the rule set, and
`--sarif` uploads to GitHub code scanning:

```yaml
- run: sbomkit scan . --sarif --fail-on high > sbomkit.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: sbomkit.sarif }
```

## Supported inputs

| ecosystem | manifests | lockfiles |
|---|---|---|
| PyPI | `requirements*.txt`, `constraints.txt`, `pyproject.toml` (PEP 621 + Poetry) | `poetry.lock`, `uv.lock` |
| npm | `package.json` | `package-lock.json` / `npm-shrinkwrap.json` (v1/v2/v3), `yarn.lock` v1 |
| Go | `go.mod` | `go.sum` |
| Cargo | `Cargo.toml` | `Cargo.lock` |

TOML is read by a bundled reader (Python 3.10 has no `tomllib`, and `tomllib`
gives values without the line numbers this tool needs).

## Rules

| id | severity | what it catches |
|---|---|---|
| SBK001 | medium | manifest with no lockfile covering that directory |
| SBK002 | medium | open-ended requirement and nothing pins it |
| SBK003 | high | declared in the manifest, missing from the lockfile |
| SBK004 | info | lockfile entry no manifest declares (transitive) |
| SBK005 | high | locked version falls outside the declared constraint |
| SBK006 | critical | dependency pulled from a URL or VCS instead of a registry |
| SBK007 | high | typosquat: one edit, a homoglyph, or a separator swap away from a popular package |
| SBK008 | medium | license could not be determined |
| SBK009 | high (critical for network copyleft) | license violates the distribution policy |
| SBK010 | medium | several versions of one package are locked |
| SBK011 | low | wildcard version specifier |
| SBK012 | medium | lockfile and on-disk metadata disagree on the license |
| SBK013 | medium | packages resolved from a non-default registry |
| SBK014 | low | declared both as runtime and as dev/build |
| SBK015 | low | lockfile with no matching manifest |
| SBK016 | medium | Go pseudo-version (a commit, not a release tag) |
| SBK017 | low | custom / proprietary license (`LicenseRef-*`) |

`sbomkit demo` writes a synthetic project that trips **all 17** and prints the
coverage table, so you can see every rule fire without trusting the README.

## Policies

| policy | allows |
|---|---|
| `closed-source` | public domain + permissive (default) |
| `weak-ok` | + weak copyleft (MPL, LGPL, CDDL) |
| `oss` | everything, including strong and network copyleft |
| `strict` | permissive only |

## Where license data comes from

In priority order, and the source is always reported:

1. `--license-map file.json` (`{"pypi": {"pkg": "MIT"}}` or a flat `{"pkg": "MIT"}`)
2. inline license in the lockfile (npm lockfiles carry one)
3. **local installed metadata** — `node_modules/<pkg>/package.json`,
   `.venv/**/site-packages/*.dist-info/METADATA`
4. a bundled table of ~150 well-known packages
5. `unknown`

Steps 3 and 4 disagreeing is itself a finding (SBK012), because a lockfile that
does not match the tree on disk is the more interesting of the two problems.

## MCP server

```bash
pip install 'sbomkit[mcp]'
uvx --from 'sbomkit[mcp]' sbomkit-mcp
```

Six tools: `sbomkit_scan`, `sbomkit_sbom`, `sbomkit_diff`,
`sbomkit_explain_license`, `sbomkit_licenses_of`, `sbomkit_rules`.
`sbomkit check` prints the manifest without needing the extra.

## Limitations

* Vulnerability data (CVE / OSV) is deliberately out of scope: any offline tool
  that claims otherwise is guessing. Use an OSV client for that.
* The bundled license table is best-effort. Absence means "unknown", and
  `--license-map` overrides any entry.
* `pnpm-lock.yaml` and Yarn Berry are not parsed yet.
* Go and Cargo licenses usually come back `unknown` because neither lockfile
  format carries license metadata and there is no local cache probed.

## Development

```bash
python -m pip install -e . pytest ruff
python -m pytest
python -m ruff check .
```

## License

MIT
