# Security policy

## Scope

**sbomkit** — Supply chain check-up: SBOM, SPDX licence expressions and PR-gate diffs — is a static analysis tool: it reads **lockfiles across four ecosystems, SBOM documents, and SPDX licence expressions** and prints a report.
The security questions that apply to it are the ones that apply to any tool
that parses untrusted input.

Supported: the current release.

## What this tool does with your files

Nothing leaves your machine. There is no network client in the scanning path:
the tool opens the files you point it at, parses them, and writes a report.
It never writes to the files it reads.

## Reporting a vulnerability in sbomkit

Use [GitHub private vulnerability reporting](https://github.com/xuange-hu/sbomkit/security/advisories)
on the Security tab. If private reporting is unavailable to you, open an issue
marked `security`.

Include:

1. the version (`sbomkit --version`);
2. the input that triggers it — the actual file is preferred over a description;
3. what you expected and what happened.

For a parse failure, the smallest input that reproduces it is the whole report.

## What counts as a vulnerability here

- **The SPDX expression solver under-reporting an obligation.** `(MIT OR GPL-3.0-only)` may be satisfied by MIT; a substring match says otherwise. If the solver picks the stricter branch wrongly, or the looser one wrongly in the other direction, the answer a user acts on is wrong.
- **A lockfile parsed into the wrong shape.** `tomlite` is hand-written; a dropped array table is a silently missing package, which is the worst failure this tool can have.
- **A diff that misses a downgrade or a licence getting stricter** — that is the whole PR gate.
- **A path that escapes the directory it was pointed at.**

## What does not count

- A rule firing on input you consider correct. That is a false positive: open
  an issue with the sample and it gets a regression test.
- A rule you want added. Open an issue or a PR.

## Timing

I triage within a week and will confirm receipt. If a fix needs to sit in a
branch for a while, the advisory goes out when the fix lands, not before.
