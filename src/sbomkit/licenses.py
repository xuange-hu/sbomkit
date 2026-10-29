"""License identification and risk categories.

Two jobs, kept deliberately separate from the expression parser:

1. ``normalize``  - map whatever a lockfile says ("MIT License", "Apache 2",
   "BSD-3-Clause", "GPL-3.0+") onto a canonical SPDX identifier.
2. ``category``   - bucket that identifier into a distribution-risk class.

Everything unknown stays unknown. This module never guesses a license for a
package it has no evidence about; that is ``known.py``'s job and it is opt-in.
"""

from __future__ import annotations

import re

# ------------------------------------------------------------------ categories

PERMISSIVE = "permissive"
WEAK_COPYLEFT = "weak-copyleft"
STRONG_COPYLEFT = "strong-copyleft"
NETWORK_COPYLEFT = "network-copyleft"
PUBLIC_DOMAIN = "public-domain"
OTHER = "other"
UNKNOWN = "unknown"

CATEGORY_ORDER = {
    PUBLIC_DOMAIN: 0,
    PERMISSIVE: 1,
    WEAK_COPYLEFT: 3,
    OTHER: 4,
    STRONG_COPYLEFT: 6,
    NETWORK_COPYLEFT: 7,
    UNKNOWN: 5,
}

CATEGORY_LABEL = {
    PERMISSIVE: "permissive",
    WEAK_COPYLEFT: "weak copyleft",
    STRONG_COPYLEFT: "strong copyleft",
    NETWORK_COPYLEFT: "network copyleft",
    PUBLIC_DOMAIN: "public domain",
    OTHER: "other",
    UNKNOWN: "unknown",
}

# Canonical SPDX id -> category. Only licenses that actually show up in real
# lockfiles are listed; anything else falls through to ``UNKNOWN`` via the
# suffix heuristics and then to the explicit UNKNOWN bucket.
_CATEGORIES: dict[str, str] = {
    # public domain
    "CC0-1.0": PUBLIC_DOMAIN,
    "Unlicense": PUBLIC_DOMAIN,
    "MIT-0": PUBLIC_DOMAIN,
    "0BSD": PUBLIC_DOMAIN,
    # permissive
    "MIT": PERMISSIVE,
    "MIT-advertising": PERMISSIVE,
    "ISC": PERMISSIVE,
    "Apache-2.0": PERMISSIVE,
    "Apache-1.1": PERMISSIVE,
    "BSD-2-Clause": PERMISSIVE,
    "BSD-3-Clause": PERMISSIVE,
    "BSD-1-Clause": PERMISSIVE,
    "BSD-4-Clause": PERMISSIVE,
    "Zlib": PERMISSIVE,
    "BSL-1.0": PERMISSIVE,
    "Python-2.0": PERMISSIVE,
    "PostgreSQL": PERMISSIVE,
    "NCSA": PERMISSIVE,
    "AFL-3.0": PERMISSIVE,
    "AFL-2.1": PERMISSIVE,
    "CC-BY-4.0": PERMISSIVE,
    "CC-BY-3.0": PERMISSIVE,
    "Unicode-DFS-2016": PERMISSIVE,
    "WTFPL": PERMISSIVE,
    # weak copyleft
    "MPL-2.0": WEAK_COPYLEFT,
    "MPL-1.1": WEAK_COPYLEFT,
    "MPL-2.0-no-copyleft-exception": WEAK_COPYLEFT,
    "LGPL-2.1-only": WEAK_COPYLEFT,
    "LGPL-2.1-or-later": WEAK_COPYLEFT,
    "LGPL-3.0-only": WEAK_COPYLEFT,
    "LGPL-3.0-or-later": WEAK_COPYLEFT,
    "LGPL-2.0-only": WEAK_COPYLEFT,
    "ECL-2.0": WEAK_COPYLEFT,
    "CDDL-1.0": WEAK_COPYLEFT,
    "CDDL-1.1": WEAK_COPYLEFT,
    "CPL-1.0": WEAK_COPYLEFT,
    "OSL-3.0": WEAK_COPYLEFT,
    # strong copyleft
    "GPL-2.0-only": STRONG_COPYLEFT,
    "GPL-2.0-or-later": STRONG_COPYLEFT,
    "GPL-3.0-only": STRONG_COPYLEFT,
    "GPL-3.0-or-later": STRONG_COPYLEFT,
    "AGPL-3.0-only": NETWORK_COPYLEFT,
    "AGPL-3.0-or-later": NETWORK_COPYLEFT,
    "SSPL-1.0": NETWORK_COPYLEFT,
    "EUPL-1.2": STRONG_COPYLEFT,
    "CC-BY-SA-4.0": STRONG_COPYLEFT,
    "CC-BY-SA-3.0": STRONG_COPYLEFT,
    "BUSL-1.1": OTHER,
    "Elastic-2.0": OTHER,
    "Prosperity-3.0": OTHER,
}

# Suffix fallbacks for ids we have not enumerated.
_SUFFIX_RULES: tuple[tuple[str, str], ...] = (
    ("AGPL", NETWORK_COPYLEFT),
    ("SSPL", NETWORK_COPYLEFT),
    ("LGPL", WEAK_COPYLEFT),
    ("GPL", STRONG_COPYLEFT),
    ("MPL", WEAK_COPYLEFT),
    ("CDDL", WEAK_COPYLEFT),
    ("ECL", WEAK_COPYLEFT),
    ("MIT", PERMISSIVE),
    ("BSD", PERMISSIVE),
    ("ISC", PERMISSIVE),
    ("Apache", PERMISSIVE),
    ("Zlib", PERMISSIVE),
    ("CC0", PUBLIC_DOMAIN),
    ("Unlicense", PUBLIC_DOMAIN),
)

# Non-SPDX spellings seen in the wild -> canonical id.
_ALIASES: dict[str, str] = {
    "mit license": "MIT",
    "mit/x11": "MIT",
    "x11": "MIT",
    "expat": "MIT",
    "expat license": "MIT",
    "the mit license": "MIT",
    "apache license 2.0": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache2": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache license version 2.0": "Apache-2.0",
    "asl 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "new bsd license": "BSD-3-Clause",
    "simplified bsd license": "BSD-2-Clause",
    "2-clause bsd license": "BSD-2-Clause",
    "3-clause bsd license": "BSD-3-Clause",
    "bsd-2": "BSD-2-Clause",
    "bsd-3": "BSD-3-Clause",
    "isc license": "ISC",
    "mozilla public license 2.0": "MPL-2.0",
    "mpl 2.0": "MPL-2.0",
    "gplv2": "GPL-2.0-only",
    "gpl v2": "GPL-2.0-only",
    "gpl-2": "GPL-2.0-only",
    "gpl-2.0": "GPL-2.0-only",
    "gnu general public license v2.0": "GPL-2.0-only",
    "gplv3": "GPL-3.0-only",
    "gpl v3": "GPL-3.0-only",
    "gpl-3": "GPL-3.0-only",
    "gpl-3.0": "GPL-3.0-only",
    "gnu general public license v3.0": "GPL-3.0-only",
    "gpl-2+": "GPL-2.0-or-later",
    "gpl-3+": "GPL-3.0-or-later",
    "gplv2+": "GPL-2.0-or-later",
    "gplv3+": "GPL-3.0-or-later",
    "lgplv2.1": "LGPL-2.1-only",
    "lgpl-2.1": "LGPL-2.1-only",
    "lgplv3": "LGPL-3.0-only",
    "lgpl-3.0": "LGPL-3.0-only",
    "lgpl": "LGPL-3.0-only",
    "agplv3": "AGPL-3.0-only",
    "agpl-3.0": "AGPL-3.0-only",
    "agpl": "AGPL-3.0-only",
    "agpl-3+": "AGPL-3.0-or-later",
    "unlicense": "Unlicense",
    "cc0": "CC0-1.0",
    "cc0-1.0": "CC0-1.0",
    "zlib license": "Zlib",
    "boost software license": "BSL-1.0",
    "python software foundation license": "Python-2.0",
    "psf": "Python-2.0",
    "psf-2.0": "Python-2.0",
    "proprietary": "LicenseRef-proprietary",
    "commercial": "LicenseRef-proprietary",
    "closed source": "LicenseRef-proprietary",
    "unlicense license": "Unlicense",
}


def _title_key(text: str) -> str:
    return re.sub(r"[\s,]+", " ", text.strip().lower()).strip(" .")


def normalize(raw: str | None) -> str | None:
    """Best-effort mapping of a free-text license onto an SPDX id.

    Returns ``None`` when there is nothing usable, which callers must treat as
    "unknown", never as "probably fine".
    """
    if raw is None:
        return None
    text = raw.strip()
    if not text:
        return None
    key = _title_key(text)
    if key in ("none", "noassertion", "n/a", "na", "unknown", ""):
        return None
    if key in _ALIASES:
        return _ALIASES[key]

    # ``SEE LICENSE IN LICENSE`` / ``UNLICENSED`` style markers
    if key.startswith("see license"):
        return None
    if key == "unlicensed":
        return "LicenseRef-proprietary"

    # An expression ("MIT OR Apache-2.0", "GPL-3.0-only AND MIT") is not a
    # single license id. Hand it back untouched for spdx.py to parse; folding
    # it here would turn "(MIT OR GPL-3.0-only)" into one unknown token and
    # make every dual-licensed package look copyleft.
    if re.search(r"(^|[\s(])(OR|AND|WITH)([\s)]|$)", text, re.IGNORECASE) or "(" in text:
        return text

    # Exact SPDX id, with or without the "+" and "-only"/"-or-later" suffix.
    cand = text.replace(" ", "-")
    cand = re.sub(r"[^A-Za-z0-9.+\-]", "", cand)
    if cand in _CATEGORIES:
        return cand
    if cand.endswith("+"):
        base = cand[:-1]
        if base in _CATEGORIES:
            return base
        if base + "-or-later" in _CATEGORIES:
            return base + "-or-later"
        return base + "-or-later"
    if cand in _ALIASES:
        return _ALIASES[cand]

    upper = cand.upper()
    for known in _CATEGORIES:
        if known.upper() == upper:
            return known
    # "Apache-2.0 WITH LLVM-exception" is handled by the expression parser;
    # a bare token that merely starts with a known id is not enough.
    return cand or None


def category(license_id: str | None) -> str:
    """Risk class for a (normalized) license id."""
    if not license_id:
        return UNKNOWN
    if license_id in _CATEGORIES:
        return _CATEGORIES[license_id]
    if license_id.startswith("LicenseRef-"):
        return OTHER
    base = license_id[:-1] if license_id.endswith("+") else license_id
    for token, cat in _SUFFIX_RULES:
        if token.lower() in base.lower():
            return cat
    return UNKNOWN


def risk_level(license_id: str | None) -> int:
    return CATEGORY_ORDER.get(category(license_id), CATEGORY_ORDER[UNKNOWN])


# -------------------------------------------------------------- policy presets

DEFAULT_POLICIES: dict[str, tuple[str, ...]] = {
    # Distribution context -> categories that are allowed.
    "closed-source": (PUBLIC_DOMAIN, PERMISSIVE),
    "weak-ok": (PUBLIC_DOMAIN, PERMISSIVE, WEAK_COPYLEFT),
    "oss": (PUBLIC_DOMAIN, PERMISSIVE, WEAK_COPYLEFT, STRONG_COPYLEFT, NETWORK_COPYLEFT),
    "strict": (PUBLIC_DOMAIN, PERMISSIVE),
}

POLICY_NOTE = {
    "closed-source": "proprietary distribution: copyleft is not acceptable",
    "weak-ok": "proprietary distribution with dynamic linking only",
    "oss": "open-source distribution",
    "strict": "permissive-only distribution",
}


def policy_allows(policy: str, cat: str) -> bool:
    return cat in DEFAULT_POLICIES.get(policy, DEFAULT_POLICIES["closed-source"])
