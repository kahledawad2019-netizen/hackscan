"""Canonical vulnerability classes, mapped from rule ids and CWEs.

`vuln_class` is the vendor-independent identity used for fingerprinting and dedupe, so
the same issue reported by HackScan, Semgrep and Bandit lands in the same class.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

SQLI = "sqli"
CMDI = "cmdi"
CODEI = "codei"
WEAK_CRYPTO = "weak_crypto"
SECRET = "secret"

KNOWN_CLASSES = frozenset({SQLI, CMDI, CODEI, WEAK_CRYPTO, SECRET})

# Classes the own taint engine models; only these may be suppressed by taint.
TAINT_CLASSES = frozenset({SQLI, CMDI, CODEI})

OTHER_PREFIX = "other:"

_CWE_TO_CLASS = {
    "CWE-89": SQLI,
    "CWE-564": SQLI,
    "CWE-77": CMDI,
    "CWE-78": CMDI,
    "CWE-88": CMDI,
    "CWE-94": CODEI,
    "CWE-95": CODEI,
    "CWE-327": WEAK_CRYPTO,
    "CWE-328": WEAK_CRYPTO,
    "CWE-916": WEAK_CRYPTO,
    "CWE-259": SECRET,
    "CWE-321": SECRET,
    "CWE-798": SECRET,
}

# Exact rule ids (tool-qualified) that map without needing a CWE.
_RULE_TO_CLASS = {
    # Bandit
    "bandit:B608": SQLI,
    "bandit:B602": CMDI,
    "bandit:B604": CMDI,
    "bandit:B605": CMDI,
    "bandit:B609": CMDI,
    "bandit:B102": CODEI,
    "bandit:B307": CODEI,
    "bandit:B303": WEAK_CRYPTO,
    "bandit:B324": WEAK_CRYPTO,
    "bandit:B105": SECRET,
    "bandit:B106": SECRET,
    "bandit:B107": SECRET,
    # Semgrep registry rule whose metadata lists CWE-704 although it detects SQLi.
    "semgrep:python.flask.security.injection.tainted-sql-string.tainted-sql-string": SQLI,
}

# Own rules use the HS-<CLASS>-NNN scheme.
_OWN_RULE_PREFIX = {
    "HS-SQLI-": SQLI,
    "HS-CMDI-": CMDI,
    "HS-CODEI-": CODEI,
    "HS-CRYPTO-": WEAK_CRYPTO,
}

_CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)


def normalize_cwe(raw: str) -> str | None:
    """`'cwe-89: SQL Injection'` -> `'CWE-89'`; returns None if no CWE number is present."""
    match = _CWE_RE.search(raw)
    return f"CWE-{int(match.group(1))}" if match else None


def normalize_cwes(raws: Iterable[str]) -> tuple[str, ...]:
    """Normalize, dedupe and sort CWE ids (numeric order)."""
    found = {c for c in (normalize_cwe(r) for r in raws) if c}
    return tuple(sorted(found, key=lambda c: int(c.split("-")[1])))


def classify(rule_id: str, cwes: Iterable[str] = ()) -> str:
    """Map a rule id and its CWEs to a canonical class.

    Precedence: own rule prefix, then exact tool rule, then gitleaks (always secrets),
    then CWE. Unmappable findings get `other:<lowest CWE>` or `other:<rule_id>`.
    """
    for prefix, cls in _OWN_RULE_PREFIX.items():
        if rule_id.startswith(prefix):
            return cls
    if rule_id in _RULE_TO_CLASS:
        return _RULE_TO_CLASS[rule_id]
    if rule_id.startswith("gitleaks:"):
        return SECRET
    normalized = normalize_cwes(cwes)
    for cwe in normalized:
        if cwe in _CWE_TO_CLASS:
            return _CWE_TO_CLASS[cwe]
    if normalized:
        return f"{OTHER_PREFIX}{normalized[0]}"
    return f"{OTHER_PREFIX}{rule_id}"


def is_mergeable_class(vuln_class: str, cwes: Iterable[str]) -> bool:
    """Findings only merge across sources when their identity is grounded.

    Known classes are always mergeable. `other:` classes merge only when backed by a
    CWE; `other:<rule_id>` (no CWE) never merges with anything else.
    """
    if vuln_class in KNOWN_CLASSES:
        return True
    return bool(normalize_cwes(cwes))
