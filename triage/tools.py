"""Tools the agent may call.

The division of labour matters more than the code here. The model decides
*judgement* things ("is confidentiality impact high?"). Code decides *factual*
things (what score those metrics produce, whether a CWE exists). A model that
is never asked to state a number can never invent one.
"""
from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any

from .models import RawFinding

DATA = Path(__file__).resolve().parent.parent / "data"

# --------------------------------------------------------------------------
# CWE catalogue  (grounding source #2 — the scan data is source #1)
# --------------------------------------------------------------------------

_CWE_CACHE: dict[str, dict[str, str]] | None = None


def cwe_catalogue() -> dict[str, dict[str, str]]:
    global _CWE_CACHE
    if _CWE_CACHE is None:
        _CWE_CACHE = json.loads((DATA / "cwe.json").read_text(encoding="utf-8"))
    return _CWE_CACHE


def lookup_cwe(cwe_id: str) -> dict[str, str] | None:
    """Return the catalogue entry, or None if this CWE is not one we know.

    None is the important case: it means the model produced an identifier that
    does not exist in our source of truth, and the claim gets blocked.
    """
    return cwe_catalogue().get((cwe_id or "").strip().upper())


# --------------------------------------------------------------------------
# CVSS v3.1 base score
# --------------------------------------------------------------------------

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}

VECTOR_RE = re.compile(
    r"^CVSS:3\.1/AV:([NALP])/AC:([LH])/PR:([NLH])/UI:([NR])/"
    r"S:([UC])/C:([HLN])/I:([HLN])/A:([HLN])$"
)


def _roundup(value: float) -> float:
    """CVSS v3.1 Appendix A roundup — integer arithmetic, not round()."""
    i = int(round(value * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def build_vector(m: dict[str, str]) -> str:
    return ("CVSS:3.1/AV:{AV}/AC:{AC}/PR:{PR}/UI:{UI}/"
            "S:{S}/C:{C}/I:{I}/A:{A}").format(**m)


def score_cvss(vector: str) -> tuple[float, str]:
    """Compute the base score and severity rating from a v3.1 vector.

    Raises ValueError on a malformed vector, which is itself a useful signal:
    a model that invents a vector usually gets the shape subtly wrong.
    """
    match = VECTOR_RE.match((vector or "").strip())
    if not match:
        raise ValueError(f"malformed CVSS v3.1 vector: {vector!r}")
    av, ac, pr, ui, scope, c, i, a = match.groups()

    iss = 1 - ((1 - _CIA[c]) * (1 - _CIA[i]) * (1 - _CIA[a]))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    exploitability = 8.22 * _AV[av] * _AC[ac] * (_PR_U if scope == "U" else _PR_C)[pr] * _UI[ui]

    if impact <= 0:
        score = 0.0
    elif scope == "U":
        score = _roundup(min(impact + exploitability, 10))
    else:
        score = _roundup(min(1.08 * (impact + exploitability), 10))
    return score, severity_of(score)


def severity_of(score: float) -> str:
    if score == 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


# --------------------------------------------------------------------------
# Deduplication
# --------------------------------------------------------------------------

def _dedupe_key(f: RawFinding) -> tuple[str, str, str]:
    """Same bug class, same endpoint, same parameter = the same finding.

    Query strings are stripped: a scanner that walks ?id=1 and ?id=2 reports
    the same injection twice, and a report that lists it twice looks careless.
    """
    path = re.sub(r"[?#].*$", "", f.url or "").rstrip("/").lower()
    return (f.kind.strip().lower(), path, (f.parameter or "").strip().lower())


def dedupe(findings: list[RawFinding]) -> list[tuple[RawFinding, list[str]]]:
    """Return [(kept_finding, [ids_it_absorbed]), ...] preserving input order."""
    groups: dict[tuple[str, str, str], list[RawFinding]] = {}
    order: list[tuple[str, str, str]] = []
    for f in findings:
        key = _dedupe_key(f)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)
    return [(groups[k][0], [d.id for d in groups[k][1:]]) for k in order]


# --------------------------------------------------------------------------
# Tool descriptions, for backends that support native tool calling
# --------------------------------------------------------------------------

TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "lookup_cwe",
        "description": "Look up a CWE identifier in the local catalogue. "
                       "Returns null if the CWE is not present, which means it must not be cited.",
        "parameters": {
            "type": "object",
            "properties": {"cwe_id": {"type": "string", "description": "e.g. CWE-89"}},
            "required": ["cwe_id"],
        },
    },
    {
        "name": "score_cvss",
        "description": "Compute the CVSS v3.1 base score and severity from a vector string. "
                       "Always use this; never state a score yourself.",
        "parameters": {
            "type": "object",
            "properties": {"vector": {"type": "string"}},
            "required": ["vector"],
        },
    },
]

TOOL_IMPLS = {
    "lookup_cwe": lambda cwe_id: lookup_cwe(cwe_id),
    "score_cvss": lambda vector: (lambda s: {"score": s[0], "severity": s[1]})(score_cvss(vector)),
}
