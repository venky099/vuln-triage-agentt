"""Data models for the triage pipeline.

No LLM imports here on purpose: everything downstream (tools, grounding,
reporting) operates on plain dataclasses, so it can all be unit-tested without
a model, a network, or an API key.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

SEVERITIES = ("Critical", "High", "Medium", "Low", "None")


@dataclass
class RawFinding:
    """One finding exactly as a scanner reported it. This is ground truth.

    Every claim the agent makes must trace back to a field on this object or
    to the CWE catalogue. Nothing else is allowed into the report.
    """
    id: str
    scanner: str
    kind: str                      # "SQL Injection", "Reflected XSS", ...
    url: str = ""
    parameter: str = ""
    method: str = "GET"
    payload: str = ""
    evidence: str = ""             # what the scanner actually saw
    raw: dict[str, Any] = field(default_factory=dict)

    def evidence_corpus(self) -> str:
        """Everything the agent is permitted to draw facts from."""
        parts = [self.kind, self.url, self.parameter, self.method,
                 self.payload, self.evidence, self.scanner]
        parts += [f"{k}={v}" for k, v in (self.raw or {}).items()]
        return "\n".join(str(p) for p in parts if p)


@dataclass
class TriagedFinding:
    """What the agent produced for one raw finding, after validation."""
    source_id: str
    title: str
    cwe_id: str = ""               # "CWE-89"
    cwe_name: str = ""
    cvss_vector: str = ""
    cvss_score: float = 0.0
    severity: str = "None"
    summary: str = ""
    reproduction: str = ""
    remediation: str = ""
    duplicates: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)   # grounding violations

    @property
    def grounded(self) -> bool:
        return not self.flags

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# The form the model must fill in. Free-text answers are where models wander;
# a schema with a fixed shape is much harder to get wrong, and a violation is
# detectable instead of silent.
TRIAGE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["title", "cwe_id", "cvss_metrics", "summary",
                 "reproduction", "remediation"],
    "additionalProperties": False,
    "properties": {
        "title": {"type": "string", "minLength": 8, "maxLength": 120},
        "cwe_id": {"type": "string", "pattern": r"^CWE-\d{1,4}$"},
        # The model chooses the metrics. It does NOT get to state the score —
        # that is computed from these by code, so it cannot be invented.
        "cvss_metrics": {
            "type": "object",
            "required": ["AV", "AC", "PR", "UI", "S", "C", "I", "A"],
            "additionalProperties": False,
            "properties": {
                "AV": {"enum": ["N", "A", "L", "P"]},
                "AC": {"enum": ["L", "H"]},
                "PR": {"enum": ["N", "L", "H"]},
                "UI": {"enum": ["N", "R"]},
                "S":  {"enum": ["U", "C"]},
                "C":  {"enum": ["H", "L", "N"]},
                "I":  {"enum": ["H", "L", "N"]},
                "A":  {"enum": ["H", "L", "N"]},
            },
        },
        "summary": {"type": "string", "minLength": 20, "maxLength": 700},
        "reproduction": {"type": "string", "minLength": 10, "maxLength": 900},
        "remediation": {"type": "string", "minLength": 20, "maxLength": 900},
    },
}
