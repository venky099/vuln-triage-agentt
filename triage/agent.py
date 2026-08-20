"""The triage loop.

For each finding:

    dedupe  ->  ask the model to fill in the schema  ->  validate
            ->  compute the score from its metrics (code, not model)
            ->  resolve the CWE against the catalogue (code, not model)
            ->  ground-check every remaining claim

The model is only ever asked for judgement. Every number and identifier in the
finished report is produced or verified by code.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable

from .grounding import enforce
from .llm import SYSTEM_PROMPT, Backend, get_backend
from .models import TRIAGE_SCHEMA, RawFinding, TriagedFinding
from .tools import build_vector, cwe_catalogue, dedupe, lookup_cwe, score_cvss


class SchemaError(ValueError):
    pass


def validate(payload: Any) -> dict[str, Any]:
    """Validate against TRIAGE_SCHEMA. Small hand-rolled checker, no dependency.

    Only the subset of JSON Schema the form actually uses is implemented, and
    an unsupported keyword is a bug rather than a silent pass.
    """
    if not isinstance(payload, dict):
        raise SchemaError("expected a JSON object")

    props = TRIAGE_SCHEMA["properties"]
    for key in TRIAGE_SCHEMA["required"]:
        if key not in payload:
            raise SchemaError("missing required field: {}".format(key))
    for key in payload:
        if key not in props:
            raise SchemaError("unexpected field: {}".format(key))

    import re as _re
    for key, spec in props.items():
        if key not in payload:
            continue
        value = payload[key]
        if spec.get("type") == "string":
            if not isinstance(value, str):
                raise SchemaError("{} must be a string".format(key))
            if len(value) < spec.get("minLength", 0):
                raise SchemaError("{} is too short (min {})".format(key, spec["minLength"]))
            if len(value) > spec.get("maxLength", 10 ** 9):
                raise SchemaError("{} is too long (max {})".format(key, spec["maxLength"]))
            if "pattern" in spec and not _re.match(spec["pattern"], value):
                raise SchemaError("{} does not match {}".format(key, spec["pattern"]))
        elif spec.get("type") == "object":
            if not isinstance(value, dict):
                raise SchemaError("{} must be an object".format(key))
            for sub in spec["required"]:
                if sub not in value:
                    raise SchemaError("{}.{} is missing".format(key, sub))
            for sub, sub_value in value.items():
                sub_spec = spec["properties"].get(sub)
                if sub_spec is None:
                    raise SchemaError("unexpected metric: {}".format(sub))
                if sub_value not in sub_spec["enum"]:
                    raise SchemaError("{}.{}={!r} not in {}".format(key, sub, sub_value, sub_spec["enum"]))
    return payload


def _context(raw: RawFinding) -> str:
    """Exactly what the model is allowed to see. Nothing else is in scope."""
    return json.dumps({
        "id": raw.id,
        "scanner": raw.scanner,
        "kind": raw.kind,
        "url": raw.url,
        "parameter": raw.parameter,
        "method": raw.method,
        "payload": raw.payload,
        "evidence": raw.evidence,
        "extra": raw.raw,
        "allowed_cwe_ids": sorted(cwe_catalogue().keys()),
        "schema": TRIAGE_SCHEMA,
    }, indent=2)



def _adds_information(catalogue: str, model_text: str, threshold: float = 0.4) -> bool:
    """True when the catalogue wording contributes something new.

    Compares significant words (4+ letters). If most of the catalogue sentence
    already appears in the model's remediation, prepending it only repeats.
    """
    import re as _re
    cat = set(_re.findall(r"[a-z]{4,}", catalogue.lower()))
    mod = set(_re.findall(r"[a-z]{4,}", model_text.lower()))
    if not cat:
        return False
    return len(cat - mod) / len(cat) >= threshold



def finalise_grounded(raw: RawFinding, triaged: TriagedFinding,
                      redact: bool = True) -> TriagedFinding:
    """Turn a raw triage entry into the version that ships.

    Runs the grounding checks, then leads with the CWE catalogue's remediation
    where it adds something the model did not say.

    This exists as a standalone function because two callers need it: the agent
    (grounding=True) and the web UI, which runs the model once with grounding
    off and applies this to a copy so it can show both views. Before it was
    shared, the same finding produced different remediation text depending on
    which entry point you came in through.
    """
    triaged = enforce(raw, triaged, redact=redact)
    entry = lookup_cwe(triaged.cwe_id) if triaged.cwe_id else None
    if entry and _adds_information(entry["remediation"], triaged.remediation):
        triaged.remediation = "{} {}".format(entry["remediation"], triaged.remediation).strip()
    return triaged


@dataclass
class TriageResult:
    findings: list[TriagedFinding] = field(default_factory=list)
    duplicates_removed: int = 0
    schema_retries: int = 0
    backend: str = ""

    @property
    def flagged(self) -> list[TriagedFinding]:
        return [f for f in self.findings if f.flags]

    def counts(self) -> dict[str, int]:
        out = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out


class TriageAgent:
    def __init__(self, backend: Backend | None = None, *, grounding: bool = True,
                 redact: bool = True, max_retries: int = 2) -> None:
        self.backend = backend or get_backend()
        self.grounding = grounding
        self.redact = redact
        self.max_retries = max_retries

    def _ask(self, raw: RawFinding) -> tuple[dict[str, Any], int]:
        """Ask, validate, and on a schema violation say what was wrong and retry."""
        user = _context(raw)
        retries = 0
        last_error = ""
        for attempt in range(self.max_retries + 1):
            prompt = user if attempt == 0 else (
                user + "\n\nYour previous answer was rejected: " + last_error +
                "\nReturn corrected JSON matching the schema exactly."
            )
            text = self.backend.complete_json(SYSTEM_PROMPT, prompt)
            try:
                payload = json.loads(text)
            except json.JSONDecodeError as exc:
                last_error = "not valid JSON ({})".format(exc.msg)
                retries += 1
                continue
            try:
                return validate(payload), retries
            except SchemaError as exc:
                last_error = str(exc)
                retries += 1
        raise SchemaError("model did not satisfy the schema after {} attempts: {}".format(
            self.max_retries + 1, last_error))

    def triage_one(self, raw: RawFinding, duplicates: list[str] | None = None) -> TriagedFinding:
        payload, retries = self._ask(raw)

        # The model chose metrics. Code builds the vector and computes the score,
        # so no score in this report was ever produced by a language model.
        vector = build_vector(payload["cvss_metrics"])
        score, severity = score_cvss(vector)

        entry = lookup_cwe(payload["cwe_id"])
        triaged = TriagedFinding(
            source_id=raw.id,
            title=payload["title"].strip(),
            cwe_id=payload["cwe_id"].upper(),
            cwe_name=(entry or {}).get("name", ""),
            cvss_vector=vector,
            cvss_score=score,
            severity=severity,
            summary=payload["summary"].strip(),
            reproduction=payload["reproduction"].strip(),
            remediation=payload["remediation"].strip(),
            duplicates=list(duplicates or []),
        )
        triaged._retries = retries  # type: ignore[attr-defined]

        if self.grounding:
            triaged = finalise_grounded(raw, triaged, redact=self.redact)
        else:
            triaged.flags = []
        return triaged

    def run(self, findings: list[RawFinding],
            progress: Callable[[int, int, RawFinding], None] | None = None) -> TriageResult:
        grouped = dedupe(findings)
        result = TriageResult(backend=self.backend.name,
                              duplicates_removed=len(findings) - len(grouped))
        for i, (raw, dupes) in enumerate(grouped, 1):
            if progress:
                progress(i, len(grouped), raw)
            triaged = self.triage_one(raw, dupes)
            result.schema_retries += getattr(triaged, "_retries", 0)
            result.findings.append(triaged)
        result.findings.sort(key=lambda f: -f.cvss_score)
        return result
