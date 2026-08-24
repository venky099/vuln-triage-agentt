"""Tests for scoring, schema validation, grounding and the triage loop.

Everything runs against the mock backend: no API key, no network, no model.

Run: pytest -q
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from triage.agent import (                                       # noqa: E402
    SchemaError, TriageAgent, UnsupportedSchema, validate,
)
from triage.grounding import check, enforce                      # noqa: E402
from triage.llm import MockBackend, resolve_ollama_model         # noqa: E402
from triage.models import RawFinding, TriagedFinding             # noqa: E402
from triage.parsers import detect_format, load, parse_zap        # noqa: E402
from triage.tools import (                                       # noqa: E402
    build_vector, dedupe, lookup_cwe, score_cvss, severity_of,
)

ROOT = Path(__file__).resolve().parents[1]


def raw(**kw) -> RawFinding:
    base = dict(id="T-1", scanner="VibeScanner", kind="SQL Injection",
                url="https://target.example/product?id=1", parameter="id",
                method="GET", payload="1' OR '1'='1",
                evidence="Database error string present in the response body.")
    base.update(kw)
    return RawFinding(**base)


# --------------------------- CVSS: the numbers must be right ---------------------------

@pytest.mark.parametrize("vector,expected,rating", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "Medium"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 4.3, "Medium"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", 6.5, "Medium"),
    ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0, "None"),
])
def test_cvss_matches_published_scores(vector, expected, rating):
    """Checked against the official CVSS v3.1 calculator."""
    score, sev = score_cvss(vector)
    assert score == expected
    assert sev == rating


def test_cvss_rejects_malformed_vector():
    for bad in ["", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "AV:N/AC:L", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"]:
        with pytest.raises(ValueError):
            score_cvss(bad)


def test_severity_boundaries():
    assert severity_of(0.0) == "None"
    assert severity_of(3.9) == "Low"
    assert severity_of(4.0) == "Medium"
    assert severity_of(6.9) == "Medium"
    assert severity_of(7.0) == "High"
    assert severity_of(8.9) == "High"
    assert severity_of(9.0) == "Critical"


def test_build_vector_roundtrips():
    metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
               "C": "H", "I": "H", "A": "H"}
    assert score_cvss(build_vector(metrics))[0] == 9.8


# --------------------------- CWE catalogue ---------------------------

def test_known_cwe_resolves():
    assert lookup_cwe("CWE-89")["name"] == "SQL Injection"
    assert lookup_cwe("cwe-89")["name"] == "SQL Injection"


def test_unknown_cwe_returns_none():
    assert lookup_cwe("CWE-9999") is None
    assert lookup_cwe("") is None


# --------------------------- dedupe ---------------------------

def test_dedupe_merges_same_bug_on_same_endpoint():
    findings = [
        raw(id="A", url="https://t.example/p?id=1"),
        raw(id="B", url="https://t.example/p?id=7"),      # same endpoint, different value
        raw(id="C", url="https://t.example/other", parameter="q", kind="Reflected XSS"),
    ]
    grouped = dedupe(findings)
    assert len(grouped) == 2
    kept, absorbed = grouped[0]
    assert kept.id == "A" and absorbed == ["B"]


def test_dedupe_keeps_different_parameters_apart():
    findings = [raw(id="A", parameter="id"), raw(id="B", parameter="name")]
    assert len(dedupe(findings)) == 2


# --------------------------- schema validation ---------------------------

def good_payload(**over):
    p = {
        "title": "SQL Injection in the id parameter",
        "cwe_id": "CWE-89",
        "cvss_metrics": {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                         "S": "U", "C": "H", "I": "H", "A": "H"},
        "summary": "The id parameter is concatenated into a SQL query.",
        "reproduction": "Send id=1' OR '1'='1 and compare.",
        "remediation": "Use parameterised queries so input is never parsed as SQL.",
    }
    p.update(over)
    return p


def test_valid_payload_passes():
    assert validate(good_payload()) is not None


@pytest.mark.parametrize("mutation", [
    {"cwe_id": "89"},                       # wrong shape
    {"cwe_id": "CWE-ABC"},
    {"title": "short"},                     # below minLength
    {"cvss_metrics": {"AV": "N"}},          # missing metrics
])
def test_bad_payloads_rejected(mutation):
    with pytest.raises(SchemaError):
        validate(good_payload(**mutation))


def test_unexpected_field_rejected():
    payload = good_payload()
    payload["cvss_score"] = 9.8             # the model must never supply a score
    with pytest.raises(SchemaError):
        validate(payload)


def test_invalid_metric_value_rejected():
    payload = good_payload()
    payload["cvss_metrics"]["AV"] = "Z"
    with pytest.raises(SchemaError):
        validate(payload)


# --------------------------- grounding: the lie detector ---------------------------

def triaged(**over) -> TriagedFinding:
    base = dict(source_id="T-1", title="SQL Injection in id",
                cwe_id="CWE-89", cwe_name="SQL Injection",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cvss_score=9.8, severity="Critical",
                summary="The id parameter is concatenated into a SQL query.",
                reproduction="Send a crafted id value.",
                remediation="Use parameterised queries.")
    base.update(over)
    return TriagedFinding(**base)


def test_clean_finding_has_no_flags():
    assert check(raw(), triaged()) == []


def test_invented_cve_is_caught():
    t = triaged(summary="This matches CVE-2019-4471 in the upstream library.")
    flags = check(raw(), t)
    assert any("invented CVE" in f for f in flags)


def test_cve_present_in_scan_data_is_allowed():
    """Grounding blocks *invented* references, not real ones."""
    r = raw(evidence="Banner disclosed a version affected by CVE-2021-44228.")
    t = triaged(summary="The exposed service is affected by CVE-2021-44228.")
    assert not any("invented CVE" in f for f in check(r, t))


def test_cwe_outside_catalogue_is_caught():
    flags = check(raw(), triaged(cwe_id="CWE-781"))
    assert any("CWE not in catalogue" in f for f in flags)


def test_score_that_does_not_follow_from_vector_is_caught():
    flags = check(raw(), triaged(cvss_score=4.0))
    assert any("does not follow from vector" in f for f in flags)


def test_score_stated_in_prose_must_match():
    flags = check(raw(), triaged(summary="Severity is high, CVSS score of 4.2 overall."))
    assert any("does not match computed" in f for f in flags)


def test_url_not_in_scan_is_caught():
    t = triaged(reproduction="Also reachable at https://unrelated.example/admin.")
    assert any("URL not present in scan data" in f for f in check(raw(), t))


def test_url_from_the_scan_is_allowed():
    t = triaged(reproduction="Request https://target.example/product?id=1 again.")
    assert not any("URL not present" in f for f in check(raw(), t))


@pytest.mark.parametrize("repro", [
    "Request https://target.example/product?id=<payload> and compare.",   # extra query
    "Request https://target.example/product again.",                      # no query
    "Request https://target.example/product/ again.",                     # trailing slash
    "Request https://TARGET.example/product?id=1 again.",                 # host case
])
def test_same_endpoint_different_query_is_not_a_fabrication(repro):
    """Regression, found by running a real model.

    A correct reproduction step appends the parameter under test. Comparing
    whole URLs flagged that as invented -- 5 of 12 findings in an Ollama run,
    every one a false positive. Endpoints are compared without the query now.
    """
    assert not any("URL not present" in f for f in check(raw(), triaged(reproduction=repro)))


@pytest.mark.parametrize("repro", [
    "Also reachable at https://target.example/secret/backup.zip",   # invented path
    "See https://evil.example/product?id=1",                        # different host
])
def test_invented_endpoint_is_still_caught(repro):
    assert any("URL not present" in f for f in check(raw(), triaged(reproduction=repro)))


def test_unsupported_impact_claim_is_caught():
    t = triaged(summary="This allows remote code execution on the host.")
    assert any("unsupported impact claim" in f for f in check(raw(), t))


def test_malformed_vector_is_caught():
    assert any("malformed CVSS vector" in f
               for f in check(raw(), triaged(cvss_vector="CVSS:3.1/AV:N")))


# --------------------------- enforcement ---------------------------

def test_enforce_redacts_invented_cve_from_prose():
    t = enforce(raw(), triaged(summary="Matches CVE-2019-4471 upstream."))
    assert "CVE-2019-4471" not in t.summary
    assert "UNVERIFIED REFERENCE REMOVED" in t.summary
    assert t.flags and not t.grounded


def test_enforce_drops_ungrounded_cwe_rather_than_citing_it():
    t = enforce(raw(), triaged(cwe_id="CWE-781", cwe_name="Invented"))
    assert t.cwe_id == "" and t.cwe_name == ""


def test_enforce_leaves_clean_findings_untouched():
    original = triaged()
    result = enforce(raw(), triaged())
    assert result.summary == original.summary
    assert result.grounded


# --------------------------- the agent end to end ---------------------------

@pytest.fixture(scope="module")
def agent() -> TriageAgent:
    return TriageAgent(backend=MockBackend())


def test_agent_produces_a_grounded_finding(agent):
    out = agent.triage_one(raw(id="CLEAN-2"))
    assert out.cvss_score > 0
    assert out.severity in ("Critical", "High", "Medium", "Low", "None")
    assert out.cvss_vector.startswith("CVSS:3.1/")


def test_score_is_computed_not_taken_from_the_model(agent):
    """The whole point: the number in the report is arithmetic, not generation."""
    out = agent.triage_one(raw(id="CLEAN-2"))
    recomputed, rating = score_cvss(out.cvss_vector)
    assert out.cvss_score == recomputed
    assert out.severity == rating


def test_agent_flags_the_hallucinated_findings(agent):
    findings = [raw(id="EV-{:03d}".format(i)) for i in range(1, 31)]
    result = agent.run(findings)
    # dedupe collapses identical findings; at least one flagged entry must survive
    assert result.findings
    assert all(f.cvss_score == score_cvss(f.cvss_vector)[0] for f in result.findings)


def test_grounding_disabled_lets_claims_through():
    loose = TriageAgent(backend=MockBackend(), grounding=False)
    strict = TriageAgent(backend=MockBackend(), grounding=True)
    dirty = [r for r in (raw(id="EV-{:03d}".format(i)) for i in range(1, 40))
             if check(r, loose.triage_one(r))]
    assert dirty, "expected the mock to fabricate on at least one finding"
    for r in dirty:
        assert loose.triage_one(r).flags == []       # not checked
        assert strict.triage_one(r).flags != []      # caught


def test_dedupe_reported_in_result(agent):
    findings = [raw(id="A"), raw(id="B"), raw(id="C", parameter="other")]
    result = agent.run(findings)
    assert result.duplicates_removed == 1
    assert len(result.findings) == 2


# --------------------------- parsers ---------------------------

def test_sample_scan_parses():
    findings = load(ROOT / "data" / "sample_scan.json")
    assert len(findings) == 6
    assert findings[0].scanner == "VibeScanner"


def test_format_detection():
    assert detect_format({"site": []}) == "zap"
    assert detect_format({"hosts": []}) == "nmap"
    assert detect_format({"findings": []}) == "vibescanner"


def test_zap_parser():
    data = {"site": [{"alerts": [{"alert": "Reflected XSS", "confidence": "High",
                                  "instances": [{"uri": "https://t.example/s",
                                                 "param": "q", "method": "GET",
                                                 "attack": "<svg>", "evidence": "<svg>"}]}]}]}
    out = parse_zap(data)
    assert len(out) == 1 and out[0].scanner == "OWASP ZAP" and out[0].parameter == "q"


def test_empty_scan_is_an_error(tmp_path):
    p = tmp_path / "empty.json"
    p.write_text(json.dumps({"findings": []}), encoding="utf-8")
    with pytest.raises(ValueError):
        load(p)


# --------------------------- Ollama model resolution ---------------------------
#
# Ollama resolves a bare name only to `:latest`, so a machine holding
# `llama3.2:3b` answers 404 for `llama3.2`. These cover the mapping that turns
# that into a non-event, and the None that stops auto-detection pretending a
# backend is usable when it is not.

def test_bare_name_matches_a_tagged_model():
    assert resolve_ollama_model("llama3.2", ["llama3.2:3b"]) == "llama3.2:3b"


def test_exact_name_wins_over_prefix():
    assert resolve_ollama_model("llama3.2:1b", ["llama3.2:3b", "llama3.2:1b"]) == "llama3.2:1b"


def test_empty_name_takes_whatever_is_installed():
    assert resolve_ollama_model("", ["mistral:7b"]) == "mistral:7b"
    assert resolve_ollama_model(None, ["mistral:7b"]) == "mistral:7b"


def test_unknown_model_does_not_resolve():
    assert resolve_ollama_model("nope", ["llama3.2:3b"]) is None


def test_nothing_installed_never_resolves():
    assert resolve_ollama_model("llama3.2", []) is None
    assert resolve_ollama_model("", []) is None


# --------------------------- resilience: the network is not the model ---------------------------
#
# complete_json() used to sit outside the try in _ask(), so one dropped
# connection on finding 45 of 50 discarded the 44 already paid for.

class _Blip(MockBackend):
    """Fails on the Nth call, then behaves."""
    name = "blip"

    def __init__(self, fail_on, times=1):
        self.n = 0
        self.fail_on = fail_on
        self.times = times

    def complete_json(self, system, user):
        self.n += 1
        if self.fail_on <= self.n < self.fail_on + self.times:
            raise ConnectionError("connection reset by peer")
        return super().complete_json(system, user)


def _findings(n):
    return [RawFinding(id="R-{}".format(i), scanner="s", kind="SQL Injection",
                       url="https://t.example/p{}".format(i), parameter="id",
                       evidence="database error in the response body")
            for i in range(1, n + 1)]


def test_transient_failure_is_retried_not_fatal():
    result = TriageAgent(backend=_Blip(fail_on=3), backoff=0).run(_findings(5))
    assert len(result.findings) == 5
    assert result.errors == []


def test_network_retry_does_not_spend_the_schema_budget():
    """A dropped connection says nothing about the model's ability to fill the form."""
    result = TriageAgent(backend=_Blip(fail_on=2), backoff=0).run(_findings(3))
    assert result.schema_retries == 0


def test_unrecoverable_finding_does_not_discard_the_others():
    # net_retries=2 means three attempts per finding, so failing calls 3-5
    # exhausts R-3 exactly and leaves R-4 onward with a working connection.
    agent = TriageAgent(backend=_Blip(fail_on=3, times=3), backoff=0)
    result = agent.run(_findings(5))
    assert [f.source_id for f in result.findings] == ["R-1", "R-2", "R-4", "R-5"]
    assert len(result.errors) == 1
    assert result.errors[0][0] == "R-3"
    assert "ConnectionError" in result.errors[0][1]


# --------------------------- validate() must not pass what it cannot check ---------------------------

def test_unimplemented_schema_type_raises_rather_than_passing():
    """The docstring promises no silent pass; this is what enforces it."""
    import copy as _copy
    from triage import models as _models
    original = _copy.deepcopy(_models.TRIAGE_SCHEMA["properties"])
    _models.TRIAGE_SCHEMA["properties"]["title"] = {"type": "integer", "minimum": 5}
    try:
        with pytest.raises(UnsupportedSchema):
            validate(_valid_payload())
    finally:
        _models.TRIAGE_SCHEMA["properties"] = original


def test_unsupported_schema_is_not_a_schema_error():
    """SchemaError is retried against the model; this must not be, so it is a
    separate type. Nothing the model returns can satisfy an uncheckable rule."""
    assert not issubclass(UnsupportedSchema, SchemaError)


def _valid_payload():
    return {
        "title": "SQL Injection in id at https://t.example/p",
        "cwe_id": "CWE-89",
        "cvss_metrics": {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                         "S": "U", "C": "H", "I": "H", "A": "H"},
        "summary": "s" * 40,
        "reproduction": "r" * 30,
        "remediation": "m" * 40,
    }
