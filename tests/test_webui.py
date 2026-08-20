"""Tests for the web UI: the toggle contract, input guards, and key handling.

Uses FastAPI's TestClient, so no server and no network.

Run: pytest -q
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

fastapi = pytest.importorskip("fastapi", reason="web extra not installed")
from fastapi.testclient import TestClient                       # noqa: E402

from webui.app import app                                       # noqa: E402
from webui.security import (                                    # noqa: E402
    MAX_SCAN_BYTES, RateLimiter, Rejected, cap_findings,
    validate_api_key, validate_scan,
)

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = (ROOT / "data" / "sample_scan.json").read_text(encoding="utf-8")

client = TestClient(app)


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """The limiter is module-level and shared, so without this the suite
    exhausts its own quota and later tests fail with 429 depending on order."""
    from webui.app import limiter
    limiter._hits.clear()
    yield
    limiter._hits.clear()


def triage(scan=SAMPLE, backend="mock", api_key=None):
    return client.post("/api/triage",
                       json={"scan": scan, "backend": backend, "api_key": api_key})


# --------------------------- pages and static ---------------------------

def test_index_renders():
    r = client.get("/")
    assert r.status_code == 200
    assert "Grounding checks" in r.text


def test_health():
    body = client.get("/api/health").json()
    assert body["ok"] is True
    assert body["version"]


def test_html_report_escapes_client_supplied_fields():
    """Regression: /api/render accepts a client-built result, so severity,
    score and cwe_id are attacker-controlled and must not reach the HTML raw."""
    import re as _re
    from triage.agent import TriageResult
    from triage.models import TriagedFinding
    from triage.report import to_html
    evil = TriagedFinding(
        source_id="X", title="t", cwe_id='CWE-1"><script>alert(1)</script>',
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_score="<img src=x onerror=alert(1)>", severity="Critical",
        summary="s", reproduction="r", remediation="m")
    out = to_html(TriageResult(findings=[evil]))
    assert not _re.search(r"<(script|img)", out)
    assert "&lt;script&gt;" in out


def test_example_endpoint_serves_the_sample():
    body = client.get("/api/example").json()
    assert len(body["findings"]) == 6


# --------------------------- the toggle contract ---------------------------

def test_triage_returns_both_views():
    body = triage().json()
    assert body["ok"] is True
    assert len(body["ungrounded"]) == len(body["grounded"]) > 0
    assert body["duplicatesRemoved"] == 1          # the two SQLi findings merge


def test_views_differ_exactly_where_claims_were_ungrounded():
    """The demo depends on this: same findings, different text."""
    body = triage().json()
    ung = {f["source_id"]: f for f in body["ungrounded"]}
    gr = {f["source_id"]: f for f in body["grounded"]}
    assert ung.keys() == gr.keys()

    changed = [k for k in gr if gr[k]["summary"] != ung[k]["summary"]
               or gr[k]["cwe_id"] != ung[k]["cwe_id"]]
    assert changed, "grounding should have altered at least one finding"
    assert body["flaggedCount"] == len(changed)

    for k in gr:
        if not gr[k]["flags"]:
            # untouched findings must be byte-identical across both views
            assert gr[k]["summary"] == ung[k]["summary"]


PROSE = ("title", "summary", "reproduction", "remediation")


def _prose(findings) -> str:
    """Only the fields that end up in the report body.

    The flag messages deliberately name the removed reference -- a reviewer has
    to know which claim was pulled -- so they are not part of this check.
    """
    return " ".join(f[k] for f in findings for k in PROSE)


def test_fabricated_cve_present_ungrounded_and_gone_grounded():
    body = triage().json()
    assert "CVE-2019-3253" in _prose(body["ungrounded"])
    assert "CVE-2019-3253" not in _prose(body["grounded"])
    assert "UNVERIFIED REFERENCE REMOVED" in _prose(body["grounded"])


def test_flag_message_still_names_the_removed_reference():
    """Redaction hides the claim from the report, not from the reviewer."""
    body = triage().json()
    flags = [x for f in body["grounded"] for x in f["flags"]]
    assert any("CVE-2019-3253" in x for x in flags)


def test_scores_are_consistent_across_both_views():
    from triage.tools import score_cvss
    body = triage().json()
    for view in ("ungrounded", "grounded"):
        for f in body[view]:
            assert f["cvss_score"] == score_cvss(f["cvss_vector"])[0]


# --------------------------- input guards ---------------------------

@pytest.mark.parametrize("scan,fragment", [
    ("", "Paste a scan"),
    ("{not json", "Invalid JSON"),
    ('{"findings": []}', "No findings"),
])
def test_bad_input_rejected(scan, fragment):
    r = triage(scan=scan)
    assert r.status_code == 400
    assert fragment in r.json()["error"]


def test_finding_cap_enforced():
    many = json.dumps({"findings": [
        {"id": "x%d" % i, "type": "SQL Injection", "url": "https://t/%d" % i,
         "parameter": "id", "evidence": "e"} for i in range(80)]})
    r = triage(scan=many)
    assert r.status_code == 400
    assert "caps at" in r.json()["error"]


def test_oversized_scan_gets_a_useful_message():
    """Regression: pydantic's max_length must not pre-empt validate_scan()."""
    big = json.dumps({"findings": [{"id": "x", "type": "SQL Injection",
                                    "evidence": "e" * (MAX_SCAN_BYTES + 5000)}]})
    r = triage(scan=big)
    assert r.status_code == 400
    assert "limit is" in r.json()["error"]


def test_unknown_backend_rejected():
    r = client.post("/api/triage", json={"scan": SAMPLE, "backend": "evil"})
    assert r.status_code == 422


# --------------------------- API key handling ---------------------------

def test_openai_requires_a_key():
    r = triage(backend="openai", api_key=None)
    assert r.status_code == 400
    assert "your own OpenAI key" in r.json()["error"]


def test_malformed_key_rejected_before_any_network_call():
    r = triage(backend="openai", api_key="not-a-key")
    assert r.status_code == 400
    assert "does not look like" in r.json()["error"]


def test_key_never_appears_in_any_response():
    """Errors are the usual place secrets leak. They must not here."""
    key = "sk-" + "A" * 40
    r = triage(backend="openai", api_key=key)
    assert key not in r.text
    assert "sk-" not in r.text


def test_validate_api_key_shape():
    assert validate_api_key(None) is None
    assert validate_api_key("   ") is None
    assert validate_api_key("sk-" + "b" * 30) == "sk-" + "b" * 30
    for bad in ["hello", "sk-short", "x" * 400]:
        with pytest.raises(Rejected):
            validate_api_key(bad)


# --------------------------- render / download ---------------------------

@pytest.mark.parametrize("fmt,marker", [
    ("markdown", "# Vulnerability Assessment Report"),
    ("html", "<!doctype html>"),
    ("json", '"findings"'),
])
def test_render_formats(fmt, marker):
    payload = triage().json()
    r = client.post("/api/render", json={"payload": payload, "format": fmt})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and marker in body["body"]


def test_render_rejects_malformed_payload():
    r = client.post("/api/render", json={"payload": {"grounded": [{"nope": 1}]},
                                         "format": "markdown"})
    assert r.status_code == 400


# --------------------------- rate limiting ---------------------------

def test_rate_limiter_blocks_then_is_per_client():
    rl = RateLimiter(max_calls=3, window_seconds=60)
    for _ in range(3):
        rl.check("1.1.1.1")
    with pytest.raises(Rejected, match="Rate limit"):
        rl.check("1.1.1.1")
    rl.check("2.2.2.2")          # a different client is unaffected


def test_cap_findings_helper():
    cap_findings(1)
    with pytest.raises(Rejected):
        cap_findings(10_000)


def test_validate_scan_accepts_normal_input():
    assert validate_scan(SAMPLE) == SAMPLE
