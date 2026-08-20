"""Measure how often the model invents facts, with grounding off and on.

    python evals/run_eval.py                 # 50 findings, auto-detected backend
    python evals/run_eval.py -n 100 --backend ollama

This is the part of the project that matters. Anyone can wire an LLM to a
report template. The question a security team will actually ask is "how often
does it make something up, and how do you know?" -- and that needs a number.

The findings are synthesised from a fixed seed so the run is reproducible.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from triage.agent import TriageAgent            # noqa: E402
from triage.grounding import check              # noqa: E402
from triage.llm import get_backend              # noqa: E402
from triage.models import RawFinding            # noqa: E402

KINDS = [
    ("SQL Injection", "id", "1' OR '1'='1",
     "Response length changed and a database error string appeared in the body."),
    ("Reflected XSS", "q", "<svg onload=alert(1)>",
     "Payload reflected unencoded inside the HTML body."),
    ("Cross-Site Request Forgery", "", "",
     "State-changing POST accepted with no anti-CSRF token present."),
    ("Insecure Direct Object Reference", "record_id", "record_id=3312",
     "Authenticated as one user; retrieved a record owned by another. No ownership check."),
    ("Verbose Error Message", "page", "page=abc",
     "Stack trace disclosed framework version and an absolute server file path."),
    ("Exposed service", "", "",
     "Service banner disclosed product name and version."),
]

PATHS = ["/product", "/search", "/account/email", "/invoice", "/api/v1/orders",
         "/admin/report", "/profile", "/cart", "/checkout", "/download"]


def synth(n: int, seed: int = 20260810) -> list[RawFinding]:
    rng = random.Random(seed)
    out = []
    for i in range(1, n + 1):
        kind, param, payload, evidence = KINDS[i % len(KINDS)]
        path = PATHS[rng.randrange(len(PATHS))]
        out.append(RawFinding(
            id="EV-{:03d}".format(i),
            scanner="VibeScanner",
            kind=kind,
            url="https://target.example{}".format(path),
            parameter=param,
            method="POST" if "Forgery" in kind else "GET",
            payload=payload,
            evidence=evidence,
        ))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", "--count", type=int, default=50)
    ap.add_argument("--backend", choices=["openai", "ollama", "mock"])
    ap.add_argument("--out", default="evals/results.json")
    args = ap.parse_args()

    backend = get_backend(args.backend)
    findings = synth(args.count)
    print("backend: {} | findings: {}\n".format(backend.name, len(findings)))

    # Both sides measure the SAME findings, one at a time. Deduplication is
    # deliberately not used here: it would change the denominator between the
    # two arms and make the comparison meaningless.
    off_agent = TriageAgent(backend=backend, grounding=False)
    on_agent = TriageAgent(backend=backend, grounding=True, redact=True)

    affected_before = 0
    before_violations = 0
    by_kind: dict[str, int] = {}
    leaked = 0
    flagged = 0
    retries = 0

    for raw in findings:
        # Arm A: no grounding. Count what would have shipped.
        unchecked = off_agent.triage_one(raw)
        flags = check(raw, unchecked)
        if flags:
            affected_before += 1
        before_violations += len(flags)
        for f in flags:
            key = f.split(":")[0]
            by_kind[key] = by_kind.get(key, 0) + 1

        # Arm B: grounding on. Re-check the text that would actually be published.
        published = on_agent.triage_one(raw)
        retries += getattr(published, "_retries", 0)
        if published.flags:
            flagged += 1
        if check(raw, published):
            leaked += 1

    pct = 100.0 * affected_before / len(findings)
    print("GROUNDING OFF")
    print("  findings containing an ungrounded claim : {}/{}  ({:.0f}%)".format(
        affected_before, len(findings), pct))
    print("  total violations                        : {}".format(before_violations))
    for k, v in sorted(by_kind.items(), key=lambda kv: -kv[1]):
        print("     {:<34} {}".format(k, v))
    print()
    print("GROUNDING ON")
    print("  findings flagged for review             : {}".format(flagged))
    print("  ungrounded claims surviving into text   : {}".format(leaked))
    print("  schema retries                          : {}".format(retries))
    print()
    print("RESULT: invented references reaching the report went from {} to {}."
          .format(affected_before, leaked))

    payload = {
        "backend": backend.name,
        "sample_size": len(findings),
        "grounding_off": {
            "findings_with_ungrounded_claims": affected_before,
            "total_violations": before_violations,
            "by_category": by_kind,
        },
        "grounding_on": {
            "findings_flagged": flagged,
            "ungrounded_claims_in_published_text": leaked,
            "schema_retries": retries,
        },
        "note": ("With the mock backend these numbers describe a simulated model and are "
                 "reproducible, not empirical. Run with --backend ollama or openai to measure "
                 "a real model."),
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print("wrote {}".format(args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
