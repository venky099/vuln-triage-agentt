# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

A CLI + web app that turns scanner JSON into a pentest report, and an eval harness that
measures how often the model fabricates facts. The *point* of the project is the grounding
layer, not the report generation — README.md explains the reasoning at length and its
"Honesty note" and "Results" sections set the standard for how claims about the numbers
must be worded (the mock backend simulates hallucination; its numbers are not evidence
about real models).

## Commands

```bash
python -m triage.cli data/sample_scan.json                    # markdown to stdout
python -m triage.cli data/sample_scan.json -f html -o r.html  # HTML report
python -m triage.cli scan.json --backend ollama --no-grounding
vulntriage ...                                                # same, after `pip install -e .`

python evals/run_eval.py -n 50                                # mock backend
python evals/run_eval.py -n 20 --backend ollama               # needs `ollama serve`

pytest -q                                                     # 97 tests, no network
pytest tests/test_triage.py::test_invented_cve_is_caught -q   # one test
pytest -k grounding -q

uvicorn webui.app:app --reload --port 8000                    # web UI
```

Core CLI, tests and the mock eval need no dependencies and no API key. The web UI needs
`pip install -r requirements.txt` (fastapi/uvicorn/jinja2, plus httpx for `tests/test_webui.py`).

**CLI exit code 1 means a human is needed** — either a finding carries an ungrounded
claim, or a finding could not be triaged and is absent from the report (2 is an unreadable
scan). Don't "fix" a non-zero exit from a successful triage.

## Architecture

Pipeline: `parsers` → `tools.dedupe` → `agent` (ask/validate/retry) → `tools` (score, CWE)
→ `grounding` → `report`.

The invariant that everything else follows from: **the model is asked only for judgement;
every number and identifier in the output is produced or verified by code.**

- `triage/models.py` — `RawFinding` (scanner ground truth) and `TriagedFinding`, plus
  `TRIAGE_SCHEMA`, the form the model fills in. The schema deliberately has no
  `cvss_score` field and `additionalProperties: False`, so a model that states a score is
  rejected. No LLM imports here, on purpose — everything downstream is unit-testable
  without a model.
- `triage/agent.py` — `validate()` is a hand-rolled JSON Schema subset checker (no
  dependency); only the keywords `TRIAGE_SCHEMA` actually uses are implemented, and anything
  else raises `UnsupportedSchema`. That is deliberately *not* a `SchemaError`: a `SchemaError`
  is retried against the model, which is nonsense when the checker itself cannot evaluate the
  rule. Widening the schema means widening the checker. `_ask()` retries on a schema violation
  by telling the model what was wrong; `_complete()` retries the *network* with backoff on a
  separate budget, because a dropped connection says nothing about the model's answer. A
  finding that still fails lands in `TriageResult.errors` and the run continues — one blip
  must not discard findings already paid for. `_context()` defines *exactly* what
  the model may see — adding a field there widens what it can draw on, so it also widens
  what grounding must be able to trace.
- `triage/parsers.py` — one function per scanner, all landing on `RawFinding`.
  `detect_format()` keys on a field unique to each (`site`→zap, `hosts`→nmap,
  `issues`/`issue_events`→burp). The Burp parser carries the awkward cases: detail
  arrives as HTML and is stripped, `<host ip=...>` survives XML conversion as a dict,
  and the parameter is read out of Burp's own "The `x` parameter" phrasing — which is
  scan data, so it stays traceable, and a miss leaves the field empty rather than
  inventing a name. `webui/static/app.js` mirrors `detect_format()` for its format
  chip; the two have to move together.
- `triage/tools.py` — CVSS v3.1 arithmetic (`_roundup` follows Appendix A integer
  arithmetic, not `round()`), the CWE catalogue loader, and `dedupe` (keys on class +
  path-without-query + parameter).
- `triage/grounding.py` — `check()` returns violation strings; `enforce()` attaches them
  and redacts. Verification is lexical, in code, against the `RawFinding` corpus and the
  CWE catalogue — never by asking the model to check itself. Ungrounded text is replaced
  with a visible `[UNVERIFIED REFERENCE REMOVED]` marker rather than deleted; an ungrounded
  `cwe_id` is dropped to empty since it is a field, not prose.
- `triage/llm.py` — `Backend` subclasses; `get_backend()` resolves `LLM_BACKEND`, else
  auto-detects (`OPENAI_API_KEY` → openai, Ollama *with a model pulled* → ollama,
  else mock). An open port alone is not enough — `resolve_ollama_model()` also maps
  a bare `llama3.2` onto an installed `llama3.2:3b`, since Ollama itself only
  resolves bare names to `:latest`.
  `MockBackend` is a *deterministic simulation of a confident model*: it fabricates a CVE
  or an out-of-catalogue CWE on a seeded 1-in-3 subset keyed by finding id, so the eval is
  reproducible. Keep it deterministic — the tests and eval depend on the same findings
  failing every run.
- `webui/app.py` — runs the agent once with `grounding=False`, then applies
  `finalise_grounded()` to a deep copy, so the UI's ungrounded/grounded toggle costs one
  model pass, not two. `finalise_grounded()` lives in `agent.py` precisely because the CLI
  and the web UI both need identical post-processing.
- `webui/security.py` — payload/finding caps, per-client fixed-window rate limiter, and
  OpenAI key shape check. Two things the limiter has to get right: `_client()` in `app.py`
  counts `TRIAGE_PROXY_DEPTH` entries from the *right* of `X-Forwarded-For` (the leftmost is
  whatever the caller typed, and reading it made the limiter free to bypass), and eviction
  drops the clients with the fewest hits rather than clearing the table, so flooding it with
  new identities cannot buy anyone a reset. The key is per-request only: never logged, never persisted,
  never echoed — including in error messages, which is why the triage handler reports only
  `type(exc).__name__`.

### Data files

`data/cwe.json` is the only CWE source of truth: 16 entries, id → `{name, remediation}`.
A CWE outside it is rejected by design. Adding entries changes both what the model is
allowed to cite (the list is injected into its context) and what grounding accepts.

## Conventions

- No hard dependency for the core path — stdlib only in `triage/` (the `openai` import is
  inside `OpenAIBackend.__init__`). Reach for a library only if it is genuinely necessary.
- `.format()` string formatting throughout, not f-strings, in most modules.
- Comments explain *why* a decision was made, often citing the failure mode it prevents
  (see the URL check in `grounding.py`, or `VECTOR_IN_PROSE`). Match that register; a
  comment restating the code is out of place here.
- Tests run entirely against `MockBackend`. A change that requires network or an API key
  to test is the wrong change.
- `to_html()` escapes every interpolated field because `/api/render` accepts client-supplied
  JSON — keep it that way when editing the template.
