# AI Vulnerability Triage Agent

Turns raw scanner output into a client-ready pentest report — and **measures how
often the model makes things up**, then stops it.

```
$ vulntriage data/sample_scan.json --target demo.vulnerable.example

Backend: mock | 6 findings in
  [1/5] VS-001 SQL Injection
  [2/5] VS-003 Reflected XSS
  ...

5 findings (1 duplicates merged) | 1 critical, 0 high, 4 medium, 0 low
2 finding(s) contain ungrounded claims and are flagged for review
```

Sample output: [`reports/sample_report.md`](reports/sample_report.md) ·
[HTML](reports/sample_report.html) · [JSON](reports/sample_report.json)

## The problem

A scanner tells you `window_kitchen open`. A client needs to be told *what broke,
how bad it is, and how to fix it*. Writing that up is most of the billable time on
an assessment, and it is the same shape every time — which makes it automatable.

The obvious approach is to hand the findings to an LLM. The obvious approach also
produces this:

> The `id` parameter is vulnerable to SQL injection. This corresponds to
> **CVE-2019-4471**.

That CVE does not exist. The model produced it because reports it has read
contain identifiers of that shape, and a plausible-looking one was the most
likely next token. It is not flagged as uncertain — it reads exactly like the
sentence before it, which is true.

Send that to a client, they look it up, and every other finding in the report
becomes suspect. **That single failure mode is why generated security reports
are not in wider use**, and it is what this project is actually about.

## How it works

```
scanner JSON  ->  dedupe  ->  LLM fills a fixed schema  ->  validate (retry on failure)
              ->  score computed from metrics BY CODE
              ->  CWE resolved against a local catalogue
              ->  grounding check on every remaining claim
              ->  report
```

Three design decisions do the work:

**1. The model fills in a form, never a blank page.** It returns JSON against a
fixed schema — title, CWE, eight CVSS metrics, summary, reproduction,
remediation. A schema violation is *detectable*, so the agent tells the model
what was wrong and asks again. Free-form prose has no such check.

**2. The model is never allowed to state a number.** It chooses CVSS *metrics*
(is confidentiality impact high? is user interaction required?) — judgement calls
a model is reasonable at. The **score is then computed in code** from CVSS v3.1
arithmetic. A model that is never asked for a number cannot invent one. The
schema explicitly rejects a `cvss_score` field if the model tries to supply one.

**3. Every claim must trace to a source, or it does not ship.** There are exactly
two sources of truth: the scanner's own output, and a local CWE catalogue.

| Check | Catches |
|---|---|
| CVE citations | An identifier not present anywhere in the scan data |
| CWE identifiers | A CWE that is not in the catalogue |
| CVSS score | A number that does not follow from the vector |
| Score in prose | Prose disagreeing with the computed score |
| URLs | An endpoint the scanner never touched |
| Impact language | "remote code execution", "full compromise" — claims a single scanner finding cannot support |

Ungrounded claims are **redacted and flagged**, not silently deleted:

```
Input supplied in q is reflected into the response without encoding.
This corresponds to [UNVERIFIED REFERENCE REMOVED].

⚠ Needs review before sending:
  - invented CVE reference: CVE-2019-3253
```

The reviewer sees that something was removed and why. A defence whose failure
mode is invisible is worse than none.

**Note that verification happens in code, not by asking the model to check
itself.** A model that hallucinated a CVE will confirm the CVE is real when
asked — the same process produced both answers.

## Results

`python evals/run_eval.py -n 50` — 50 findings, each run twice, grounding off
then on. Both arms measure the same set:

```
GROUNDING OFF
  findings containing an ungrounded claim : 9/50  (18%)
     invented CVE reference             5
     CWE not in catalogue               4

GROUNDING ON
  findings flagged for review            : 9
  ungrounded claims surviving into text  : 0

RESULT: invented references reaching the report went from 9 to 0.
```

**These particular numbers come from the mock backend and are reproducible, not
empirical.** See the honesty note below.

## Install and run

```bash
git clone https://github.com/<you>/vuln-triage-agent
cd vuln-triage-agent
python -m venv .venv && .venv\Scripts\activate     # Windows
# source .venv/bin/activate                         # macOS / Linux

python -m triage.cli data/sample_scan.json                    # markdown to stdout
python -m triage.cli data/sample_scan.json -f html -o r.html  # styled HTML report
python evals/run_eval.py -n 50                                # the measurement
pytest -q                                                     # 41 tests
```

No API key and no dependencies are needed for any of the above.

Exit code is **1 when any finding carries an ungrounded claim**, so it can gate a
pipeline: a report nobody has reviewed never ships automatically.

### Backends

| Backend | Setup |
|---|---|
| `mock` | none — the default |
| `ollama` | `ollama serve`, then `LLM_BACKEND=ollama` |
| `openai` | `pip install openai`, set `OPENAI_API_KEY`, then `LLM_BACKEND=openai` |

### Input formats

VibeScanner JSON (primary), OWASP ZAP, and Nmap. Detected automatically; override
with `--input-format`.

## Honesty note about the mock backend

The default backend is **a simulation of a confident model, not a language
model.** It fills the schema competently and, on a fixed seeded subset, does what
real models do when pressed to sound authoritative: cites a CVE that does not
exist, or a CWE outside the catalogue.

That makes the mechanism reproducible and the grounding layer testable with zero
setup. **It is not evidence about how any real model behaves.** Every number in
the Results section above is a property of the simulation.

The grounding checks, the CVSS arithmetic, the schema validation and the
redaction are all real code operating on real text — only the model is simulated.
Run `python evals/run_eval.py --backend ollama` and publish those numbers before
making any claim about real-world hallucination rates.

## Limitations

- The CWE catalogue is 16 entries covering common web classes, not the full list.
  A legitimate CWE outside it is rejected — a false positive by design, on the
  principle that a missing citation beats a wrong one.
- Grounding is lexical, not semantic. A claim that is subtly wrong but uses only
  words present in the scan data will pass.
- Impact overclaiming is pattern-matched against a fixed phrase list; a novel
  phrasing gets through.
- Deduplication keys on bug class plus endpoint plus parameter. Two genuinely
  distinct bugs of the same class on one endpoint would be merged.
- The eval's findings are synthetic. Real scanner output is messier.

## Layout

```
triage/models.py      dataclasses + the output schema
triage/tools.py       CVSS v3.1 scorer, CWE catalogue, dedupe
triage/parsers.py     VibeScanner / ZAP / Nmap -> RawFinding
triage/llm.py         openai | ollama | mock backends
triage/agent.py       the loop: ask, validate, retry, compute, ground
triage/grounding.py   the checks, and redaction
triage/report.py      markdown / HTML / JSON
evals/run_eval.py     hallucination measurement
tests/                41 tests, no network needed
```

## Related

[VibeScanner](https://vibescanner.onrender.com) finds the bugs this triages —
scanner output goes straight in as input.

[Indirect Prompt Injection Lab](https://github.com/<you>/rag-injection-lab) —
the other side of the same coin. There, untrusted text reaches a model and it
obeys. Here, a model produces untrusted text and something downstream believes
it. Both are the same lesson: **a language model is not a source of truth, and
whatever consumes its output has to act like it.**
