# AI Vulnerability Triage Agent

[![tests](https://github.com/venky099/vuln-triage-agent/actions/workflows/tests.yml/badge.svg)](https://github.com/venky099/vuln-triage-agent/actions/workflows/tests.yml)

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

<details>
<summary><b>New to this? The whole idea, in plain language</b> — no security background needed</summary>

<br>

**In one sentence:** a model writes the security report, and a second, much dumber
piece of code checks every fact it wrote and crosses out anything it cannot prove.

### What a scanner is

Imagine a robot that walks around your house at night testing things, and comes back
with a list:

```
kitchen window  - unlocked
back door       - lock is broken
garage keypad   - shows the code as you type it
```

That is a vulnerability scanner, except for websites. It finds problems, but describes
them in robot-speak: `param id vulnerable to SQLi, payload 1' OR '1'='1`.

### The existing problem

A robot list is useless to the person who has to fix things. What they need is:

> **The kitchen window does not lock.** Anyone in the back alley can push it open in
> about two seconds and climb in. This is serious — 8 out of 10. Replace the latch
> with a keyed model; about £15.

Writing *that*, for every item, for every client, is where most of the billable time
on an assessment goes. It is slow, it is the same shape every time, and that makes it
a job for a computer.

### Why the obvious fix explodes

Hand the list to an LLM and say "write this up." It does — beautifully. And then,
somewhere in the middle, it writes:

> The `id` parameter is vulnerable to SQL injection. **This corresponds to CVE-2019-4471.**

`CVE-2019-4471` is an official worldwide ID for a known bug, like an ISBN for a book.
**It does not exist.** The model invented it.

A model does not *know* things; it is an extremely good guesser of the next word. It
has read millions of security reports, and in those, "this corresponds to…" is nearly
always followed by `CVE-` and eight digits. So it produces some. That is not lying —
lying requires knowing the truth.

**The analogy:** a kid who skimmed the book writes *"as the author says on page 94,
'the river remembers everything.'"* There is no page 94 quote. But the sentence sounds
exactly like every real book report they have read, so out it comes — in the same
confident voice as all the true sentences around it. **The invented sentence looks
identical to the real ones.** No wobble in the handwriting, no "um."

And that is the real damage: the client googles the CVE, finds nothing, and now
distrusts the *entire* report — because they have no way to tell which other parts
were invented. One fake fact poisons fifty true ones.

### The proposed solution: three rules

**Rule 1 — a form to fill in, never a blank page.** The model gets fixed boxes: title,
bug type, summary, how to repeat it, how to fix it. A blank sheet lets a kid write
fiction; a form with labelled boxes does not — and if they scribble outside the boxes,
**you can see it immediately.** Free-form prose gives you nothing to check against.
When the form comes back wrong, the program says exactly what was wrong and asks again.

**Rule 2 — the model is never allowed to say a number.** Every bug gets a danger score
out of 10. The model never states it. It only answers questions it is genuinely good
at — can this be attacked over the internet? does the victim have to click something?
could private data be read? — and then **code does the arithmetic** and gets `9.8`.
Like a teacher who never asks "what grade do you deserve?" but asks "did you hand in
all six assignments?" and works it out. A model never asked for a number cannot invent
one. The form does not even have a box for it.

**Rule 3 — every fact must trace to a source, or it is struck out.** Exactly two things
are allowed to be true: what the scanner actually saw, and a local list of 16 known bug
types. Anything else the model asserts is treated as invented — a CVE that appears
nowhere in the scan, a bug type not on the list, a web address the scanner never
visited, a score that disagrees with the maths, or a scary phrase like "full system
compromise" that one scanner finding cannot possibly prove.

Struck out **visibly**, not quietly deleted:

```
This corresponds to [UNVERIFIED REFERENCE REMOVED].

⚠ invented CVE reference: CVE-2019-3253
```

A teacher who silently erases the fake quote teaches nobody anything, and the report
still *looks* perfect. Red pen and a note means everyone can see something was wrong.
**A safety net you cannot see is worse than none**, because it stops you looking.

### The cleverest part

Why not just ask the model "are you sure that CVE is real?"

**Because it will say yes.** The same guessing machine that produced the fake code will
produce a confident confirmation — it is the same process running twice. Asking a kid
to proofread their own invented quote gets you the quote plus a signature. So all the
checking happens in plain, boring, non-AI code, against data the model cannot influence.
Dumb code that can only look things up beats smart code that can imagine things.

### The honest failure, which is the most useful part

A small local model took a plain database bug, called it a completely different kind of
bug, and scored it 6.0 when it should have been about 9.8 — and **every check passed,
correctly.** Nothing was invented. The bug type it named is real and on the list. The
score genuinely follows from the answers it gave. It simply gave the wrong answers:
well-formed, traceable, checkable, and wrong.

**Grounding catches invention, not incompetence.** You can build a machine that catches
a kid quoting a page that does not exist. You cannot build that same machine to catch a
kid who quotes a real page and misunderstood it. That needs a second reader, a rule, or
a human. This project does not close that gap and does not pretend to.

### One finding, start to finish

```
1. Scanner says     : /product, parameter "id", payload "1' OR '1'='1",
                      evidence "database error appeared in the response"
2. Dedupe           : it tested ?id=1 and ?id=2 and reported both -> merged into one
3. Model fills form : CWE-89 - internet-reachable, no login needed, reads private data
                      "...This corresponds to CVE-2019-4471."
4. Code does maths  : 9.8 Critical            <- the model never touched this number
5. Code checks facts: "CVE-2019-4471" searched in the scanner's notes -> not there
6. Struck out+flagged: "[UNVERIFIED REFERENCE REMOVED]"
                       ⚠ invented CVE reference: CVE-2019-4471
7. Exit code 1      : a pipeline will not send this report until a human has looked
```

### The whole thing in a paragraph

**A model can be a good judge but must never be a source of facts.** So it does the
judging — how bad is this, how would you explain it — and everything else is taken away
from it: numbers are computed by arithmetic, identifiers are looked up in a fixed list,
and every remaining sentence is checked against what the scanner actually saw. What
cannot be traced is struck out in red rather than quietly removed, and the report is
held back until a person signs off. The goal is not "make the model more accurate." It
is **assume it will make things up, and build everything downstream so that when it
does, you find out.**

</details>

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

Two measurements, and they say different things.

### Against a simulated adversarial model

`python evals/run_eval.py -n 50` uses the mock backend, which fabricates a
reference on a fixed subset of findings so the checks have something to catch:

```
GROUNDING OFF   9/50 findings carried an ungrounded claim  (18%)
                  invented CVE reference   5
                  CWE not in catalogue     4
GROUNDING ON    0 surviving into the report
```

**These numbers describe the simulation, not a language model.** They demonstrate
that the checks work when fabrication occurs. They say nothing about how often it
occurs.

### Against a real model

`python evals/run_eval.py -n 20 --backend ollama` with **llama3.2:3b**:

```
GROUNDING OFF   0/20 findings carried an ungrounded claim  (0%)
GROUNDING ON    0 flagged, 0 surviving
schema retries  0
```

**It fabricated nothing.** No invented CVEs, no CWEs outside the catalogue, no
URLs it had not been given, and it satisfied the output schema on every single
attempt without a retry.

The most likely reason is that fabrication was prevented upstream rather than
caught downstream: the system prompt forbids CVE citations outright, the schema
constrains `cwe_id` to a pattern, and the allowed CWE list is supplied in the
context. **Grounding is defence in depth here, not the primary control** — which
is a better place for it to be, and not what I expected to find.

### The failure it did have, which grounding does not catch

The same model, on a plain SQL injection with a database error in the evidence:

```
cwe    : CWE-22 Path Traversal              <- wrong class entirely
vector : CVSS:3.1/AV:P/AC:H/PR:H/UI:R/...   <- AV:P means physical access
score  : 6.0 Medium                          <- should be around 9.8 Critical
flags  : none
```

Nothing here is fabricated. CWE-22 is real and in the catalogue, the vector is
well formed, and 6.0 genuinely follows from those metrics — so every check passes,
correctly.

**Grounding catches invention, not incompetence.** A small model produces
confident, well formed, entirely wrong triage and nothing in this project stops
it. Detecting that would need a different mechanism: a second model disagreeing,
a rule that a database error implies CWE-89, or a human. That gap is real and it
is not closed.

### Scope of these numbers

One model, 20 synthetic findings, one run. Not a benchmark. A larger model would
behave differently in both directions — likely better triage, and possibly more
confident fabrication, which is exactly the case the checks exist for.

## Install and run

```bash
git clone https://github.com/venky099/vuln-triage-agent
cd vuln-triage-agent
python -m venv .venv && .venv\Scripts\activate     # Windows
# source .venv/bin/activate                         # macOS / Linux

python -m triage.cli data/sample_scan.json                    # markdown to stdout
python -m triage.cli data/sample_scan.json -f html -o r.html  # styled HTML report
python evals/run_eval.py -n 50                                # the measurement
pytest -q                                                     # 97 tests
```

No API key and no dependencies are needed for any of the above.

The backend is auto-detected, so if Ollama happens to be running those commands
use it and take about a minute per finding. Pass `--backend mock` for the instant
version.

Exit code is **1 when any finding carries an ungrounded claim**, so it can gate a
pipeline: a report nobody has reviewed never ships automatically.

### Backends

| Backend | Setup |
|---|---|
| `mock` | none — the fallback when nothing else is available |
| `ollama` | `ollama serve` and pull a model, then `LLM_BACKEND=ollama` |
| `openai` | `pip install openai`, set `OPENAI_API_KEY`, then `LLM_BACKEND=openai` |

Without `LLM_BACKEND` or `--backend`, the choice is made by detection: an
`OPENAI_API_KEY` wins, else an Ollama with at least one model pulled, else mock.
An open Ollama port with nothing pulled is not treated as available — selecting a
backend that cannot answer turns the first documented command into a stack trace.
`LLM_MODEL` is matched against the installed tags, so `llama3.2` finds
`llama3.2:3b`.

### Input formats

VibeScanner JSON (primary), Burp Suite, OWASP ZAP, and Nmap. Detected automatically;
override with `--input-format`.

Burp is read in both shapes it ships in: Professional's report export (a flat `issues`
array with HTML issue detail) and Enterprise/REST (each issue wrapped in an
`issue_events` envelope).

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
triage/parsers.py     VibeScanner / Burp / ZAP / Nmap -> RawFinding
triage/llm.py         openai | ollama | mock backends
triage/agent.py       the loop: ask, validate, retry, compute, ground
triage/grounding.py   the checks, and redaction
triage/report.py      markdown / HTML / JSON
evals/run_eval.py     hallucination measurement
tests/                97 tests, no network needed
```

## Related

[VibeScanner](https://vibescanner.onrender.com) finds the bugs this triages —
scanner output goes straight in as input.

[Indirect Prompt Injection Lab](https://github.com/venky099/rag-injection-lab) —
the other side of the same coin. There, untrusted text reaches a model and it
obeys. Here, a model produces untrusted text and something downstream believes
it. Both are the same lesson: **a language model is not a source of truth, and
whatever consumes its output has to act like it.**
