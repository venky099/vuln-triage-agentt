"""Model backends: OpenAI, Ollama, or a deterministic mock.

Backend is chosen by LLM_BACKEND, else auto-detected:
    OPENAI_API_KEY set        -> openai
    Ollama answering locally  -> ollama
    otherwise                 -> mock

ABOUT THE MOCK -- read before quoting any number this repo produces.

The mock is a *simulation of a confident model*, not a language model. It fills
in the schema competently for the vulnerability classes it recognises, and -- on
a fixed, seeded subset of findings -- it does what real models do under pressure
to sound authoritative: it cites a CVE that does not exist, or a CWE that is not
in the catalogue.

That behaviour is deliberate and deterministic, so the grounding layer has
something to catch and the eval produces a stable before/after number with no
API key. It is NOT evidence about how any real model behaves. Run the eval
against `openai` or `ollama` and publish those numbers before making a claim
about real-world hallucination rates.
"""
from __future__ import annotations

import hashlib
import json
import os
import urllib.request

SYSTEM_PROMPT = """You are a penetration testing report writer.

You will be given ONE finding from an automated scanner. Produce a triage entry
as JSON matching the schema you are given. Rules:

1. Every factual claim must come from the scanner evidence provided. If the
   evidence does not support something, do not write it.
2. Never state a CVSS score. Choose the eight CVSS v3.1 metrics; the score is
   computed from them by the caller.
3. Cite a CWE only if it is in the provided catalogue. Never invent identifiers.
4. Do not cite CVE numbers. A scanner finding on a custom application does not
   map to a CVE, and inventing one destroys the credibility of the whole report.
5. Write for a developer who has to fix this. Be specific and brief.

Return only JSON. No prose, no code fences."""


class Backend:
    name = "base"

    def complete_json(self, system: str, user: str) -> str:  # pragma: no cover
        raise NotImplementedError


# --------------------------------------------------------------------------
# Mock
# --------------------------------------------------------------------------

# Reasonable triage per vulnerability class, keyed by a substring of the kind.
_PLAYBOOK = {
    "sql injection": {
        "cwe": "CWE-89",
        "metrics": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
        "summary": "The {parameter} parameter is concatenated into a SQL query. A crafted value changes the meaning of the query, exposing the database behind {url}.",
        "repro": "Send a {method} request to {url} with {parameter}={payload} and compare the response against a benign value.",
        "fix": "Use parameterised queries so {parameter} is bound as a value and never parsed as SQL.",
    },
    "xss": {
        "cwe": "CWE-79",
        "metrics": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
        "summary": "Input supplied in {parameter} is reflected into the response without encoding, so an attacker-supplied script executes in a victim browser.",
        "repro": "Request {url} with {parameter}={payload} and observe the payload rendered unencoded in the HTML body.",
        "fix": "Encode output for the context it lands in, and prefer textContent over innerHTML when inserting untrusted text.",
    },
    "request forgery": {
        "cwe": "CWE-352",
        "metrics": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "N", "I": "H", "A": "N"},
        "summary": "The endpoint at {url} performs a state change without verifying the request originated from the application itself.",
        "repro": "Host a page that auto-submits a {method} to {url}, then load it while authenticated; the change is applied.",
        "fix": "Require an unpredictable per-session token on state-changing requests and set SameSite on the session cookie.",
    },
    "direct object": {
        "cwe": "CWE-639",
        "metrics": {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
        "summary": "The {parameter} value selects a record without checking that the authenticated user owns it, so any user can read another user data via {url}.",
        "repro": "Authenticate, then request {url} with {parameter} set to an identifier belonging to a different user.",
        "fix": "Check ownership server-side on every request rather than trusting the identifier supplied by the client.",
    },
    "error message": {
        "cwe": "CWE-209",
        "metrics": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"},
        "summary": "An unhandled error at {url} returns a stack trace, disclosing framework version and server file paths that assist further attacks.",
        "repro": "Request {url} with {parameter}={payload} to trigger the error and observe the trace in the response body.",
        "fix": "Return a generic error to the client and log the detail server-side only.",
    },
    "exposed service": {
        "cwe": "CWE-200",
        "metrics": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"},
        "summary": "A network service is reachable at {url} and discloses product and version information in its banner.",
        "repro": "Connect to {url} and read the service banner.",
        "fix": "Restrict access at the firewall and suppress version banners where the service allows it.",
    },
}

_FALLBACK = {
    "cwe": "CWE-20",
    "metrics": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"},
    "summary": "The scanner reported an issue affecting {url}. Input handling at {parameter} does not sufficiently validate the supplied value.",
    "repro": "Request {url} with {parameter}={payload} and compare the response against a benign value.",
    "fix": "Validate the input against an allowlist of expected values before use.",
}


class MockBackend(Backend):
    """Deterministic stand-in. See the module docstring for its limits."""

    name = "mock"
    # 1 in HALLUCINATE_EVERY findings receives a fabricated citation.
    HALLUCINATE_EVERY = 3

    def complete_json(self, system: str, user: str) -> str:
        ctx = json.loads(user)
        kind = (ctx.get("kind") or "").lower()
        play = next((p for key, p in _PLAYBOOK.items() if key in kind), _FALLBACK)

        fields = {
            "url": ctx.get("url") or "the affected endpoint",
            "parameter": ctx.get("parameter") or "the request body",
            "method": ctx.get("method") or "GET",
            "payload": ctx.get("payload") or "a crafted value",
        }
        summary = play["summary"].format(**fields)
        cwe = play["cwe"]

        # Seeded "confident guessing": stable per finding id, so the eval is
        # reproducible and the same findings fail on every run.
        seed = int(hashlib.sha256((ctx.get("id") or "").encode()).hexdigest(), 16)
        if seed % self.HALLUCINATE_EVERY == 0:
            if seed % 2 == 0:
                # A fabricated CVE. Correct shape, entirely invented.
                summary += " This corresponds to CVE-{}-{}.".format(2019 + (seed % 6), 1000 + (seed % 8999))
            else:
                # A CWE identifier that is not in the catalogue.
                cwe = "CWE-{}".format(700 + (seed % 90))

        return json.dumps({
            "title": "{} in {} at {}".format(ctx.get("kind"), fields["parameter"], fields["url"])[:120],
            "cwe_id": cwe,
            "cvss_metrics": play["metrics"],
            "summary": summary,
            "reproduction": play["repro"].format(**fields),
            "remediation": play["fix"].format(**fields),
        })


# --------------------------------------------------------------------------
# Real backends
# --------------------------------------------------------------------------

class OpenAIBackend(Backend):
    name = "openai"

    def __init__(self, model: str | None = None) -> None:
        from openai import OpenAI
        self.client = OpenAI()
        self.model = model or os.environ.get("LLM_MODEL", "gpt-4o-mini")

    def complete_json(self, system: str, user: str) -> str:
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": user}],
            response_format={"type": "json_object"},
            temperature=0,
        )
        return (resp.choices[0].message.content or "").strip()


class OllamaBackend(Backend):
    name = "ollama"

    def __init__(self, model: str | None = None) -> None:
        self.host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
        self.model = model or os.environ.get("LLM_MODEL", "llama3.2")

    def complete_json(self, system: str, user: str) -> str:
        payload = json.dumps({
            "model": self.model, "stream": False, "format": "json",
            "options": {"temperature": 0},
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
        }).encode()
        req = urllib.request.Request(self.host + "/api/chat", data=payload,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=180) as resp:
            body = json.loads(resp.read())
        return (body.get("message", {}).get("content") or "").strip()


def _ollama_alive() -> bool:
    import socket
    from urllib.parse import urlparse
    p = urlparse(os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434"))
    try:
        with socket.create_connection((p.hostname or "127.0.0.1", p.port or 11434), timeout=0.4):
            return True
    except OSError:
        return False


def get_backend(name: str | None = None) -> Backend:
    choice = (name or os.environ.get("LLM_BACKEND", "")).lower().strip()
    if choice == "openai":
        return OpenAIBackend()
    if choice == "ollama":
        return OllamaBackend()
    if choice == "mock":
        return MockBackend()
    if choice:
        raise SystemExit("Unknown LLM_BACKEND {!r}. Use openai, ollama or mock.".format(choice))
    if os.environ.get("OPENAI_API_KEY"):
        try:
            return OpenAIBackend()
        except ImportError:
            pass
    if _ollama_alive():
        return OllamaBackend()
    return MockBackend()
