"""Web UI for the triage agent.

Run locally:
    uvicorn webui.app:app --reload --port 8000

Deploy:
    uvicorn webui.app:app --host 0.0.0.0 --port $PORT

The centrepiece is the grounding toggle. Both views come from ONE pass of the
model: the agent runs with grounding off, and the checks are then applied to a
copy. So switching between "what the model wrote" and "what actually ships"
costs nothing extra -- which matters when a visitor is paying for the tokens.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from triage import __version__
from triage.agent import TriageAgent, finalise_grounded
from triage.llm import MockBackend, OllamaBackend, OpenAIBackend, ollama_models
from triage.parsers import detect_format, PARSERS
from triage.report import to_html, to_json, to_markdown
from triage.tools import dedupe

from .security import (
    MAX_FINDINGS,
    MAX_FINDINGS_LOCAL,
    RateLimiter,
    Rejected,
    cap_findings,
    cap_local_findings,
    validate_api_key,
    validate_ollama_model,
    validate_scan,
)

BASE_DIR = Path(__file__).parent
ROOT = BASE_DIR.parent

app = FastAPI(title="vuln-triage-agent", version=__version__, docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")
limiter = RateLimiter(max_calls=int(os.environ.get("TRIAGE_RATE", "15")))


class TriageRequest(BaseModel):
    # Deliberately looser than MAX_SCAN_BYTES so validate_scan() is what rejects
    # an oversized payload -- pydantic would otherwise win the race and return a
    # generic 422 with no explanation of the actual limit.
    scan: str = Field(max_length=4_000_000)
    backend: str = Field(default="mock", pattern="^(mock|openai|ollama)$")
    api_key: str | None = Field(default=None, max_length=400)
    model: str | None = Field(default=None, max_length=120)


# How many proxies sit in front of this app. Render terminates TLS and proxies,
# so the default is 1; set 0 when running with nothing in front.
PROXY_DEPTH = max(0, int(os.environ.get("TRIAGE_PROXY_DEPTH", "1")))


def _client(request: Request) -> str:
    """Identify the caller for rate limiting.

    X-Forwarded-For is client-controlled up to the point a trusted proxy
    appends to it, so the LEFTMOST entry is whatever the caller typed. Reading
    it made the limiter free to bypass: rotate the header and every request
    looked like a new visitor. Count PROXY_DEPTH entries from the RIGHT
    instead -- that is the address our own proxy observed.
    """
    peer = request.client.host if request.client else "?"
    if not PROXY_DEPTH:
        return peer
    parts = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
    if len(parts) < PROXY_DEPTH:
        # Fewer hops than configured: the header is short or absent, so it
        # cannot be trusted to name anyone. Fall back to the socket.
        return peer
    return parts[-PROXY_DEPTH]


def _serialise(findings) -> list[dict]:
    return [f.to_dict() for f in findings]


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    models = ollama_models()
    ctx = {"version": __version__, "max_findings": MAX_FINDINGS,
           "ollama_models": models, "max_findings_local": MAX_FINDINGS_LOCAL}
    try:
        return templates.TemplateResponse(request, "index.html", ctx)
    except TypeError:                                   # older Starlette
        return templates.TemplateResponse("index.html", {"request": request, **ctx})


@app.get("/api/health")
async def health():
    models = ollama_models()
    return {"ok": True, "version": __version__,
            "ollamaAvailable": bool(models), "ollamaModels": models}


@app.get("/api/example")
async def example():
    return JSONResponse(json.loads((ROOT / "data" / "sample_scan.json").read_text(encoding="utf-8")))


@app.post("/api/triage")
async def triage(req: TriageRequest, request: Request):
    try:
        limiter.check(_client(request))
        text = validate_scan(req.scan)
        key = validate_api_key(req.api_key)
    except Rejected as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=429
                            if "Rate limit" in str(exc) else 400)

    # --- parse ---
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return JSONResponse({"ok": False,
                             "error": "Invalid JSON: {} (line {})".format(exc.msg, exc.lineno)},
                            status_code=400)
    if isinstance(data, list):
        data = {"findings": data}
    if not isinstance(data, dict):
        return JSONResponse({"ok": False, "error": "Expected a JSON object or array."},
                            status_code=400)

    fmt = detect_format(data)
    try:
        findings = PARSERS[fmt](data)
        if not findings:
            raise ValueError("No findings found in that payload.")
        cap_findings(len(findings))
    except Rejected as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": "Could not parse scan: {}".format(exc)},
                            status_code=400)

    # Deduplicate before choosing a backend: the local cap bounds wall-clock
    # time, which is driven by model calls, and duplicates cost none. Counting
    # raw findings refused the bundled example (6 raw, 5 after merging).
    grouped = dedupe(findings)

    # --- backend ---
    if req.backend == "ollama":
        # Local models are slow enough that a full scan would hold the request
        # open for minutes, so this path is capped harder than the others.
        try:
            cap_local_findings(len(grouped))
            model = validate_ollama_model(req.model, ollama_models())
        except Rejected as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
        backend = OllamaBackend(model=model)
    elif req.backend == "openai":
        if not key:
            return JSONResponse(
                {"ok": False,
                 "error": "Paste your own OpenAI key to run against a real model. "
                          "It is used for this request only and never stored."},
                status_code=400)
        try:
            backend = OpenAIBackend(api_key=key)
        except ImportError:
            return JSONResponse({"ok": False,
                                 "error": "The openai package is not installed on this server."},
                                status_code=503)
    else:
        backend = MockBackend()

    # --- one pass of the model, two views ---
    agent = TriageAgent(backend=backend, grounding=False)
    raw_view, grounded_view = [], []
    try:
        for raw, dupes in grouped:
            unchecked = agent.triage_one(raw, dupes)
            raw_view.append(unchecked)
            grounded_view.append(finalise_grounded(raw, copy.deepcopy(unchecked)))
    except Exception as exc:
        # Never surface the key, and never surface a provider payload that might
        # quote it back. Report the exception type and nothing else.
        return JSONResponse(
            {"ok": False, "error": "Triage failed ({}). Check the scan format or your key."
                                   .format(type(exc).__name__)},
            status_code=502)

    raw_view.sort(key=lambda f: -f.cvss_score)
    grounded_view.sort(key=lambda f: -f.cvss_score)

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0}
    for f in grounded_view:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    return JSONResponse({
        "ok": True,
        "target": data.get("target", ""),
        "backend": backend.name,
        "format": fmt,
        "counts": counts,
        "duplicatesRemoved": len(findings) - len(grouped),
        "flaggedCount": sum(1 for f in grounded_view if f.flags),
        "ungrounded": _serialise(raw_view),
        "grounded": _serialise(grounded_view),
    })


class RenderRequest(BaseModel):
    payload: dict
    format: str = Field(default="markdown", pattern="^(markdown|html|json)$")


@app.post("/api/render")
async def render(req: RenderRequest, request: Request):
    """Re-render an already-triaged result for download. No model involved."""
    try:
        limiter.check(_client(request))
    except Rejected as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=429)

    from triage.agent import TriageResult
    from triage.models import TriagedFinding

    entries = req.payload.get("grounded", [])
    if not isinstance(entries, list) or len(entries) > MAX_FINDINGS:
        return JSONResponse({"ok": False, "error": "Malformed result payload."}, status_code=400)

    try:
        result = TriageResult(
            findings=[TriagedFinding(**f) for f in entries],
            duplicates_removed=int(req.payload.get("duplicatesRemoved", 0)),
            backend=str(req.payload.get("backend", "")),
        )
    except (TypeError, ValueError):
        return JSONResponse({"ok": False, "error": "Malformed result payload."}, status_code=400)

    target = str(req.payload.get("target", ""))
    body = {"markdown": to_markdown, "html": to_html, "json": to_json}[req.format](result, target)
    return JSONResponse({"ok": True, "body": body})
