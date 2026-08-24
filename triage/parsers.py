"""Turn scanner output into RawFinding objects.

VibeScanner is the primary input. Burp, ZAP and Nmap parsers are here because a
triage tool that only reads one scanner's format is a script, not a tool.
"""
from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any

from .models import RawFinding


def _s(value: Any) -> str:
    return "" if value is None else str(value)


def parse_vibescanner(data: dict[str, Any]) -> list[RawFinding]:
    out: list[RawFinding] = []
    for i, item in enumerate(data.get("findings") or data.get("results") or []):
        out.append(RawFinding(
            id=_s(item.get("id") or f"VS-{i+1:03d}"),
            scanner="VibeScanner",
            kind=_s(item.get("type") or item.get("kind") or "Unknown"),
            url=_s(item.get("url")),
            parameter=_s(item.get("parameter") or item.get("param")),
            method=_s(item.get("method") or "GET").upper(),
            payload=_s(item.get("payload")),
            evidence=_s(item.get("evidence") or item.get("proof")),
            raw={k: v for k, v in item.items()
                 if k not in {"id", "type", "kind", "url", "parameter", "param",
                              "method", "payload", "evidence", "proof"}},
        ))
    return out


def parse_zap(data: dict[str, Any]) -> list[RawFinding]:
    out: list[RawFinding] = []
    n = 0
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            for inst in alert.get("instances", [{}]):
                n += 1
                out.append(RawFinding(
                    id=f"ZAP-{n:03d}",
                    scanner="OWASP ZAP",
                    kind=_s(alert.get("alert") or alert.get("name")),
                    url=_s(inst.get("uri")),
                    parameter=_s(inst.get("param")),
                    method=_s(inst.get("method") or "GET").upper(),
                    payload=_s(inst.get("attack")),
                    evidence=_s(inst.get("evidence")),
                    raw={"confidence": _s(alert.get("confidence"))},
                ))
    return out


def parse_nmap(data: dict[str, Any]) -> list[RawFinding]:
    out: list[RawFinding] = []
    n = 0
    for host in data.get("hosts", []):
        for port in host.get("ports", []):
            if _s(port.get("state")) != "open":
                continue
            n += 1
            out.append(RawFinding(
                id=f"NMAP-{n:03d}",
                scanner="Nmap",
                kind=f"Exposed service: {_s(port.get('service')) or 'unknown'}",
                url=f"{_s(host.get('address'))}:{_s(port.get('port'))}",
                method="TCP",
                evidence=_s(port.get("product")) or _s(port.get("service")),
                raw={"port": _s(port.get("port")), "version": _s(port.get("version"))},
            ))
    return out


# --------------------------------------------------------------------------
# Burp Suite
# --------------------------------------------------------------------------

_TAGS = re.compile(r"<[^>]+>")

# Burp's own phrasing for the input it tested. Reading the parameter out of the
# detail text is not a guess: the string comes from the scan file, so anything
# derived from it is still traceable to scanner output, which is what grounding
# requires. Kept deliberately narrow -- a miss leaves the field empty, which is
# harmless, while a loose pattern would put invented parameter names into the
# model's context.
_PARAM_RE = re.compile(
    r"(?:^|[\s(>])The\s+(?:<[^>]+>\s*)?([\w.\-]{1,40})(?:\s*<[^>]+>)?\s+"
    r"(?:URL parameter|parameter|cookie|header)",
    re.IGNORECASE)


def _detag(value: Any) -> str:
    """Burp writes issue detail as HTML fragments; the corpus wants plain text."""
    text = _s(value)
    if not text:
        return ""
    text = text.replace("<br>", " ").replace("<br/>", " ").replace("</p>", " ")
    return re.sub(r"\s+", " ", html.unescape(_TAGS.sub("", text))).strip()


def _burp_host(item: dict[str, Any]) -> str:
    """Host, however this particular export chose to spell it.

    XML-to-JSON converters keep Burp's `<host ip="...">value</host>` as a dict,
    so a plain str() here would put "{'#text': ...}" in the URL.
    """
    host = item.get("origin") or item.get("host") or ""
    if isinstance(host, dict):
        host = host.get("#text") or host.get("value") or host.get("name") or ""
    return _s(host).rstrip("/")


def parse_burp(data: dict[str, Any]) -> list[RawFinding]:
    """Burp Suite scan issues.

    Handles both shapes in the wild: a flat `issues` array (Professional's
    report export and the XML converters), and Enterprise/REST output where
    each issue arrives wrapped in an `issue_events` envelope.
    """
    issues = data.get("issues")
    if issues is None:
        issues = [e.get("issue", e) for e in (data.get("issue_events") or [])]

    out: list[RawFinding] = []
    for n, item in enumerate(issues or [], 1):
        if not isinstance(item, dict):
            continue
        detail = _detag(item.get("issue_detail") or item.get("issueDetail")
                        or item.get("detail") or item.get("description"))
        background = _detag(item.get("issue_background") or item.get("issueBackground"))
        path = _s(item.get("path"))
        url = _burp_host(item) + path

        parameter = _s(item.get("parameter") or item.get("param"))
        if not parameter:
            match = _PARAM_RE.search(_s(item.get("issue_detail") or item.get("issueDetail")
                                        or item.get("detail") or item.get("description") or ""))
            parameter = match.group(1) if match else ""

        out.append(RawFinding(
            id=_s(item.get("serial_number") or item.get("serialNumber")
                  or item.get("id") or "BURP-{:03d}".format(n)),
            scanner="Burp Suite",
            kind=_s(item.get("name") or item.get("issue_name") or "Unknown"),
            url=url,
            parameter=parameter,
            method=_s(item.get("method") or "GET").upper(),
            payload=_s(item.get("payload")),
            # Burp's own words about what it saw. Background is what the issue
            # class means in general, so it is kept apart from the evidence.
            evidence=detail,
            raw={k: v for k, v in {
                "burp_severity": _s(item.get("severity")),
                "burp_confidence": _s(item.get("confidence")),
                "issue_background": background,
            }.items() if v},
        ))
    return out


PARSERS = {"vibescanner": parse_vibescanner, "burp": parse_burp,
           "zap": parse_zap, "nmap": parse_nmap}


def detect_format(data: dict[str, Any]) -> str:
    if "site" in data:
        return "zap"
    if "hosts" in data:
        return "nmap"
    if "issues" in data or "issue_events" in data:
        return "burp"
    return "vibescanner"


def load(path: str | Path, fmt: str | None = None) -> list[RawFinding]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, list):
        data = {"findings": data}
    fmt = fmt or detect_format(data)
    if fmt not in PARSERS:
        raise ValueError(f"unknown format {fmt!r}; use one of {sorted(PARSERS)}")
    findings = PARSERS[fmt](data)
    if not findings:
        raise ValueError(f"no findings parsed from {path} (format: {fmt})")
    return findings
