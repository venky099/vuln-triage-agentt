"""Turn scanner output into RawFinding objects.

VibeScanner is the primary input. ZAP and Nmap parsers are here because a
triage tool that only reads one scanner's format is a script, not a tool.
"""
from __future__ import annotations

import json
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


PARSERS = {"vibescanner": parse_vibescanner, "zap": parse_zap, "nmap": parse_nmap}


def detect_format(data: dict[str, Any]) -> str:
    if "site" in data:
        return "zap"
    if "hosts" in data:
        return "nmap"
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
