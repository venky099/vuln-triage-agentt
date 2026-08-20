"""Report rendering: Markdown, HTML and JSON."""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from .agent import TriageResult

BADGE = {"Critical": "#b21f2d", "High": "#c9600a", "Medium": "#9a7d09",
         "Low": "#0a63c9", "None": "#6b7280"}


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def to_markdown(result: TriageResult, target: str = "") -> str:
    counts = result.counts()
    lines = [
        "# Vulnerability Assessment Report",
        "",
        "**Target:** {}  ".format(target or "not specified"),
        "**Date:** {}  ".format(_today()),
        "**Findings:** {} ({} duplicate{} merged)".format(
            len(result.findings), result.duplicates_removed,
            "" if result.duplicates_removed == 1 else "s"),
        "",
        "## Executive summary",
        "",
    ]

    top = result.findings[0] if result.findings else None
    if top and top.severity in ("Critical", "High"):
        lines.append(
            "The assessment identified **{} critical** and **{} high** severity issues. "
            "The most serious is *{}*, scoring {} ({}). Issues at this level should be "
            "remediated before the next release.".format(
                counts["Critical"], counts["High"], top.title, top.cvss_score, top.severity))
    elif result.findings:
        lines.append(
            "No critical or high severity issues were identified. {} finding(s) of medium "
            "severity or below are listed below.".format(len(result.findings)))
    else:
        lines.append("No findings were reported by the scanner.")

    lines += ["", "| Severity | Count |", "|---|---|"]
    for sev in ("Critical", "High", "Medium", "Low", "None"):
        if counts.get(sev):
            lines.append("| {} | {} |".format(sev, counts[sev]))

    if result.flagged:
        lines += [
            "",
            "> **{} finding(s) contain claims that could not be traced to the scan "
            "data.** They are marked below and must be reviewed before this report "
            "is sent.".format(len(result.flagged)),
        ]

    lines += ["", "## Findings", ""]
    for i, f in enumerate(result.findings, 1):
        lines += [
            "### {}. {}".format(i, f.title),
            "",
            "**Severity:** {} ({})  ".format(f.severity, f.cvss_score),
            "**CVSS v3.1:** `{}`  ".format(f.cvss_vector),
        ]
        if f.cwe_id:
            lines.append("**Weakness:** {} — {}  ".format(f.cwe_id, f.cwe_name))
        lines.append("**Source:** {}{}".format(
            f.source_id,
            " (also seen as {})".format(", ".join(f.duplicates)) if f.duplicates else ""))
        lines += ["", f.summary, "",
                  "**Reproduction**", "", f.reproduction, "",
                  "**Remediation**", "", f.remediation, ""]
        if f.flags:
            lines += ["**⚠ Needs review before sending:**", ""]
            lines += ["- {}".format(flag) for flag in f.flags]
            lines.append("")
        lines.append("---")
        lines.append("")

    lines += [
        "## About this report",
        "",
        "Findings were triaged with an LLM under a fixed output schema. CVSS scores "
        "are computed from the selected metrics by code, not stated by the model, and "
        "every claim is checked against the scanner output and a local CWE catalogue "
        "before inclusion. Claims that could not be traced are flagged above rather "
        "than silently removed.",
        "",
        "Backend: `{}`. Schema retries: {}.".format(result.backend, result.schema_retries),
    ]
    return "\n".join(lines)


def to_html(result: TriageResult, target: str = "") -> str:
    counts = result.counts()
    rows = []
    for i, f in enumerate(result.findings, 1):
        flags = ""
        if f.flags:
            flags = ("<div class='flags'><b>Needs review before sending</b><ul>"
                     + "".join("<li>{}</li>".format(html.escape(x)) for x in f.flags)
                     + "</ul></div>")
        rows.append(
            "<article class='finding'>"
            "<div class='head'><span class='sev' style='background:{c}'>{sev} {score}</span>"
            "<h3>{i}. {title}</h3></div>"
            "<p class='meta'><code>{vec}</code>{cwe} &middot; source {src}</p>"
            "<p>{summary}</p>"
            "<h4>Reproduction</h4><p>{repro}</p>"
            "<h4>Remediation</h4><p>{fix}</p>{flags}</article>".format(
                c=BADGE.get(f.severity, "#6b7280"), sev=f.severity, score=f.cvss_score, i=i,
                title=html.escape(f.title), vec=html.escape(f.cvss_vector),
                cwe=" &middot; {} {}".format(f.cwe_id, html.escape(f.cwe_name)) if f.cwe_id else "",
                src=html.escape(f.source_id), summary=html.escape(f.summary),
                repro=html.escape(f.reproduction), fix=html.escape(f.remediation), flags=flags))

    summary_cells = "".join(
        "<div class='stat'><span style='color:{}'>{}</span><small>{}</small></div>".format(
            BADGE[s], counts[s], s) for s in ("Critical", "High", "Medium", "Low") if counts.get(s))

    return """<!doctype html><html><head><meta charset="utf-8">
<title>Vulnerability Assessment Report</title><style>
:root{{--bg:#fff;--fg:#14161d;--muted:#5b6472;--line:#e4e7ee;--card:#fafbfd}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0d0f14;--fg:#e8eaf0;--muted:#98a1b0;--line:#252a34;--card:#141821}}}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--fg);font:15px/1.6 -apple-system,"Segoe UI",Roboto,sans-serif;padding:40px 20px}}
.wrap{{max-width:820px;margin:0 auto}}
h1{{font-size:1.7rem;margin-bottom:4px}}
.sub{{color:var(--muted);margin-bottom:24px}}
.stats{{display:flex;gap:10px;margin:20px 0 28px;flex-wrap:wrap}}
.stat{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 18px;text-align:center}}
.stat span{{display:block;font-size:1.5rem;font-weight:700}}
.stat small{{color:var(--muted)}}
.finding{{border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:16px;background:var(--card)}}
.head{{display:flex;align-items:center;gap:10px;margin-bottom:6px;flex-wrap:wrap}}
.sev{{color:#fff;font:700 .72rem/1 monospace;padding:5px 9px;border-radius:999px;white-space:nowrap}}
h3{{font-size:1.05rem}} h4{{font-size:.82rem;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);margin:14px 0 4px}}
.meta{{color:var(--muted);font-size:.84rem;margin-bottom:10px}}
code{{font-family:ui-monospace,Consolas,monospace;font-size:.82em}}
.flags{{margin-top:14px;padding:10px 14px;border-left:3px solid #c9600a;background:rgba(201,96,10,.08);border-radius:6px;font-size:.88rem}}
.flags ul{{margin:6px 0 0 18px}}
footer{{color:var(--muted);font-size:.84rem;margin-top:30px;border-top:1px solid var(--line);padding-top:16px}}
</style></head><body><div class="wrap">
<h1>Vulnerability Assessment Report</h1>
<p class="sub">{target} &middot; {date} &middot; {n} findings, {dupes} duplicates merged</p>
<div class="stats">{stats}</div>
{rows}
<footer>Triaged with an LLM under a fixed output schema. CVSS scores are computed from the
selected metrics by code, never stated by the model. Every claim is checked against the scanner
output and a local CWE catalogue; untraceable claims are flagged, not silently dropped.
Backend: <code>{backend}</code>. Schema retries: {retries}.</footer>
</div></body></html>""".format(
        target=html.escape(target or "Unspecified target"), date=_today(),
        n=len(result.findings), dupes=result.duplicates_removed,
        stats=summary_cells, rows="".join(rows),
        backend=result.backend, retries=result.schema_retries)


def to_json(result: TriageResult, target: str = "") -> str:
    return json.dumps({
        "target": target,
        "generated": _today(),
        "backend": result.backend,
        "counts": result.counts(),
        "duplicates_removed": result.duplicates_removed,
        "schema_retries": result.schema_retries,
        "ungrounded_findings": len(result.flagged),
        "findings": [f.to_dict() for f in result.findings],
    }, indent=2)
