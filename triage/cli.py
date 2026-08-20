"""vulntriage command line interface."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .agent import TriageAgent
from .llm import get_backend
from .parsers import load
from .report import to_html, to_json, to_markdown


def _utf8_out() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main(argv: list[str] | None = None) -> int:
    _utf8_out()
    ap = argparse.ArgumentParser(
        prog="vulntriage",
        description="Turn raw scanner output into a grounded pentest report.")
    ap.add_argument("scan", help="scanner output JSON")
    ap.add_argument("-o", "--out", help="write the report here (default: stdout)")
    ap.add_argument("-f", "--format", choices=["markdown", "html", "json"],
                    default="markdown")
    ap.add_argument("--input-format", choices=["vibescanner", "zap", "nmap"],
                    help="override scanner format detection")
    ap.add_argument("--backend", choices=["openai", "ollama", "mock"],
                    help="model backend (default: auto-detect)")
    ap.add_argument("--no-grounding", action="store_true",
                    help="skip the grounding checks (for the eval; never for a real report)")
    ap.add_argument("--no-redact", action="store_true",
                    help="flag ungrounded claims but leave the text intact")
    ap.add_argument("--target", default="", help="target name for the report header")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)

    try:
        findings = load(args.scan, args.input_format)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("Could not read scan: {}".format(exc), file=sys.stderr)
        return 2

    target = args.target
    if not target:
        try:
            target = json.loads(Path(args.scan).read_text(encoding="utf-8")).get("target", "")
        except Exception:
            target = ""

    agent = TriageAgent(backend=get_backend(args.backend),
                        grounding=not args.no_grounding,
                        redact=not args.no_redact)

    def progress(i: int, total: int, raw) -> None:
        if not args.quiet:
            print("  [{}/{}] {} {}".format(i, total, raw.id, raw.kind), file=sys.stderr)

    if not args.quiet:
        print("Backend: {} | {} findings in".format(agent.backend.name, len(findings)),
              file=sys.stderr)

    try:
        result = agent.run(findings, progress=progress)
    except Exception as exc:
        print("Triage failed: {}: {}".format(type(exc).__name__, exc), file=sys.stderr)
        return 1

    renderers = {"markdown": to_markdown, "html": to_html, "json": to_json}
    output = renderers[args.format](result, target)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        if not args.quiet:
            print("Wrote {}".format(args.out), file=sys.stderr)
    else:
        print(output)

    if not args.quiet:
        counts = result.counts()
        print("\n{} findings ({} duplicates merged) | {} critical, {} high, {} medium, {} low"
              .format(len(result.findings), result.duplicates_removed,
                      counts["Critical"], counts["High"], counts["Medium"], counts["Low"]),
              file=sys.stderr)
        if result.flagged:
            print("{} finding(s) contain ungrounded claims and are flagged for review"
                  .format(len(result.flagged)), file=sys.stderr)

    # Non-zero when something needs a human before this report goes out.
    return 1 if result.flagged else 0


if __name__ == "__main__":
    raise SystemExit(main())
