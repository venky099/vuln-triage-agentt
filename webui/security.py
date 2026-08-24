"""Guards for the hosted demo.

The threat model here is narrower than a scanner's. This app parses JSON and
runs string analysis: no subprocess, no outbound fetching of user-supplied URLs,
so no RCE or SSRF surface. What it does have is a spending account attached to
it, which is its own kind of vulnerability.
"""
from __future__ import annotations

import re
import time
from collections import defaultdict, deque

# A scan payload is JSON produced by a scanner. Generous, but bounded.
MAX_SCAN_BYTES = 512 * 1024
MAX_FINDINGS = 60

# A local model on CPU takes roughly a minute per finding, so a full scan would
# hold an HTTP request open for many minutes. Cap it hard and say why.
MAX_FINDINGS_LOCAL = 5

# OpenAI keys are opaque, but they have a recognisable shape. Checking it
# prevents wasting a round trip on an obvious typo -- it is not validation.
KEY_SHAPE = re.compile(r"^sk-[A-Za-z0-9_\-]{20,}$")

class Rejected(Exception):
    """Refused for a reason worth showing the user."""

def validate_scan(text: str) -> str:
    if not text or not text.strip():
        raise Rejected("Paste a scan first, or load the example.")
    size = len(text.encode("utf-8"))
    if size > MAX_SCAN_BYTES:
        raise Rejected("Scan is {:.0f} KB; the limit is {:.0f} KB.".format(
            size / 1024, MAX_SCAN_BYTES / 1024))
    return text

def validate_api_key(key: str | None) -> str | None:
    """Shape-check only.

    The key is used for one request and then goes out of scope. It is never
    written to disk, never logged, and never echoed back in a response -- which
    includes error messages, the place secrets most often leak.
    """
    if not key or not key.strip():
        return None
    key = key.strip()
    if len(key) > 300:
        raise Rejected("That does not look like an API key.")
    if not KEY_SHAPE.match(key):
        raise Rejected("That does not look like an OpenAI key (expected sk-...).")
    return key

def cap_findings(n: int) -> None:
    if n > MAX_FINDINGS:
        raise Rejected(
            "This scan has {} findings; the demo caps at {}. Run the CLI locally "
            "for larger scans.".format(n, MAX_FINDINGS))

class RateLimiter:
    """Fixed window, per client. Adequate for a single-instance demo."""

    def __init__(self, max_calls: int = 15, window_seconds: int = 60,
                 max_clients: int = 4096) -> None:
        self.max_calls = max_calls
        self.window = window_seconds
        self.max_clients = max_clients
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> None:
        now = time.monotonic()
        hits = self._hits[key]
        while hits and now - hits[0] > self.window:
            hits.popleft()
        if len(hits) >= self.max_calls:
            raise Rejected("Rate limit reached ({}/minute). Try again shortly."
                           .format(self.max_calls))
        hits.append(now)
        if len(self._hits) > self.max_clients:
            self._evict(now)

    def _evict(self, now: float) -> None:
        """Drop clients whose window has expired.

        The old version cleared the whole table, which handed an attacker a
        reset button: manufacture enough distinct identities and everyone's
        counters vanish, including your own. Only entries that are already
        spent may be dropped.
        """
        for key in [k for k, v in self._hits.items() if not v or now - v[-1] > self.window]:
            del self._hits[key]
        if len(self._hits) <= self.max_clients:
            return
        # Still oversized. Any eviction inside a live window hands that client a
        # fresh allowance, so evict the ones with the least to lose first:
        # fewest hits, then least recently seen. A client already at the limit
        # is exactly who the table exists to remember, so it goes last -- which
        # means flooding with new identities cannot buy anyone a reset.
        ranked = sorted(self._hits.items(), key=lambda kv: (len(kv[1]), kv[1][-1]))
        for key, _ in ranked[:len(self._hits) - self.max_clients]:
            del self._hits[key]


def cap_local_findings(n: int) -> None:
    if n > MAX_FINDINGS_LOCAL:
        raise Rejected(
            "A local model takes about a minute per finding, so the browser caps "
            "Ollama runs at {} (this scan needs {} after merging duplicates). "
            "Use the simulated model here, or run the CLI for the full scan."
            .format(MAX_FINDINGS_LOCAL, n))


def validate_ollama_model(name: str | None, available: list[str]) -> str:
    """Pick a model, refusing anything not actually pulled.

    The name reaches Ollama's API, and an unknown one gets a bare 404 part-way
    through a run. Checking against the installed list turns that into an
    immediate, comprehensible refusal.
    """
    if not available:
        raise Rejected("Ollama is not reachable. Start it with `ollama serve`.")
    name = (name or "").strip()
    if not name:
        return available[0]
    if name not in available:
        raise Rejected("Ollama has no model named {!r}. Available: {}."
                       .format(name, ", ".join(available)))
    return name
