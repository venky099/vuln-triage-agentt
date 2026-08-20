"""Grounding: every claim must trace back to a source, or it does not ship.

There are exactly two sources of truth:

    1. the RawFinding the scanner produced
    2. the local CWE catalogue

Anything the model asserts that cannot be traced to one of those is a claim it
invented. This module finds those and flags them.

The design point worth stating: this is not "ask the model to check itself".
A model that hallucinated a CVE will happily confirm the CVE is real, because
the same process produced both answers. Verification has to happen in code,
against data the model cannot influence.
"""
from __future__ import annotations

import re

from .models import RawFinding, TriagedFinding
from .tools import VECTOR_RE, lookup_cwe, score_cvss

# Patterns for the classes of claim a report writer tends to fabricate.
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
CWE_RE = re.compile(r"\bCWE-\d{1,4}\b", re.IGNORECASE)
# A vector written into prose. Stripped before looking for a stated score --
# otherwise "CVSS:3.1/AV:N/..." reads as a score of 3.1 and a perfectly correct
# report gets flagged for review. Removing the vector first is more robust than
# trying to exclude it with lookarounds, which backtrack into "3".
VECTOR_IN_PROSE = re.compile(r"CVSS:3\.\d/(?:[A-Z]{1,2}:[A-Z](?:/|\b))+", re.IGNORECASE)

# A numeric score stated in prose. The model is told never to state one; if it
# does anyway, it has to agree with the arithmetic.
SCORE_RE = re.compile(
    r"\bCVSS\s*(?:v?3(?:\.\d)?\s+)?(?:base\s*)?(?:score)?\s*(?:of|is|:|=)?\s*"
    r"(\d{1,2}(?:\.\d)?)\b",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+")
# Absolute claims a scanner finding cannot support.
OVERCLAIM_RE = re.compile(
    r"\b(?:remote code execution|full (?:system|server) compromise|"
    r"complete takeover|all (?:customer|user) (?:data|records) (?:were|was) (?:exposed|stolen))\b",
    re.IGNORECASE,
)


def _normalise(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "")).lower()


def _endpoint(url: str) -> str:
    """scheme://host/path, lowercased, without query, fragment or trailing slash.

    Two URLs are the same endpoint when they differ only in query string. That
    is the normal shape of a reproduction step, not evidence of invention.
    """
    url = (url or "").strip().lower()
    url = re.split(r"[?#]", url, 1)[0]
    return url.rstrip("/")


def check(raw: RawFinding, triaged: TriagedFinding) -> list[str]:
    """Return a list of grounding violations. Empty list means every claim traced."""
    flags: list[str] = []
    corpus = _normalise(raw.evidence_corpus())
    prose = " ".join([triaged.title, triaged.summary,
                      triaged.reproduction, triaged.remediation])

    # 1. CVE citations. A scanner finding on a bespoke application does not map
    #    to a CVE, and a fabricated one is the single most damaging error a
    #    generated report can contain.
    for cve in set(CVE_RE.findall(prose)):
        if cve.lower() not in corpus:
            flags.append("invented CVE reference: {}".format(cve.upper()))

    # 2. CWE identifiers must exist in the catalogue.
    for cwe in set(CWE_RE.findall(prose)) | ({triaged.cwe_id} if triaged.cwe_id else set()):
        if not lookup_cwe(cwe):
            flags.append("CWE not in catalogue: {}".format(cwe.upper()))

    # 3. A stated score must match the computed one. The model is told never to
    #    state a score; if it does anyway, it has to agree with the arithmetic.
    for stated in SCORE_RE.findall(VECTOR_IN_PROSE.sub(" ", prose)):
        try:
            if abs(float(stated) - triaged.cvss_score) > 0.05:
                flags.append("stated CVSS {} does not match computed {}".format(stated, triaged.cvss_score))
        except ValueError:
            flags.append("unparseable CVSS score in prose: {}".format(stated))

    # 4. The vector must be well formed and its score must be the one recorded.
    if triaged.cvss_vector:
        if not VECTOR_RE.match(triaged.cvss_vector):
            flags.append("malformed CVSS vector: {}".format(triaged.cvss_vector))
        else:
            computed, _ = score_cvss(triaged.cvss_vector)
            if abs(computed - triaged.cvss_score) > 0.001:
                flags.append("score {} does not follow from vector".format(triaged.cvss_score))

    # 5. Any URL cited must point at an endpoint the scanner actually touched.
    #
    #    Compared on scheme+host+path only. A reproduction step legitimately
    #    appends the parameter under test -- the scan records
    #    "https://host/report" with parameter "q", and a correct write-up says
    #    "request https://host/report?q=...". A substring match on the whole URL
    #    calls that a fabrication, and a checker that cries wolf is a checker
    #    nobody reads. An invented *path* is still caught.
    scanned = {_endpoint(u) for u in URL_RE.findall(raw.evidence_corpus())}
    scanned.add(_endpoint(raw.url))
    scanned.discard("")
    for url in set(URL_RE.findall(prose)):
        if _endpoint(url.rstrip(".,);")) not in scanned:
            flags.append("URL not present in scan data: {}".format(url))

    # 6. Impact claims a single scanner finding cannot support.
    for phrase in set(m.group(0) for m in OVERCLAIM_RE.finditer(prose)):
        flags.append("unsupported impact claim: {}".format(phrase.lower()))

    return flags


def enforce(raw: RawFinding, triaged: TriagedFinding, redact: bool = True) -> TriagedFinding:
    """Attach flags, and optionally strip the offending claims from the prose.

    Redaction beats deletion: the reviewer sees that something was removed and
    why, instead of a sentence quietly disappearing.
    """
    triaged.flags = check(raw, triaged)
    if not (redact and triaged.flags):
        return triaged

    corpus = _normalise(raw.evidence_corpus())

    def scrub(text: str) -> str:
        text = CVE_RE.sub(lambda m: m.group(0) if m.group(0).lower() in corpus
                          else "[UNVERIFIED REFERENCE REMOVED]", text)
        text = OVERCLAIM_RE.sub("[UNSUPPORTED CLAIM REMOVED]", text)
        return text

    triaged.title = scrub(triaged.title)
    triaged.summary = scrub(triaged.summary)
    triaged.reproduction = scrub(triaged.reproduction)
    triaged.remediation = scrub(triaged.remediation)

    # An ungrounded CWE cannot simply be scrubbed from prose: it is a field.
    # Drop it rather than cite something that does not exist.
    if any(f.startswith("CWE not in catalogue") for f in triaged.flags):
        triaged.cwe_id = ""
        triaged.cwe_name = ""
    return triaged
