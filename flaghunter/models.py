"""Core data models for FlagHunter.

The scanner is organised around three objects:

* :class:`Endpoint`  - an attackable surface (a page, a form, an API route)
  with its method and parameter names.
* :class:`Finding`   - a candidate weakness tied to an entry point, carrying
  the evidence, a confidence, a verification status and a ready-to-run
  manual-verification playbook (steps + Kali/curl commands + expected result).
* :class:`Result`    - everything produced by one scan.

Nothing here asserts that a vulnerability is *confirmed*: statuses describe how
much evidence exists, and the strongest automatic status is ``"evidence"``
(a reproducible indicator), never ``"exploited"``.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

# --- The ten supported vulnerability categories (stable machine keys) --------
# Keys are used across rules, detectors, playbooks and the dashboard.
CATEGORIES: dict[str, str] = {
    "SQLI": "SQL Injection",
    "COOKIE_AUTH": "Cookie-based Authentication Bypass",
    "IDOR": "Insecure Direct Object Reference (IDOR)",
    "XSS": "Cross-Site Scripting (XSS)",
    "FILE_UPLOAD": "Unrestricted File Upload",
    "SSRF": "Server-Side Request Forgery (SSRF)",
    "COMMAND_INJECTION": "Command Injection",
    "BROKEN_ACCESS_CONTROL": "Broken Access Control",
    "XXE": "XML External Entity (XXE)",
    "SSTI": "Server-Side Template Injection (SSTI)",
}

# Auxiliary (non-vuln) categories used for hints / hygiene.
AUX_CATEGORIES: dict[str, str] = {
    "FLAG": "CTF Flag Hint",
    "SECRET": "Exposed Secret",
    "HEADERS": "Security Header",
    "INFO": "Information",
}

ALL_CATEGORIES = {**CATEGORIES, **AUX_CATEGORIES}

# Verification status ladder (increasing evidence, never "confirmed exploit").
STATUS_CANDIDATE = "candidate"        # pattern/structure only; manual check required
STATUS_INDICATOR = "indicator"        # active-but-safe probe returned a weak signal
STATUS_EVIDENCE = "evidence"          # reproducible signal (e.g. input reflected verbatim)
STATUS_NEEDS_CONFIRM = "needs-confirmation"  # requires an intrusive check the user must approve

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def category_label(key: str) -> str:
    return ALL_CATEGORIES.get(key, key)


@dataclass
class Endpoint:
    """An attackable surface discovered during crawling."""

    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)   # parameter names only
    source: str = "link"                               # link|form|js|api|guess
    enctype: str = ""                                  # for forms
    note: str = ""

    def key(self) -> tuple:
        """Dedup key: same path + method + the *set* of parameter names."""
        return (self.method.upper(), self.url.split("#")[0], tuple(sorted(set(self.params))))

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Cookie:
    name: str
    secure: bool = False
    httponly: bool = False
    samesite: str = ""
    looks_privilege: bool = False   # name/value hints at a role/privilege flag

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    category: str
    title: str
    location: str                       # URL (or file path) where it was seen
    evidence: str = ""
    entry_point: str = ""               # param name, "cookie:X", "header:Y", "body", ...
    method: str = "GET"
    severity: str = "info"
    confidence: float = 0.3
    status: str = STATUS_CANDIDATE
    source: str = "pattern"             # pattern|structure|active|ai
    recommendation: str = "Review manually in an authorized lab."
    verification: list[str] = field(default_factory=list)   # step-by-step manual plan
    commands: list[str] = field(default_factory=list)       # ready Kali/curl commands
    expected: str = ""                  # what a vulnerable vs safe result looks like
    tags: list[str] = field(default_factory=list)

    def dedup_key(self) -> tuple:
        return (self.category, self.location, self.entry_point, self.title)

    def priority(self) -> tuple:
        """Sort key (desc): severity, then confidence, then status strength."""
        status_rank = {
            STATUS_EVIDENCE: 3,
            STATUS_INDICATOR: 2,
            STATUS_NEEDS_CONFIRM: 1,
            STATUS_CANDIDATE: 0,
        }.get(self.status, 0)
        return (SEVERITY_ORDER.get(self.severity, 0), round(self.confidence, 3), status_rank)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["category_label"] = category_label(self.category)
        return d


@dataclass
class FlagHint:
    """A non-exploitative pointer to where a flag might live."""

    location: str
    kind: str            # comment|hidden-field|js-var|path|file|keyword|encoded
    detail: str
    confidence: float = 0.3

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Result:
    target: str
    scanned: list[str] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    cookies: list[Cookie] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    flag_hints: list[FlagHint] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    # -- finding bookkeeping --------------------------------------------------
    def add_finding(self, finding: Finding) -> bool:
        """Add a finding unless an equal-or-stronger duplicate already exists."""
        key = finding.dedup_key()
        for i, existing in enumerate(self.findings):
            if existing.dedup_key() == key:
                # Keep whichever has the stronger priority / more evidence.
                if finding.priority() > existing.priority():
                    self.findings[i] = finding
                return False
        self.findings.append(finding)
        return True

    def add_endpoint(self, endpoint: Endpoint) -> bool:
        key = endpoint.key()
        if any(e.key() == key for e in self.endpoints):
            return False
        self.endpoints.append(endpoint)
        return True

    def category_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.category] = counts.get(f.category, 0) + 1
        return counts

    def most_likely(self, limit: int = 5) -> list[Finding]:
        """Top vulnerability findings by priority (excludes aux categories)."""
        vulns = [f for f in self.findings if f.category in CATEGORIES]
        return sorted(vulns, key=lambda f: f.priority(), reverse=True)[:limit]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scanned": self.scanned,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "cookies": [c.to_dict() for c in self.cookies],
            "findings": [f.to_dict() for f in sorted(self.findings, key=lambda f: f.priority(), reverse=True)],
            "flag_hints": [h.to_dict() for h in self.flag_hints],
            "most_likely": [f.to_dict() for f in self.most_likely()],
            "category_counts": self.category_counts(),
            "errors": self.errors,
            "metadata": self.metadata,
        }
