"""Regex signature engine.

Loads ``rules/patterns.yaml`` and scans a piece of content (a response body,
a header blob, a URL, or a source file) for signatures. Findings here are
*signals*, not proof: confidence comes from the rule, and FP control is applied
by (a) capping matches per rule, (b) de-duplicating identical evidence, and
(c) redacting secrets/flags so sensitive bytes are never stored.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from .models import Finding, STATUS_CANDIDATE

DEFAULT_RULES = Path(__file__).parent.parent / "rules" / "patterns.yaml"
ALL_KINDS = ["text", "html", "js", "json", "xml", "source", "headers", "url"]
MAX_SCAN_BYTES = 1_000_000
MAX_MATCHES_PER_RULE = 5


class PatternEngine:
    def __init__(self, rule_file=None):
        raw = yaml.safe_load(Path(rule_file or DEFAULT_RULES).read_text(encoding="utf-8"))
        self.rules: list[tuple[dict, re.Pattern]] = []
        for r in raw.get("rules", []):
            pattern = r["pattern"]
            if len(pattern) > 1000:
                raise ValueError(f"Rule regex too long: {r.get('title')}")
            self.rules.append((r, re.compile(pattern, re.I | re.M)))

    def scan(self, location: str, content: str, kind: str = "text") -> list[Finding]:
        if not content:
            return []
        content = content[:MAX_SCAN_BYTES]
        findings: list[Finding] = []
        for rule, regex in self.rules:
            if kind not in rule.get("applies_to", ALL_KINDS):
                continue
            seen_evidence: set[str] = set()
            count = 0
            for match in regex.finditer(content):
                evidence = match.group(0)[:200].strip()
                key = evidence.lower()
                if key in seen_evidence:
                    continue
                seen_evidence.add(key)
                count += 1
                if count > MAX_MATCHES_PER_RULE:
                    break
                if rule.get("redact", False):
                    evidence = "[redacted: potential secret or flag matched here]"
                findings.append(Finding(
                    category=rule["category"],
                    title=rule["title"],
                    location=location,
                    evidence=evidence,
                    severity=rule.get("severity", "info"),
                    confidence=float(rule.get("confidence", 0.35)),
                    status=STATUS_CANDIDATE,
                    source="pattern",
                    recommendation=rule.get("recommendation", "Manually verify in a lab."),
                    tags=list(rule.get("tags", [])),
                ))
        return findings
