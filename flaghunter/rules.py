from pathlib import Path
import re, yaml
from .models import Finding

DEFAULT_RULES = Path(__file__).parent.parent / "rules" / "patterns.yaml"

class PatternEngine:
    def __init__(self, rule_file=None):
        raw = yaml.safe_load(Path(rule_file or DEFAULT_RULES).read_text(encoding="utf-8"))
        self.rules = []
        for r in raw.get("rules", []):
            if len(r["pattern"]) > 500:
                raise ValueError("Rule regex too long")
            self.rules.append((r, re.compile(r["pattern"], re.I | re.M)))

    def scan(self, location: str, content: str, kind="text"):
        findings = []
        for r, regex in self.rules:
            if kind not in r.get("applies_to", ["text", "html", "js", "source", "headers", "url"]):
                continue
            count = 0
            for match in regex.finditer(content[:1_000_000]):
                count += 1
                if count > 5: break
                evidence = match.group(0)[:160]
                if r.get("redact", False): evidence = "[redacted: potential secret or flag]"
                findings.append(Finding(category=r["category"], title=r["title"],location=location,
                    evidence=evidence,severity=r.get("severity","info"),confidence=float(r.get("confidence",0.35)),
                    recommendation=r.get("recommendation","Manually verify in a lab.")))
        return findings
