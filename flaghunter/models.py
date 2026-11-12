from dataclasses import dataclass, field, asdict
from typing import Any

@dataclass
class Finding:
    category: str
    title: str
    location: str
    evidence: str
    severity: str = "info"
    confidence: float = 0.3
    status: str = "candidate"
    recommendation: str = "Review manually in an authorized lab."
    source: str = "pattern"
    def to_dict(self): return asdict(self)

@dataclass
class Result:
    target: str
    scanned: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    def to_dict(self):
        return {"target": self.target,"scanned": self.scanned,"findings": [x.to_dict() for x in self.findings],"errors":self.errors,"metadata":self.metadata}
