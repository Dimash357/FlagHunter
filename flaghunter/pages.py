"""In-memory representation of a fetched page.

Kept separate from :mod:`flaghunter.models` because pages hold raw response
bodies that are used by detectors but are *not* serialised into the report
(only derived findings/endpoints are).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Page:
    url: str
    final_url: str
    status: int
    content_type: str
    kind: str                 # html|js|json|xml|text
    headers: dict[str, str] = field(default_factory=dict)
    text: str = ""
    elapsed_ms: int = 0
    redirect_chain: list[str] = field(default_factory=list)
    set_cookies: list[str] = field(default_factory=list)

    def header(self, name: str, default: str = "") -> str:
        name = name.lower()
        for k, v in self.headers.items():
            if k.lower() == name:
                return v
        return default
