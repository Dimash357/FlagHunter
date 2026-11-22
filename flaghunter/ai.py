"""Optional Gemini reviewer.

Runs **after** the local detectors and only on *ambiguous* findings (moderate
confidence, not already strong evidence, not flags/secrets). It receives
sanitized metadata only - category, title, entry point, confidence, status and a
redacted evidence snippet - never raw page bodies, cookies or credentials. Any
API error is swallowed so the rule-based scan is never blocked.
"""

from __future__ import annotations

import json
import os
import re

import httpx

from .models import CATEGORIES

_REDACT_RE = re.compile(
    r"(?:flag|ctf|htb|thm|pico|key|secret)\{[^}]*\}|eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_.-]+|AKIA[0-9A-Z]{16}",
    re.I)


def _sanitize(text: str, limit: int = 100) -> str:
    return _REDACT_RE.sub("[redacted]", text or "")[:limit]


class GeminiReviewer:
    def __init__(self, key=None, model=None, base_url=None):
        self.key = key or os.getenv("GEMINI_API_KEY", "")
        self.model = model or os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        self.base_url = (base_url or os.getenv(
            "GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta")).rstrip("/")

    def _candidates(self, findings, max_findings):
        out = []
        for f in findings:
            if f.category not in CATEGORIES:
                continue
            if f.category in ("FLAG", "SECRET"):
                continue
            # Ambiguous = worth a second opinion: not trivial, not already strong.
            if f.status == "evidence":
                continue
            if 0.2 <= f.confidence < 0.7:
                out.append(f)
        out.sort(key=lambda f: f.confidence, reverse=True)
        return out[:max_findings]

    async def review(self, findings, max_findings=10):
        if not self.key:
            return {"status": "skipped", "reason": "GEMINI_API_KEY missing"}
        candidates = self._candidates(findings, max_findings)
        if not candidates:
            return {"status": "skipped", "reason": "No ambiguous findings to review"}
        safe = [{
            "category": CATEGORIES.get(f.category, f.category),
            "title": f.title,
            "entry_point": f.entry_point,
            "method": f.method,
            "confidence": round(f.confidence, 2),
            "status": f.status,
            "evidence": _sanitize(f.evidence),
        } for f in candidates]

        instruction = (
            "Ты ассистент по defensive-анализу для авторизованного Web CTF. "
            "Ниже эвристические находки локального сканера (уже отсортированы). "
            "Для каждой категории: оцени, насколько правдоподобна уязвимость, "
            "укажи вероятные false positive и что проверить вручную в первую очередь. "
            "Не утверждай, что уязвимость подтверждена, и не давай инструкций по доступу "
            "к чужим/закрытым данным. Ответ кратко, по-русски, сгруппируй по категориям. "
            "Находки: " + json.dumps(safe, ensure_ascii=False)
        )
        endpoint = f"{self.base_url}/models/{self.model}:generateContent"
        payload = {
            "contents": [{"role": "user", "parts": [{"text": instruction}]}],
            "generationConfig": {"temperature": 0.1, "maxOutputTokens": 1200},
        }
        try:
            async with httpx.AsyncClient(timeout=30, trust_env=False) as client:
                resp = await client.post(endpoint, params={"key": self.key}, json=payload)
                resp.raise_for_status()
                obj = resp.json()
                parts = obj.get("candidates", [{}])[0].get("content", {}).get("parts", [])
                text = "\n".join(p.get("text", "") for p in parts).strip()
                return {"status": "ok", "model": self.model,
                        "reviewed": len(candidates), "analysis": text}
        except (httpx.HTTPError, ValueError, IndexError, KeyError) as exc:
            return {"status": "unavailable", "model": self.model, "reason": str(exc)[:250]}
