"""Local vulnerability detectors.

Three layers, strongest-evidence-wins, all running *before* any AI is consulted:

1. ``run_passive`` - signature scan (:mod:`flaghunter.rules`) over every fetched
   page body / headers / URL, plus response-header hygiene checks.
2. ``run_structural`` - reasoning over the discovered surface (endpoint params,
   cookies, forms, routes) to name the *most likely* category and entry point
   for each attack surface, with deliberately modest confidence.
3. :class:`ActiveProber` - opt-in, scope-bounded probes that look for a
   reproducible signal (input reflected verbatim, a DB error that the baseline
   did not have, template arithmetic evaluated). Potentially intrusive probes
   (time-based command injection) run only when the user confirms them.

No layer ever claims a confirmed exploit; the strongest status is ``"evidence"``
(a reproducible indicator the operator can verify by hand).
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from .http_client import Fetcher
from .models import (
    Finding, Result, CATEGORIES,
    STATUS_INDICATOR, STATUS_EVIDENCE,
)
from .pages import Page
from .rules import PatternEngine
from .scope import Scope, ScopeError

# Parameter-name heuristics → (category, base confidence).
_PARAM_MAP: dict[str, list[tuple[str, float]]] = {}


def _register(names: set[str], category: str, conf: float) -> None:
    for n in names:
        _PARAM_MAP.setdefault(n, []).append((category, conf))


_register({"id", "uid", "user_id", "account_id", "order_id", "doc_id", "document_id",
           "file_id", "invoice_id", "profile_id", "record_id", "num", "no", "pid",
           "account", "order", "document", "invoice", "profile", "record"}, "IDOR", 0.3)
_register({"url", "uri", "link", "next", "redirect", "redir", "return", "returnurl",
           "return_url", "dest", "destination", "callback", "webhook", "image",
           "img", "image_url", "imageurl", "fetch", "feed", "domain", "site",
           "proxy", "load", "open", "continue", "target_url", "out", "go",
           "page_url"}, "SSRF", 0.3)
_register({"cmd", "command", "exec", "ping", "ip", "dns", "run", "system",
           "target", "address", "hostname", "addr", "host"}, "COMMAND_INJECTION", 0.3)
_register({"id", "uid", "user_id", "pid", "cat", "category", "search", "q", "query",
           "name", "sort", "order", "filter", "item", "product", "article",
           "keyword", "term"}, "SQLI", 0.25)
_register({"q", "search", "query", "name", "message", "comment", "text", "s",
           "keyword", "title", "lang", "ref", "input", "data", "msg", "content",
           "body", "subject", "term"}, "XSS", 0.25)
_register({"template", "tpl", "view", "greeting", "preview", "theme", "name",
           "msg", "message", "content", "subject", "title"}, "SSTI", 0.2)

_ADMIN_PATH_RE = re.compile(
    r"/(admin|administrator|internal|manage(?:ment)?|dashboard|console|config|"
    r"setup|backend|staff|moderator|superuser)(?:/|$)", re.I)

_SQL_ERROR_RE = re.compile(
    r"(SQL syntax|mysql_fetch|Unclosed quotation mark|Incorrect syntax near|ORA-\d{5}|"
    r"quoted string not properly terminated|PostgreSQL.*ERROR|PG::|SQLSTATE\[|"
    r"sqlite3?\.(?:OperationalError|Error)|SQLiteException|near \"[^\"]*\": syntax error|"
    r"Warning:\s+(?:mysqli?|pg|oci|sqlsrv)_)", re.I)


# --------------------------------------------------------------------- passive
def run_passive(result: Result, pages: list[Page], engine: PatternEngine) -> None:
    seen_headers: set[str] = set()
    for page in pages:
        for f in engine.scan(page.final_url, page.text, page.kind):
            result.add_finding(f)
        # URL parameters as their own signal source.
        for f in engine.scan(page.final_url, page.final_url, "url"):
            result.add_finding(f)
        # Header signatures + hygiene (never scan Set-Cookie / auth headers).
        header_text = "\n".join(
            f"{k}: {v}" for k, v in page.headers.items()
            if k.lower() not in {"set-cookie", "authorization", "proxy-authorization"}
        )
        for f in engine.scan(page.final_url + " [headers]", header_text, "headers"):
            result.add_finding(f)
        _header_hygiene(result, page, seen_headers)


def _header_hygiene(result: Result, page: Page, seen: set[str]) -> None:
    # Reported once per missing header for the whole target, not per page.
    if page.kind != "html":
        return
    present = {k.lower() for k in page.headers}
    checks = {
        "content-security-policy": ("Missing Content-Security-Policy", 0.5),
        "x-content-type-options": ("Missing X-Content-Type-Options", 0.4),
        "x-frame-options": ("Missing X-Frame-Options / frame-ancestors", 0.35),
    }
    for header, (title, conf) in checks.items():
        if header in seen:
            continue
        if header == "x-frame-options" and "content-security-policy" in present:
            continue
        if header not in present:
            seen.add(header)
            result.add_finding(Finding(
                category="HEADERS", title=title, location=page.final_url,
                evidence="Response header absent on at least one HTML page",
                severity="info", confidence=conf, source="structure",
                recommendation="Set this response header to harden the app (defence in depth).",
            ))


# ------------------------------------------------------------------ structural
def _param_categories(name: str) -> list[tuple[str, float]]:
    hits = list(_PARAM_MAP.get(name.lower(), []))
    hits.sort(key=lambda x: x[1], reverse=True)
    return hits[:2]   # at most the two most-likely categories per parameter


def run_structural(result: Result) -> None:
    # 1. Endpoint parameters → most-likely category + entry point.
    for ep in result.endpoints:
        for param in dict.fromkeys(ep.params):     # preserve order, unique
            for category, conf in _param_categories(param):
                result.add_finding(Finding(
                    category=category,
                    title=f"{CATEGORIES[category]} candidate parameter",
                    location=ep.url,
                    entry_point=param,
                    method=ep.method,
                    evidence=f"Parameter '{param}' on a {ep.source} ({ep.method}) endpoint",
                    severity="medium" if conf >= 0.3 else "low",
                    confidence=conf,
                    source="structure",
                    recommendation="Heuristic from the parameter name; verify with the steps below.",
                ))
        # 2. File-upload forms.
        if ep.note == "file-upload":
            result.add_finding(Finding(
                category="FILE_UPLOAD",
                title="Unrestricted file upload candidate",
                location=ep.url, entry_point=(ep.params[0] if ep.params else "file"),
                method="POST",
                evidence="Form exposes a file input",
                severity="medium", confidence=0.5, source="structure",
                recommendation="Test extension / content-type / storage-location controls.",
            ))
        # 3. XML-accepting endpoints → XXE surface.
        if "xml" in ep.enctype or ep.url.lower().endswith((".xml", "/xml", "/soap")):
            result.add_finding(Finding(
                category="XXE", title="XML input surface (XXE candidate)",
                location=ep.url, entry_point="body", method=ep.method or "POST",
                evidence="Endpoint appears to accept XML",
                severity="medium", confidence=0.3, source="structure",
                recommendation="Submit a benign internal entity to test DTD processing.",
            ))

    # 4. Privilege cookies → cookie-auth / access-control surface.
    for cookie in result.cookies:
        if cookie.looks_privilege:
            weak = not cookie.httponly or not cookie.secure
            result.add_finding(Finding(
                category="COOKIE_AUTH",
                title="Session/privilege cookie - test tampering",
                location=result.target,
                entry_point=f"cookie:{cookie.name}",
                evidence=(f"Cookie '{cookie.name}' "
                          f"(HttpOnly={cookie.httponly}, Secure={cookie.secure}, "
                          f"SameSite={cookie.samesite or 'unset'})"),
                severity="medium" if weak else "low",
                confidence=0.4 if weak else 0.3,
                source="structure",
                recommendation="Flip the privilege value or test JWT signing; confirm the server re-checks it.",
            ))

    # 5. Reachable admin-ish routes (200 OK without auth).
    for http in result.metadata.get("http", []):
        url = http.get("url", "")
        if http.get("status") == 200 and _ADMIN_PATH_RE.search(urlparse(url).path):
            result.add_finding(Finding(
                category="BROKEN_ACCESS_CONTROL",
                title="Privileged route reachable (HTTP 200)",
                location=url, entry_point="",
                evidence=f"{url} returned 200 during an unauthenticated crawl",
                severity="medium", confidence=0.4, source="structure",
                recommendation="Confirm whether this should require authentication/authorisation.",
            ))


# ---------------------------------------------------------------- active probes
_MARK = "fh9k3x"
_REFLECT_PAYLOAD = _MARK + "<fhq9>"            # XSS reflection probe (inert server-side)
_SQLI_PAYLOAD = _MARK + "'"                    # error-based SQLi probe
_SSTI_PAYLOADS = [_MARK + "{{7*7}}", _MARK + "${7*7}"]  # evaluates to fh9k3x49
_SSTI_EXPECT = _MARK + "49"
_SLEEP_SECONDS = 4
_CMDI_PAYLOAD = "127.0.0.1;sleep " + str(_SLEEP_SECONDS)


def _snippet(text: str, needle: str, span: int = 60) -> str:
    i = text.find(needle)
    if i < 0:
        return ""
    start = max(0, i - span)
    return text[start:i + len(needle) + span].replace("\n", " ").strip()[:200]


class ActiveProber:
    """Opt-in, scope-bounded active checks. Observation only in the safe tier."""

    def __init__(self, scope: Scope, *, confirm_intrusive: bool = False,
                 max_endpoints: int = 40, max_params: int = 8,
                 timeout: float = 10.0, delay: float = 0.3):
        self.scope = scope
        self.confirm_intrusive = confirm_intrusive
        self.max_endpoints = max_endpoints
        self.max_params = max_params
        self.timeout = timeout
        self.delay = delay
        self.probe_count = 0

    async def run(self, result: Result) -> None:
        targets = [ep for ep in result.endpoints
                   if ep.params and ep.method in ("GET", "POST")][: self.max_endpoints]
        if not targets:
            result.metadata.setdefault("active", {})["note"] = "no parameterised endpoints to probe"
            return
        async with Fetcher(self.scope, timeout=self.timeout, delay=self.delay) as fetcher:
            for ep in targets:
                for param in list(dict.fromkeys(ep.params))[: self.max_params]:
                    try:
                        await self._probe_param(fetcher, result, ep, param)
                    except ScopeError as exc:
                        result.errors.append(f"active {ep.url} [{param}]: {exc}")
                        return   # scope breach: stop active probing entirely
                    except Exception as exc:  # noqa: BLE001
                        result.errors.append(
                            f"active {ep.url} [{param}]: {type(exc).__name__}: {str(exc)[:120]}")
        result.metadata.setdefault("active", {})["probes"] = self.probe_count

    async def _send(self, fetcher: Fetcher, ep, param: str, value: str):
        other = {k: "1" for k in ep.params if k != param}
        if ep.method == "POST":
            data = dict(other)
            data[param] = value
            return await fetcher.fetch(ep.url, "POST", data=data)
        params = dict(other)
        params[param] = value
        return await fetcher.fetch(ep.url, "GET", params=params)

    async def _probe_param(self, fetcher: Fetcher, result: Result, ep, param: str) -> None:
        # Baseline with a neutral marker.
        baseline = await self._send(fetcher, ep, param, _MARK + "1")
        self.probe_count += 1
        base_sql_error = bool(_SQL_ERROR_RE.search(baseline.text))

        # --- reflection (XSS) -------------------------------------------------
        refl = await self._send(fetcher, ep, param, _REFLECT_PAYLOAD)
        self.probe_count += 1
        if "<fhq9>" in refl.text:
            self._upsert(result, "XSS", ep, param, STATUS_EVIDENCE, 0.85,
                         "Input reflected unencoded (< and > preserved): "
                         + _snippet(refl.text, "<fhq9>"),
                         "high")
        elif _MARK in refl.text:
            self._upsert(result, "XSS", ep, param, STATUS_INDICATOR, 0.5,
                         "Input is reflected but angle brackets were encoded/stripped: "
                         + _snippet(refl.text, _MARK),
                         "low")

        # --- error-based SQLi -------------------------------------------------
        sqli = await self._send(fetcher, ep, param, _SQLI_PAYLOAD)
        self.probe_count += 1
        if not base_sql_error and _SQL_ERROR_RE.search(sqli.text):
            m = _SQL_ERROR_RE.search(sqli.text)
            self._upsert(result, "SQLI", ep, param, STATUS_EVIDENCE, 0.8,
                         "A single quote triggered a DB error not present in the baseline: "
                         + (m.group(0)[:120] if m else ""),
                         "high")

        # --- SSTI arithmetic --------------------------------------------------
        for payload in _SSTI_PAYLOADS:
            ssti = await self._send(fetcher, ep, param, payload)
            self.probe_count += 1
            if _SSTI_EXPECT in ssti.text and _SSTI_EXPECT not in baseline.text:
                self._upsert(result, "SSTI", ep, param, STATUS_EVIDENCE, 0.85,
                             f"Template arithmetic evaluated server-side ({payload} -> {_SSTI_EXPECT})",
                             "high")
                break

        # --- intrusive: time-based command injection (confirmed only) ---------
        if self.confirm_intrusive:
            timed = await self._send(fetcher, ep, param, _CMDI_PAYLOAD)
            self.probe_count += 1
            if timed.elapsed_ms >= (_SLEEP_SECONDS * 1000 - 500) and \
                    baseline.elapsed_ms < (_SLEEP_SECONDS * 1000 - 500):
                self._upsert(result, "COMMAND_INJECTION", ep, param, STATUS_EVIDENCE, 0.85,
                             f"Response delayed ~{timed.elapsed_ms} ms after a sleep payload "
                             f"(baseline {baseline.elapsed_ms} ms)",
                             "critical")

    def _upsert(self, result: Result, category: str, ep, param: str, status: str,
                confidence: float, evidence: str, severity: str,
                only_if_absent: bool = False) -> None:
        finding = Finding(
            category=category,
            title=f"{CATEGORIES[category]} - {status}",
            location=ep.url, entry_point=param, method=ep.method,
            evidence=evidence, severity=severity, confidence=confidence,
            status=status, source="active",
            recommendation="Reproduce with the commands below to verify by hand.",
        )
        if only_if_absent:
            key = finding.dedup_key()
            if any(f.dedup_key() == key for f in result.findings):
                return
        result.add_finding(finding)
