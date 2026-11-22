"""Authorised, bounded, same-scope crawler.

Discovers the attack surface of a CTF web target:

* pages (links), with de-duplication by URL *and* by endpoint "shape" so a
  parameter that is really an object id (``?id=1``, ``?id=2`` ...) does not
  explode the crawl;
* forms with their method, action and input names (GET & POST entry points);
* GET query parameters;
* cookies (with Secure / HttpOnly / SameSite flags and privilege-name hints);
* JavaScript (inline and external) and the API endpoints referenced in it
  (``fetch`` / ``axios`` / ``XMLHttpRequest`` / relative ``/api/...`` paths).

The crawler only *reads*: GET requests to in-scope URLs, redirects re-validated
per hop, response bodies capped in size. It never submits forms or sends
payloads - that is the job of the opt-in active prober.
"""

from __future__ import annotations

import re
from collections import deque
from typing import Callable
from urllib.parse import urljoin, urldefrag, urlparse, urlunparse, parse_qsl, urlencode

from bs4 import BeautifulSoup

from .http_client import Fetcher
from .models import Result, Endpoint, Cookie
from .pages import Page
from .scope import Scope, ScopeError

# API endpoints referenced from JavaScript.
JS_ENDPOINT_RE = re.compile(
    r"""(?:fetch|axios(?:\.(?:get|post|put|delete|patch))?|\.open)\s*\(\s*["'`]([^"'`]+)["'`]"""
    r"""|["'`](/(?:api|rest|graphql|v\d)/[^"'`\s]+)["'`]""",
    re.I,
)
# Privilege-ish cookie names.
PRIV_COOKIE_RE = re.compile(r"(admin|role|priv|is_?staff|level|group|auth|session|token)", re.I)
PRIV_VALUE_RE = re.compile(r"\b(admin|root|superuser|true|1)\b", re.I)

CONTENT_KINDS = ("text/", "javascript", "json", "xml", "xhtml")


def classify(content_type: str, url: str) -> str:
    ct = content_type.lower()
    if "html" in ct:
        return "html"
    if "javascript" in ct or url.split("?")[0].endswith(".js"):
        return "js"
    if "json" in ct:
        return "json"
    if "xml" in ct:
        return "xml"
    return "text"


def normalize_url(url: str) -> str:
    """Canonical form for exact de-duplication (defrag, sort query keys)."""
    url, _ = urldefrag(url)
    p = urlparse(url)
    host = (p.hostname or "").lower()
    netloc = host
    if p.port and not ((p.scheme == "http" and p.port == 80) or (p.scheme == "https" and p.port == 443)):
        netloc = f"{host}:{p.port}"
    query = urlencode(sorted(parse_qsl(p.query, keep_blank_values=True)))
    path = p.path or "/"
    return urlunparse((p.scheme, netloc, path, "", query, ""))


def endpoint_shape(url: str) -> tuple:
    """Shape key: (path, sorted param names) - groups ?id=1 and ?id=2 together."""
    p = urlparse(url)
    params = tuple(sorted(k for k, _ in parse_qsl(p.query, keep_blank_values=True)))
    return ((p.hostname or "").lower(), p.path or "/", params)


def _param_names(url: str) -> list[str]:
    return [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]


async def crawl(
    seed: str,
    scope: Scope,
    *,
    max_pages: int = 30,
    max_depth: int = 2,
    per_shape_limit: int = 3,
    timeout: float = 10.0,
    delay: float = 0.25,
    max_bytes: int = 1_048_576,
    on_progress: Callable[[dict], None] | None = None,
) -> tuple[Result, list[Page]]:
    """Crawl ``seed`` within ``scope`` and return (result, fetched pages)."""
    result = Result(target=seed)
    result.metadata["scope"] = scope.describe()
    pages: list[Page] = []

    seen_norm: set[str] = set()
    shape_count: dict[tuple, int] = {}
    cookie_names: set[str] = set()

    # Seed the queue with the target plus always-public discovery files.
    root = f"{urlparse(seed).scheme}://{urlparse(seed).netloc}"
    queue: deque[tuple[str, int]] = deque([(seed, 0)])
    for extra in ("/robots.txt", "/sitemap.xml"):
        candidate = root + extra
        if scope.in_scope(candidate):
            queue.append((candidate, max_depth))   # depth=max so they are leaves

    def progress(url: str):
        if on_progress:
            on_progress({
                "fetched": len(pages),
                "queued": len(queue),
                "max_pages": max_pages,
                "current": url,
                "findings": len(result.findings),
            })

    async with Fetcher(scope, timeout=timeout, delay=delay,
                       max_bytes=max_bytes) as fetcher:
        while queue and len(pages) < max_pages:
            url, depth = queue.popleft()
            norm = normalize_url(url)
            if norm in seen_norm:
                continue
            shape = endpoint_shape(url)
            if shape_count.get(shape, 0) >= per_shape_limit:
                continue
            if not scope.in_scope(url):
                continue
            seen_norm.add(norm)
            shape_count[shape] = shape_count.get(shape, 0) + 1
            progress(url)

            try:
                fr = await fetcher.fetch(url, "GET")
            except ScopeError as exc:
                result.errors.append(f"{url}: {exc}")
                continue
            except Exception as exc:  # noqa: BLE001 - network errors must not abort the scan
                result.errors.append(f"{url}: {type(exc).__name__}: {str(exc)[:160]}")
                continue

            result.scanned.append(fr.final_url)
            if fr.redirect_chain:
                result.metadata.setdefault("redirects", []).append(
                    {"from": url, "chain": fr.redirect_chain, "status": fr.status}
                )

            # Record any cookies seen on this response.
            _record_cookies(result, fr.set_cookies, cookie_names)

            ctype = fr.content_type
            if fr.status and not any(x in ctype for x in CONTENT_KINDS) and ctype:
                result.metadata.setdefault("http", []).append(
                    {"url": fr.final_url, "status": fr.status, "content_type": ctype, "skipped": "binary"}
                )
                continue

            kind = classify(ctype, fr.final_url)
            page = Page(
                url=url, final_url=fr.final_url, status=fr.status,
                content_type=ctype, kind=kind, headers=fr.headers,
                text=fr.text, elapsed_ms=fr.elapsed_ms,
                redirect_chain=fr.redirect_chain, set_cookies=fr.set_cookies,
            )
            pages.append(page)
            result.metadata.setdefault("http", []).append(
                {"url": fr.final_url, "status": fr.status, "content_type": ctype,
                 "elapsed_ms": fr.elapsed_ms, "bytes": len(fr.text)}
            )

            # Record this page's own GET parameters as an endpoint.
            params = _param_names(fr.final_url)
            if params:
                result.add_endpoint(Endpoint(
                    url=_strip_query(fr.final_url), method="GET",
                    params=params, source="link",
                ))

            if kind == "html":
                _extract_html(result, page, scope, queue, depth, max_depth)
            if kind in ("html", "js"):
                _extract_js_endpoints(result, page, scope)

            progress(url)

    result.metadata["requests"] = fetcher.request_count
    result.metadata["pages_fetched"] = len(pages)
    return result, pages


def _strip_query(url: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))


def _record_cookies(result: Result, raw_cookies: list[str], seen: set[str]) -> None:
    for raw in raw_cookies:
        if "=" not in raw:
            continue
        first = raw.split(";")[0]
        name, _, value = first.partition("=")
        name = name.strip()
        if not name or name in seen:
            continue
        seen.add(name)
        attrs = raw.lower()
        looks_priv = bool(PRIV_COOKIE_RE.search(name)) or bool(PRIV_VALUE_RE.search(value))
        samesite = ""
        m = re.search(r"samesite=(\w+)", attrs)
        if m:
            samesite = m.group(1)
        result.cookies.append(Cookie(
            name=name,
            secure="secure" in attrs,
            httponly="httponly" in attrs,
            samesite=samesite,
            looks_privilege=looks_priv,
        ))


def _extract_html(result, page, scope, queue, depth, max_depth) -> None:
    soup = BeautifulSoup(page.text, "html.parser")

    # Links & script sources → crawl frontier + JS endpoints.
    if depth < max_depth:
        for tag, attr in (("a", "href"), ("link", "href"), ("script", "src"),
                          ("form", "action"), ("iframe", "src")):
            for el in soup.find_all(tag):
                link = el.get(attr)
                if not link:
                    continue
                candidate = urldefrag(urljoin(page.final_url, link))[0]
                if scope.in_scope(candidate):
                    queue.append((candidate, depth + 1))

    # Forms → GET/POST endpoints with field names.
    for i, form in enumerate(soup.find_all("form"), 1):
        action = form.get("action") or page.final_url
        action_url = urldefrag(urljoin(page.final_url, action))[0]
        method = (form.get("method") or "GET").upper()
        enctype = (form.get("enctype") or "").lower()
        fields = [el.get("name") for el in form.find_all(["input", "textarea", "select"])
                  if el.get("name")]
        has_file = any((el.get("type") or "").lower() == "file"
                       for el in form.find_all("input"))
        result.add_endpoint(Endpoint(
            url=_strip_query(action_url) if method == "GET" else action_url,
            method=method, params=fields, source="form",
            enctype=enctype,
            note="file-upload" if has_file else "",
        ))
        result.metadata.setdefault("forms", []).append({
            "page": page.final_url, "index": i, "action": action_url,
            "method": method, "enctype": enctype, "fields": fields,
            "file_input": has_file,
        })


def _extract_js_endpoints(result, page, scope) -> None:
    text = page.text[:500_000]
    found = set()
    for m in JS_ENDPOINT_RE.finditer(text):
        raw = m.group(1) or m.group(2)
        if not raw or raw.startswith(("data:", "mailto:", "javascript:", "#")):
            continue
        candidate = urldefrag(urljoin(page.final_url, raw))[0]
        if not candidate.startswith(("http://", "https://")):
            continue
        if not scope.in_scope(candidate):
            continue
        if candidate in found:
            continue
        found.add(candidate)
        result.add_endpoint(Endpoint(
            url=_strip_query(candidate), method="GET",
            params=_param_names(candidate), source="api" if "/api" in candidate else "js",
            note="referenced in JavaScript",
        ))
