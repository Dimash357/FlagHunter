"""A small scope-aware HTTP fetcher built on httpx.

Responsibilities:

* transparent decompression (gzip / deflate / br - httpx handles the first two,
  and ``brotli`` is pulled in via requirements for ``br``);
* redirects are followed **manually** so every hop is re-validated against the
  :class:`~flaghunter.scope.Scope` - a redirect that would leave scope stops the
  chain and is reported instead of followed;
* hard caps on response size, redirect depth and timeout;
* a single connection with a polite delay, so a lab host is never hammered.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import httpx

from .scope import Scope, ScopeError

REDIRECT_CODES = {301, 302, 303, 307, 308}


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int
    headers: dict[str, str]
    text: str
    content_type: str = ""
    elapsed_ms: int = 0
    redirect_chain: list[str] = field(default_factory=list)
    set_cookies: list[str] = field(default_factory=list)
    truncated: bool = False


class Fetcher:
    def __init__(
        self,
        scope: Scope,
        *,
        timeout: float = 10.0,
        delay: float = 0.25,
        max_bytes: int = 1_048_576,
        user_agent: str = "FlagHunter-CTF/2.0 (authorized-lab-scan)",
    ):
        self.scope = scope
        self.timeout = timeout
        self.delay = delay
        self.max_bytes = max_bytes
        self.user_agent = user_agent
        self._client: httpx.AsyncClient | None = None
        self.request_count = 0

    async def __aenter__(self) -> "Fetcher":
        limits = httpx.Limits(max_connections=2, max_keepalive_connections=1)
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,       # we follow manually to enforce scope
            limits=limits,
            trust_env=False,              # ignore ambient proxy/env for lab safety
            headers={
                "User-Agent": self.user_agent,
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate, br",
            },
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def fetch(
        self,
        url: str,
        method: str = "GET",
        *,
        data: dict | None = None,
        params: dict | None = None,
        headers: dict | None = None,
        follow_redirects: bool = True,
    ) -> FetchResult:
        """Validate scope, issue the request, and follow in-scope redirects."""
        assert self._client is not None, "use 'async with Fetcher(...)'"
        chain: list[str] = []
        current = url
        set_cookies: list[str] = []

        for hop in range(self.scope.max_redirects + 1):
            self.scope.validate(current)      # raises ScopeError if out of scope
            await asyncio.sleep(self.delay)
            self.request_count += 1
            resp = await self._client.request(
                method if hop == 0 else "GET",
                current,
                data=data if hop == 0 else None,
                params=params if hop == 0 else None,
                headers=headers,
            )
            set_cookies.extend(resp.headers.get_list("set-cookie"))
            elapsed_ms = int(resp.elapsed.total_seconds() * 1000)

            if follow_redirects and resp.status_code in REDIRECT_CODES:
                location = resp.headers.get("location")
                if not location:
                    break
                nxt = str(resp.url.join(location))
                if not self.scope.check_redirect(nxt):
                    # Out-of-scope redirect: stop and report, do not follow.
                    return FetchResult(
                        url=url, final_url=current, status=resp.status_code,
                        headers=dict(resp.headers), text="",
                        content_type=resp.headers.get("content-type", "").lower(),
                        elapsed_ms=elapsed_ms, redirect_chain=chain,
                        set_cookies=set_cookies,
                    )
                chain.append(nxt)
                current = nxt
                continue

            body = resp.content
            truncated = False
            if len(body) > self.max_bytes:
                body = body[: self.max_bytes]
                truncated = True
            text = body.decode(resp.encoding or "utf-8", errors="replace")
            return FetchResult(
                url=url, final_url=str(resp.url), status=resp.status_code,
                headers=dict(resp.headers), text=text,
                content_type=resp.headers.get("content-type", "").lower(),
                elapsed_ms=elapsed_ms, redirect_chain=chain,
                set_cookies=set_cookies, truncated=truncated,
            )

        # Exhausted redirect budget.
        raise ScopeError(f"Too many redirects from {url}")
