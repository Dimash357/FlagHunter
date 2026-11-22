"""CTF flag-location hints.

Points the operator at *where* a flag might be, using only content that is
already in the fetched responses. It does **not** exploit anything or extract
protected data - it surfaces:

* flag-format tokens already visible in a response (value redacted);
* HTML comments that mention flag/secret/todo/credentials;
* hidden form fields with interesting names/values;
* JavaScript variables named like flag/secret/key/token;
* interesting paths referenced in content or disallowed in robots.txt
  (e.g. /flag.txt, /backup, /.git, /.env, /admin);
* long base64 blobs - and, only when a decode trivially reveals a flag marker,
  a redacted note that it decodes to one.
"""

from __future__ import annotations

import base64
import re
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from .models import FlagHint
from .pages import Page

_FLAG_TOKEN_RE = re.compile(
    r"\b(?:flag|ctf|htb|thm|pico(?:CTF)?|actf|pwn|key|secret)\{[^}\r\n]{1,160}\}", re.I)
_COMMENT_KEYWORD_RE = re.compile(
    r"(flag|secret|todo|fixme|hack|password|passwd|credential|api[_-]?key|hidden|debug|backdoor|remove before)", re.I)
_JS_VAR_RE = re.compile(
    r"""(?:var|let|const)\s+(\w*(?:flag|secret|key|token|pass|cred)\w*)\s*=\s*["'`]([^"'`]{1,160})["'`]""", re.I)
_SUSP_PATH_RE = re.compile(
    r"""["'(\s](/(?:flag|secret|backup|admin|private|hidden|uploads?|files?|download|debug|config|dump)[\w./-]*|/\.(?:git|env|svn|htpasswd|ssh)[\w./-]*|[\w./-]+\.(?:bak|old|swp|sql|zip|tar\.gz|tgz|log|conf|config|env))\b""", re.I)
_BASE64_RE = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")


def collect(result, pages: list[Page]) -> None:
    seen: set[tuple] = set()

    def add(location: str, kind: str, detail: str, confidence: float) -> None:
        key = (location, kind, detail)
        if key in seen:
            return
        seen.add(key)
        result.flag_hints.append(FlagHint(location=location, kind=kind,
                                          detail=detail, confidence=confidence))

    for page in pages:
        text = page.text
        loc = page.final_url

        # robots.txt / sitemap: Disallow and <loc> entries are prime hint sources.
        if loc.endswith("robots.txt"):
            for line in text.splitlines():
                line = line.strip()
                if line.lower().startswith(("disallow:", "allow:")) and len(line.split(":", 1)) == 2:
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        add(loc, "path", f"robots.txt references {path}", 0.4)
            continue
        if loc.endswith("sitemap.xml"):
            for m in re.finditer(r"<loc>\s*([^<]+?)\s*</loc>", text, re.I):
                add(loc, "path", f"sitemap lists {m.group(1)}", 0.25)
            continue

        # Visible flag tokens (redacted).
        for _ in _FLAG_TOKEN_RE.finditer(text):
            add(loc, "keyword", "A flag-format token is present in this response (value redacted)", 0.9)

        # Comments.
        for cm in re.finditer(r"<!--(.*?)-->", text, re.S):
            body = cm.group(1).strip()
            if _COMMENT_KEYWORD_RE.search(body):
                add(loc, "comment", "HTML comment of interest: " + body[:120].replace("\n", " "), 0.5)

        # JS variables.
        for jm in _JS_VAR_RE.finditer(text):
            name = jm.group(1)
            add(loc, "js-var", f"JS variable '{name}' assigned a string literal (inspect its value)", 0.45)

        # Interesting paths referenced in content.
        paths = set()
        for pm in _SUSP_PATH_RE.finditer(text):
            paths.add(pm.group(1))
        for path in list(paths)[:15]:
            add(loc, "path", f"References {path} - fetch it manually: curl -sik {urljoin(loc, path)}", 0.3)

        # Hidden form fields.
        if page.kind == "html":
            soup = BeautifulSoup(text, "html.parser")
            for inp in soup.find_all("input", attrs={"type": "hidden"}):
                name = inp.get("name") or "(unnamed)"
                value = (inp.get("value") or "")[:60]
                add(loc, "hidden-field",
                    f"Hidden input '{name}'" + (f" = {value}" if value else ""), 0.35)

        # Base64 blobs that trivially decode to a flag marker (redacted).
        for bm in _BASE64_RE.finditer(text):
            token = bm.group(0)
            if len(token) > 400:
                continue
            try:
                decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=False)
                dtext = decoded.decode("utf-8", errors="strict")
            except (ValueError, UnicodeDecodeError):
                continue
            if _FLAG_TOKEN_RE.search(dtext):
                add(loc, "encoded",
                    "A base64 string on this page decodes to a flag-format token (value redacted)", 0.8)
