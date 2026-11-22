"""A tiny, deliberately vulnerable HTTP app used only by the test-suite.

It mimics the shapes a Web Jeopardy CTF challenge exposes so the scanner can be
exercised end-to-end against localhost. It is NOT a real target and must never
be deployed. Started on an ephemeral 127.0.0.1 port by the integration tests.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

INDEX = """<!doctype html><html><head><title>Vuln CTF Demo</title></head><body>
<h1>Challenge</h1>
<!-- TODO: remove debug flag before release: flag{demo_hint_not_real} -->
<a href="/search?q=hello">search</a>
<a href="/item?id=1">item 1</a>
<a href="/render?name=guest">greeting</a>
<a href="/admin">admin</a>
<form action="/login" method="post">
  <input name="username"><input name="password" type="password">
  <input type="hidden" name="csrf" value="abc123">
</form>
<form action="/upload" method="post" enctype="multipart/form-data">
  <input type="file" name="avatar">
</form>
<script>
const api = "/api/user?user_id=1";
fetch("/api/profile?url=http://example.com/avatar");
</script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence test output
        pass

    def _send(self, body: str, status: int = 200, cookies=None, ctype="text/html"):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for c in (cookies or []):
            self.send_header("Set-Cookie", c)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        path = u.path

        if path == "/":
            self._send(INDEX, cookies=["session=deadbeef; Path=/", "role=user; Path=/"])
        elif path == "/robots.txt":
            self._send("User-agent: *\nDisallow: /secret-flag\nDisallow: /admin\n", ctype="text/plain")
        elif path == "/search":
            term = q.get("q", [""])[0]
            # Reflected XSS: echoes input unencoded.
            self._send(f"<html><body>Results for: {term}</body></html>")
        elif path == "/item":
            val = q.get("id", [""])[0]
            if "'" in val:
                # Error-based SQLi signal.
                self._send("<html><body>You have an error in your SQL syntax; "
                           "check the manual near ''' at line 1</body></html>", status=500)
            else:
                self._send(f"<html><body>Item #{val}: widget</body></html>")
        elif path == "/render":
            name = q.get("name", [""])[0]
            # Naive SSTI: evaluates {{7*7}} and ${7*7}.
            rendered = name.replace("{{7*7}}", "49").replace("${7*7}", "49")
            self._send(f"<html><body>Hello {rendered}</body></html>")
        elif path == "/admin":
            # Broken access control: no auth check.
            self._send("<html><body><h1>Admin panel</h1>users, config</body></html>")
        elif path.startswith("/api/"):
            self._send('{"ok":true,"path":"' + path + '"}', ctype="application/json")
        else:
            self._send("<html><body>not found</body></html>", status=404)

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/login":
            self._send("<html><body>logged in</body></html>",
                       cookies=["session=loggedin; Path=/"])
        else:
            self._send("<html><body>ok</body></html>")


class FixtureServer:
    def __init__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
