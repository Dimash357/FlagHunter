"""Scope enforcement and target validation.

Every outbound request is checked against a :class:`Scope` so the scanner can
never wander off the authorised CTF target (and, in particular, never touch the
competition platform itself). The scope understands:

* the set of host names the user authorised (seeded from the target URL);
* whether private / VPN / loopback addresses are allowed (``allow_private``);
* which TCP ports are allowed (a safe web default, plus anything the user
  explicitly permits, or "any port" on demand);
* redirect targets - a redirect that leaves the scope is reported, not followed.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# Ports commonly used by CTF web challenges behind a VPN lab network.
DEFAULT_PORTS = {80, 443, 8000, 8080, 8443, 3000, 5000, 8888, 8081, 9000}


class ScopeError(ValueError):
    """Raised when a URL is rejected by scope / validation rules."""


def _host_port(url: str) -> tuple[str, int, str]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ScopeError("Only http(s) URLs are accepted")
    if not parsed.hostname:
        raise ScopeError("URL has no host")
    if parsed.username or parsed.password:
        raise ScopeError("URLs with embedded credentials are not accepted")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.hostname.lower(), port, parsed.scheme


def resolve_ips(host: str, port: int) -> set[ipaddress._BaseAddress]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScopeError(f"DNS lookup failed for {host}: {exc}") from exc
    ips = {ipaddress.ip_address(info[4][0]) for info in infos}
    if not ips:
        raise ScopeError(f"No addresses resolved for {host}")
    return ips


class Scope:
    def __init__(
        self,
        seed_url: str,
        *,
        allow_private: bool = False,
        extra_ports: set[int] | None = None,
        allow_any_port: bool = False,
        extra_hosts: set[str] | None = None,
        max_redirects: int = 5,
    ):
        host, port, _ = _host_port(seed_url)
        self.allow_private = allow_private
        self.allow_any_port = allow_any_port
        self.ports = set(DEFAULT_PORTS) | (extra_ports or set())
        # The seed port is always allowed (handles arbitrary lab ports cleanly).
        self.ports.add(port)
        self.hosts = {host} | {h.lower() for h in (extra_hosts or set())}
        self.max_redirects = max_redirects
        self.seed_host = host

    # -- predicates -----------------------------------------------------------
    def port_allowed(self, port: int) -> bool:
        return self.allow_any_port or port in self.ports

    def host_allowed(self, host: str) -> bool:
        return host.lower() in self.hosts

    def in_scope(self, url: str) -> bool:
        """Cheap, no-DNS check: host and port are authorised."""
        try:
            host, port, _ = _host_port(url)
        except ScopeError:
            return False
        return self.host_allowed(host) and self.port_allowed(port)

    # -- full validation (used before an actual request) ----------------------
    def validate(self, url: str) -> str:
        """Validate scheme, host, port, and resolve+classify IPs.

        Returns the (lower-cased) host on success, raises :class:`ScopeError`.
        """
        host, port, scheme = _host_port(url)
        if not self.host_allowed(host):
            raise ScopeError(
                f"Host '{host}' is outside the authorised scope "
                f"({', '.join(sorted(self.hosts))})"
            )
        if not self.port_allowed(port):
            raise ScopeError(
                f"Port {port} is not allowed. Use --ports {port} or --allow-any-port "
                "if this CTF target really listens there."
            )
        ips = resolve_ips(host, port)
        if not self.allow_private and any(not ip.is_global for ip in ips):
            raise ScopeError(
                f"'{host}' resolves to a private/loopback/VPN address. "
                "Pass --allow-private to scan an authorised VPN/lab network."
            )
        return host

    def check_redirect(self, location_url: str) -> bool:
        """True if a redirect may be followed automatically (still in scope)."""
        return self.in_scope(location_url)

    def describe(self) -> dict:
        return {
            "hosts": sorted(self.hosts),
            "allow_private": self.allow_private,
            "allow_any_port": self.allow_any_port,
            "ports": sorted(self.ports),
            "max_redirects": self.max_redirects,
        }


def parse_ports(spec: str | None) -> set[int]:
    """Parse a comma/space separated port list like '8081,9000 3001'."""
    if not spec:
        return set()
    out: set[int] = set()
    for chunk in spec.replace(",", " ").split():
        chunk = chunk.strip()
        if not chunk:
            continue
        if not chunk.isdigit() or not (1 <= int(chunk) <= 65535):
            raise ScopeError(f"Invalid port: {chunk!r}")
        out.add(int(chunk))
    return out
