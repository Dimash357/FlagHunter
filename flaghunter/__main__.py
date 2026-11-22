"""FlagHunter command-line interface (Linux / Kali)."""

from __future__ import annotations

import argparse
import asyncio
import sys

from dotenv import load_dotenv

from .models import CATEGORIES, STATUS_EVIDENCE, STATUS_INDICATOR
from .scope import ScopeError, parse_ports
from .service import scan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="flaghunter",
        description="FlagHunter - authorized Web Jeopardy CTF triage scanner.",
        epilog="Scan only the authorised CTF target. Never scan the competition platform.",
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--url", help="Authorized CTF challenge URL")
    g.add_argument("--path", help="Local file or extracted challenge folder")

    p.add_argument("--authorized", action="store_true",
                   help="Confirm you are authorized to scan the target (required for --url)")
    p.add_argument("--allow-private", action="store_true",
                   help="Allow private / VPN / loopback targets (lab networks)")
    p.add_argument("--allow-any-port", action="store_true",
                   help="Allow any TCP port (non-standard CTF ports)")
    p.add_argument("--ports", help="Extra allowed ports, e.g. 8081,9000")
    p.add_argument("--host", action="append", default=[],
                   help="Additional in-scope host (repeatable)")

    p.add_argument("--active", action="store_true",
                   help="Enable safe active checks (input reflection, DB errors, template math)")
    p.add_argument("--confirm-intrusive", action="store_true",
                   help="Also run the intrusive time-based probe (benign sleep); implies --active")

    p.add_argument("--ai", action="store_true", help="Request Gemini review of ambiguous findings")
    p.add_argument("--out", default="output", help="Output directory (default: output)")
    p.add_argument("--max-pages", type=int, default=30)
    p.add_argument("--max-depth", type=int, default=2)
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--json", action="store_true", help="Print the JSON report to stdout")
    return p


def _print_summary(result) -> None:
    sm = result.metadata.get("summary", {})
    print("\n=== FlagHunter summary ===")
    print(f"Target        : {result.target}")
    print(f"Scanned       : {len(result.scanned)} resources, {len(result.endpoints)} endpoints")
    print(f"Findings      : {sm.get('vuln_findings', 0)} vuln / {len(result.findings)} total")
    print(f"Flag hints    : {len(result.flag_hints)}   Cookies: {len(result.cookies)}   Errors: {len(result.errors)}")
    cats = sm.get("categories", {})
    if cats:
        print("By category   : " + ", ".join(f"{k}={v}" for k, v in sorted(cats.items())))

    top = result.most_likely(8)
    if top:
        print("\n--- Most likely vulnerabilities (verify manually) ---")
        for f in top:
            mark = "‼" if f.status == STATUS_EVIDENCE else ("•" if f.status == STATUS_INDICATOR else "·")
            ep = f" [{f.entry_point}]" if f.entry_point else ""
            print(f"{mark} {CATEGORIES.get(f.category, f.category)} ({f.status}, conf {f.confidence:.2f})"
                  f"\n    {f.method} {f.location}{ep}")
            if f.evidence:
                print(f"    evidence: {f.evidence[:120]}")
            if f.commands:
                print(f"    try: {f.commands[1] if len(f.commands) > 1 else f.commands[0]}")

    hints = result.flag_hints[:8]
    if hints:
        print("\n--- Flag hints ---")
        for h in hints:
            print(f"· [{h.kind}] {h.detail}  ({h.location})")

    ai = result.metadata.get("ai", {})
    if ai.get("status") == "ok":
        print("\n--- AI review ---")
        print(ai.get("analysis", "")[:2000])
    elif ai.get("status") not in (None, "disabled"):
        print(f"\nAI review: {ai.get('status')} - {ai.get('reason', '')}")


def main(argv=None) -> int:
    load_dotenv()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.url and not args.authorized:
        parser.error("--url requires --authorized to confirm you may scan the target")
    if not (1 <= args.max_pages <= 100):
        parser.error("--max-pages must be 1..100")
    if not (0 <= args.max_depth <= 5):
        parser.error("--max-depth must be 0..5")

    try:
        ports = parse_ports(args.ports)
    except ScopeError as exc:
        parser.error(str(exc))

    active = args.active or args.confirm_intrusive

    try:
        result, report = asyncio.run(scan(
            url=args.url, path=args.path, authorized=args.authorized,
            allow_private=args.allow_private, allow_any_port=args.allow_any_port,
            ports=ports, extra_hosts=set(args.host),
            active=active, confirm_intrusive=args.confirm_intrusive,
            ai=args.ai, out=args.out,
            max_pages=args.max_pages, max_depth=args.max_depth, timeout=args.timeout,
        ))
    except (ValueError, ScopeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    _print_summary(result)
    print(f"\nHTML report : {report}")
    print(f"JSON report : {report.parent / 'report.json'}")

    if args.json:
        import json
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
