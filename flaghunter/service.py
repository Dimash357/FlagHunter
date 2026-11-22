"""Scan orchestration: crawl -> local detectors -> flag hints -> (opt) active
probes -> playbooks -> (opt) AI review -> report."""

from __future__ import annotations

from typing import Callable

from . import flaghints
from .analyzer import Analyzer
from .ai import GeminiReviewer
from .crawler import crawl
from .detectors import run_passive, run_structural, ActiveProber
from .models import Result, CATEGORIES
from .playbook import build as build_playbook
from .report import save_report
from .rules import PatternEngine
from .scope import Scope


def _is_http(location: str) -> bool:
    return location.startswith("http://") or location.startswith("https://")


def _enctype_for(result: Result, finding) -> str:
    for ep in result.endpoints:
        if ep.url == finding.location and ep.method == finding.method:
            return ep.enctype
    return ""


def attach_playbooks(result: Result) -> None:
    """Give every vulnerability finding a manual-verification playbook."""
    for f in result.findings:
        if f.category not in CATEGORIES or f.verification:
            continue
        if _is_http(f.location):
            pb = build_playbook(f.category, f.location, f.entry_point, f.method,
                                _enctype_for(result, f))
            f.verification = pb["verification"]
            f.commands = pb["commands"]
            f.expected = pb["expected"]
        else:
            # Local file finding: no live target to curl.
            pb = build_playbook(f.category, "http://TARGET" + "/", f.entry_point, f.method)
            f.verification = ["Static match in a local file - rerun against the live target:"] + pb["verification"]
            f.commands = ["# Replace http://TARGET with the live app, then:"] + pb["commands"]
            f.expected = pb["expected"]


def _summary(result: Result) -> dict:
    ml = result.most_likely(1)
    return {
        "total_findings": len(result.findings),
        "vuln_findings": sum(1 for f in result.findings if f.category in CATEGORIES),
        "endpoints": len(result.endpoints),
        "cookies": len(result.cookies),
        "flag_hints": len(result.flag_hints),
        "errors": len(result.errors),
        "top_category": ml[0].category if ml else None,
        "top_title": ml[0].title if ml else None,
        "categories": result.category_counts(),
    }


async def scan(
    url: str | None = None,
    path: str | None = None,
    *,
    authorized: bool = False,
    allow_private: bool = False,
    allow_any_port: bool = False,
    ports: set[int] | None = None,
    extra_hosts: set[str] | None = None,
    active: bool = False,
    confirm_intrusive: bool = False,
    ai: bool = False,
    out: str = "output",
    max_pages: int = 30,
    max_depth: int = 2,
    timeout: float = 10.0,
    on_progress: Callable[[dict], None] | None = None,
) -> tuple[Result, object]:
    if bool(url) == bool(path):
        raise ValueError("Provide exactly one of url or path")
    if url and not authorized:
        raise ValueError("Web scanning requires explicit authorization (--authorized)")

    engine = PatternEngine()

    if url:
        scope = Scope(
            url, allow_private=allow_private, allow_any_port=allow_any_port,
            extra_ports=ports or set(), extra_hosts=extra_hosts or set(),
        )
        # Validate the seed up-front so scope/DNS errors surface immediately.
        scope.validate(url)
        result, pages = await crawl(
            url, scope, max_pages=max_pages, max_depth=max_depth,
            timeout=timeout, on_progress=on_progress,
        )
        run_passive(result, pages, engine)
        run_structural(result)
        flaghints.collect(result, pages)
        if active:
            prober = ActiveProber(scope, confirm_intrusive=confirm_intrusive, timeout=timeout)
            await prober.run(result)
            run_structural(result)   # pick up anything the probes added shapes for
        result.metadata["active_enabled"] = active
        result.metadata["confirm_intrusive"] = confirm_intrusive
    else:
        result = Analyzer(engine).scan_path(path)

    attach_playbooks(result)

    if ai:
        result.metadata["ai"] = await GeminiReviewer().review(result.findings)
    else:
        result.metadata["ai"] = {"status": "disabled"}

    result.metadata["summary"] = _summary(result)
    report = save_report(result, out)
    return result, report
