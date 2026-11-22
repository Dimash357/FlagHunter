"""Local file / directory analysis (for downloaded CTF challenge bundles).

Complements the remote crawler: point it at extracted challenge files and it
runs the same signature engine over them (source code included), extracts forms
from local HTML, and collects flag hints. Archives are never auto-extracted -
unpack trusted bundles yourself first.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from .models import Result, Endpoint
from .rules import PatternEngine

ALLOWED_EXT = {
    ".html", ".htm", ".js", ".ts", ".jsx", ".tsx", ".py", ".php", ".xml",
    ".json", ".txt", ".css", ".java", ".go", ".rb", ".yaml", ".yml", ".md",
    ".env", ".ini", ".conf", ".sql", ".sh",
}
IGNORE_DIRS = {".git", "node_modules", "env", ".venv", "venv", "__pycache__",
               "output", "dist", "build", ".idea"}
SOURCE_EXT = {".py", ".php", ".java", ".go", ".rb", ".sh"}


def _kind_for(suffix: str) -> str:
    suffix = suffix.lower()
    if suffix in {".html", ".htm"}:
        return "html"
    if suffix in {".js", ".jsx", ".ts", ".tsx"}:
        return "js"
    if suffix == ".json":
        return "json"
    if suffix == ".xml":
        return "xml"
    if suffix in SOURCE_EXT:
        return "source"
    return "text"


class Analyzer:
    def __init__(self, engine: PatternEngine | None = None,
                 max_file_bytes: int = 1_048_576, max_total_bytes: int = 10_485_760):
        self.engine = engine or PatternEngine()
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes

    def _inspect_html_forms(self, result: Result, location: str, content: str) -> None:
        soup = BeautifulSoup(content, "html.parser")
        for i, form in enumerate(soup.find_all("form"), 1):
            action = form.get("action") or location
            method = (form.get("method") or "GET").upper()
            enctype = (form.get("enctype") or "").lower()
            fields = [el.get("name") for el in form.find_all(["input", "textarea", "select"])
                      if el.get("name")]
            has_file = any((el.get("type") or "").lower() == "file"
                           for el in form.find_all("input"))
            result.add_endpoint(Endpoint(
                url=urljoin(location, action), method=method, params=fields,
                source="form", enctype=enctype, note="file-upload" if has_file else ""))
            result.metadata.setdefault("forms", []).append({
                "page": location, "index": i, "action": action, "method": method,
                "enctype": enctype, "fields": fields, "file_input": has_file})

    def scan_path(self, path) -> Result:
        from . import flaghints
        from .pages import Page

        path = Path(path).resolve()
        result = Result(target=str(path))
        if not path.exists():
            result.errors.append("Path does not exist")
            return result

        if path.is_file():
            files = [path]
        else:
            files = [p for p in path.rglob("*")
                     if p.is_file() and p.suffix.lower() in ALLOWED_EXT
                     and not (set(p.relative_to(path).parts) & IGNORE_DIRS)]

        total = 0
        pages: list[Page] = []
        for p in sorted(files):
            try:
                size = p.stat().st_size
                if size > self.max_file_bytes or total + size > self.max_total_bytes:
                    result.errors.append(f"Skipped (size limit): {p}")
                    continue
                total += size
                data = p.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                result.errors.append(f"{p}: {exc}")
                continue
            kind = _kind_for(p.suffix)
            result.scanned.append(str(p))
            for f in self.engine.scan(str(p), data, kind):
                result.add_finding(f)
            if kind == "html":
                self._inspect_html_forms(result, str(p), data)
            pages.append(Page(url=str(p), final_url=str(p), status=0,
                              content_type="", kind=kind, text=data))

        flaghints.collect(result, pages)
        result.metadata["total_bytes"] = total
        result.metadata["files_scanned"] = len(result.scanned)
        return result
