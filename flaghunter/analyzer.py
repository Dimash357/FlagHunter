from pathlib import Path
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
from .models import Finding, Result
from .rules import PatternEngine

ALLOWED_EXT = {".html",".htm",".js",".ts",".jsx",".tsx",".py",".php",".xml",".json",".txt",".css",".java",".go",".rb",".arb",".yaml",".yml",".md"}
IGNORE_DIRS = {".git","node_modules","env",".venv","venv","__pycache__","output","dist","build"}

class Analyzer:
    def __init__(self, engine=None, max_file_bytes=1048576, max_total_bytes=10485760):
        self.engine = engine or PatternEngine()
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes

    def inspect(self, result, location, content, kind="text", headers=None):
        result.scanned.append(location)
        result.findings.extend(self.engine.scan(location, content, kind))
        if headers:
            header_text = "\n".join(f"{k}: {v}" for k,v in headers.items() if k.lower() not in {"set-cookie","authorization"})
            result.findings.extend(self.engine.scan(location+" [headers]", header_text,"headers"))
            if kind == "html":
                for header in ("content-security-policy", "x-content-type-options"):
                    if header not in {k.lower() for k in headers}:
                        result.findings.append(Finding("HEADERS",f"Missing {header}",location,"Header absent", "info",0.65,recommendation="Review response security headers."))
        if kind == "html":
            soup = BeautifulSoup(content,"html.parser")
            for i, form in enumerate(soup.find_all("form"),1):
                action = form.get("action", "")
                method = form.get("method", "get").upper()
                names = [x.get("name", "") for x in form.find_all(["input","textarea","select"]) if x.get("name")]
                result.metadata.setdefault("forms", []).append({"page":location,"index":i,"action":action,"method":method,"fields":names})
                if any(x.get("type", "").lower()=="file" for x in form.find_all("input")):
                    result.findings.append(Finding("FILE_UPLOAD","Upload form detected",location,f"action={action}","info",0.45))
        if kind == "url":
            result.metadata.setdefault("parameters", {})[location] = list(parse_qs(urlparse(location).query))

    def scan_path(self, path):
        path=Path(path).resolve()
        result=Result(target=str(path))
        if not path.exists():
            result.errors.append("Path does not exist")
            return result
        paths=[path] if path.is_file() else [p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in ALLOWED_EXT and not (set(p.relative_to(path).parts) & IGNORE_DIRS)]
        total=0
        for p in sorted(paths):
            try:
                size=p.stat().st_size
                if size>self.max_file_bytes or total+size>self.max_total_bytes:
                    result.errors.append(f"Skipped (size limit): {p}")
                    continue
                total+=size
                data=p.read_text(encoding="utf-8",errors="replace")
                kind="html" if p.suffix.lower() in {".html",".htm"} else "js" if p.suffix.lower() in {".js",".jsx",".ts",".tsx"} else "source" if p.suffix.lower() in {".py",".php",".java",".go",".rb"} else "text"
                self.inspect(result,str(p),data,kind)
            except OSError as e: result.errors.append(f"{p}: {e}")
        result.metadata["total_bytes"] = total
        return result
