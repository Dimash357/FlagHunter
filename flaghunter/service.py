from pathlib import Path
from .analyzer import Analyzer
from .crawler import crawl
from .ai import GeminiReviewer
from .report import save_report

async def scan(url=None,path=None,authorized=False,allow_private=False,ai=False,out="output",max_pages=25,max_depth=2):
    if bool(url)==bool(path): raise ValueError("Provide exactly one of url or path")
    if url and not authorized: raise ValueError("Web scanning requires explicit --authorized")
    analyzer=Analyzer()
    if url:
        result=await crawl(url,analyzer,max_pages=max_pages,max_depth=max_depth,allow_private=allow_private)
    else:
        result=analyzer.scan_path(path)
    if ai:
        result.metadata["ai"]=await GeminiReviewer().review(result.findings)
    else:
        result.metadata["ai"]={"status":"disabled"}
    report=save_report(result,out)
    return result,report
