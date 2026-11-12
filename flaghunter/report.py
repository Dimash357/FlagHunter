import json, html
from pathlib import Path

def save_report(result, out):
    out=Path(out);out.mkdir(parents=True,exist_ok=True)
    data=result.to_dict()
    (out/"report.json").write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding="utf-8")
    rows="".join("<tr>"+"".join(f"<td>{html.escape(str(value))}</td>" for value in [f.category,f.title,f.location,f.severity,f.status,f.confidence,f.evidence,f.recommendation])+"</tr>" for f in result.findings)
    ai=data["metadata"].get("ai",{})
    page="""<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>FlagHunter report</title><style>body{font-family:system-ui;background:#0d1423;color:#e8edf7;margin:2rem}h1{color:#85c9ff}table{border-collapse:collapse;width:100%;font-size:13px}td,th{border:1px solid #374151;padding:9px;vertical-align:top;overflow-wrap:anywhere}th{background:#233049}tr:nth-child(even){background:#192438}pre{white-space:pre-wrap;background:#192438;padding:1rem;border-radius:8px}small{color:#b5c4d8}</style><h1>FlagHunter · Scan report</h1><p><b>Target:</b> TARGET</p><p>Scanned resources: COUNT · Findings: FINDINGS</p><small>Heuristic candidates are not confirmed vulnerabilities. Only scan systems you own or are authorized to test.</small><h2>Findings</h2><table><tr><th>Category</th><th>Title</th><th>Location</th><th>Severity</th><th>Status</th><th>Confidence</th><th>Evidence</th><th>Recommendation</th></tr>ROWS</table><h2>AI review</h2><pre>AI</pre><h2>Errors</h2><pre>ERRORS</pre></html>"""
    page=page.replace("TARGET",html.escape(result.target)).replace("COUNT",str(len(result.scanned))).replace("FINDINGS",str(len(result.findings))).replace("ROWS",rows).replace("AI",html.escape(json.dumps(ai,ensure_ascii=False,indent=2))).replace("ERRORS",html.escape("\n".join(result.errors) or "None"))
    (out/"report.html").write_text(page,encoding="utf-8")
    return out/"report.html"
