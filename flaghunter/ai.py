import os, json
import httpx

class GeminiReviewer:
    def __init__(self, key=None, model=None, base_url=None):
        self.key=key or os.getenv("GEMINI_API_KEY","")
        self.model=model or os.getenv("GEMINI_MODEL","gemini-3.5-flash-lite")
        self.base_url=(base_url or os.getenv("GEMINI_BASE_URL","https://generativelanguage.googleapis.com/v1beta")).rstrip("/")

    async def review(self, findings, max_findings=8):
        if not self.key: return {"status":"skipped","reason":"GEMINI_API_KEY missing"}
        candidates=[f.to_dict() for f in findings if f.confidence < 0.65 and f.category != "FLAG"][:max_findings]
        if not candidates: return {"status":"skipped","reason":"No ambiguous findings"}
        # Send minimal sanitized metadata; do not send full HTTP bodies, cookies, secrets or credentials.
        safe=[{"category":f["category"],"title":f["title"],"confidence":f["confidence"],"status":f["status"]} for f in candidates]
        instruction=("You are a defensive CTF code review assistant. Assess whether these heuristic findings warrant manual verification. "
                     "Do not assert exploitation or provide instructions to access unauthorized data. "
                     "Return concise Russian text grouped by category, with false-positive caveats. Findings: "+json.dumps(safe,ensure_ascii=False))
        endpoint=f"{self.base_url}/models/{self.model}:generateContent"
        payload={"contents":[{"role":"user","parts":[{"text":instruction}]}],"generationConfig":{"temperature":0.1,"maxOutputTokens":900}}
        try:
            async with httpx.AsyncClient(timeout=25,trust_env=False) as client:
                response=await client.post(endpoint,params={"key":self.key},json=payload)
                response.raise_for_status()
                obj=response.json()
                parts=obj.get("candidates",[{}])[0].get("content",{}).get("parts",[])
                text="\n".join(p.get("text","") for p in parts)
                return {"status":"ok","model":self.model,"analysis":text}
        except (httpx.HTTPError, ValueError, IndexError, KeyError) as e:
            # API errors never stop the rule-based scanner.
            return {"status":"unavailable","model":self.model,"reason":str(e)[:250]}
