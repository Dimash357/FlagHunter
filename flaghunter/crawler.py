import asyncio, ipaddress, socket
from collections import deque
from urllib.parse import urljoin, urldefrag, urlparse
import httpx
from bs4 import BeautifulSoup
from .models import Result
from .analyzer import Analyzer

class CrawlError(ValueError): pass

def validate_target(url, allow_private=False):
    parsed=urlparse(url)
    if parsed.scheme not in {"http","https"} or not parsed.hostname or parsed.username or parsed.password:
        raise CrawlError("Only http(s) URLs without embedded credentials are accepted")
    if parsed.port and parsed.port not in {80,443,8000,8080,3000,5000,8888}:
        raise CrawlError("Port not in default allowlist; adjust for your lab")
    try:
        ips = {ipaddress.ip_address(x[4][0]) for x in socket.getaddrinfo(parsed.hostname,parsed.port or (443 if parsed.scheme=="https" else 80),type=socket.SOCK_STREAM)}
    except socket.gaierror as e: raise CrawlError(f"DNS lookup failed: {e}")
    if not ips: raise CrawlError("No addresses")
    if not allow_private and any(not ip.is_global for ip in ips):
        raise CrawlError("Private/loopback/link-local targets require --allow-private for an owned lab")
    return parsed.hostname

async def crawl(url, analyzer=None, max_pages=25, max_depth=2, delay=0.25, timeout=8, allow_private=False):
    host=validate_target(url,allow_private)
    analyzer=analyzer or Analyzer()
    result=Result(target=url)
    queue=deque([(url,0)])
    seen=set()
    limits=httpx.Limits(max_connections=1,max_keepalive_connections=1)
    async with httpx.AsyncClient(timeout=timeout,follow_redirects=False,limits=limits,trust_env=False,headers={"User-Agent":"FlagHunter-CTF-Lab/1.0"}) as client:
        while queue and len(seen)<max_pages:
            current,depth=queue.popleft()
            current=urldefrag(current)[0]
            parsed=urlparse(current)
            if current in seen or parsed.hostname != host or parsed.scheme not in {"http","https"}: continue
            seen.add(current)
            try:
                # Resolve every URL before the request; same-host URLs only, no redirects.
                validate_target(current,allow_private)
                await asyncio.sleep(delay)
                resp=await client.get(current)
                if resp.status_code in {301,302,303,307,308}:
                    result.errors.append(f"Redirect not followed: {current}")
                    continue
                ctype=resp.headers.get("content-type","").lower()
                if len(resp.content)>analyzer.max_file_bytes:
                    result.errors.append(f"Too large: {current}")
                    continue
                if not any(x in ctype for x in ("text/","javascript","json","xml","xhtml")):
                    result.errors.append(f"Skipped non-text content: {current}")
                    continue
                kind="html" if "html" in ctype else "js" if "javascript" in ctype or current.endswith(".js") else "text"
                analyzer.inspect(result,current,resp.text,kind,resp.headers)
                analyzer.inspect(result,current, current,"url")
                result.metadata.setdefault("http",[]).append({"url":current,"status":resp.status_code,"content_type":ctype})
                if kind=="html" and depth<max_depth:
                    soup=BeautifulSoup(resp.text,"html.parser")
                    for tag,attr in [("a","href"),("script","src")]:
                        for element in soup.find_all(tag):
                            link=element.get(attr)
                            if not link: continue
                            candidate=urldefrag(urljoin(current,link))[0]
                            p=urlparse(candidate)
                            if p.hostname==host and p.scheme in {"http","https"} and candidate not in seen:
                                queue.append((candidate,depth+1))
            except (httpx.HTTPError,CrawlError,UnicodeError) as e:
                result.errors.append(f"{current}: {str(e)[:180]}")
    return result
