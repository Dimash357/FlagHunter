import argparse, asyncio
from dotenv import load_dotenv
from .service import scan

def main():
    load_dotenv()
    p=argparse.ArgumentParser(description="FlagHunter: authorized passive CTF site/file analyzer")
    g=p.add_mutually_exclusive_group(required=True)
    g.add_argument("--url",help="Authorized HTTP(S) lab URL")
    g.add_argument("--path",help="Local file or folder")
    p.add_argument("--authorized",action="store_true",help="Confirm authorization to scan target")
    p.add_argument("--allow-private",action="store_true",help="Allow private/loopback lab URLs")
    p.add_argument("--ai",action="store_true",help="Request Gemini review for ambiguous candidates")
    p.add_argument("--out",default="output")
    p.add_argument("--max-pages",type=int,default=25)
    p.add_argument("--max-depth",type=int,default=2)
    args=p.parse_args()
    if args.max_pages<1 or args.max_pages>100 or args.max_depth<0 or args.max_depth>5: p.error("max-pages must be 1..100, max-depth 0..5")
    try:
        result,report=asyncio.run(scan(url=args.url,path=args.path,authorized=args.authorized,allow_private=args.allow_private,ai=args.ai,out=args.out,max_pages=args.max_pages,max_depth=args.max_depth))
        print(f"Scanned: {len(result.scanned)} | Findings: {len(result.findings)} | Errors: {len(result.errors)}")
        for finding in result.findings[:30]: print(f"[{finding.category}] {finding.title}: {finding.location}")
        print(f"HTML: {report}")
        print(f"JSON: {report.parent / 'report.json'}")
        if args.ai: print(f"AI: {result.metadata.get('ai',{}).get('status')}")
    except (ValueError,OSError) as e: p.error(str(e))

if __name__=="__main__":main()
