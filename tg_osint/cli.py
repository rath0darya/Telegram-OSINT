from __future__ import annotations
import argparse
from pathlib import Path
from dotenv import load_dotenv
from .analyzer import analyze_evidence
from .core import CaseDB, normalize_target
from .intel_db import IntelligenceDB
from .public_web import fetch_public_page
from .report import build_report, write_html

def main():
    p=argparse.ArgumentParser(prog="tg-osint",description="Telegram public-information OSINT collector for Termux.")
    p.add_argument("target")
    p.add_argument("--messages",type=int,default=0,help="Collect up to N public messages")
    p.add_argument("--timeout",type=int,default=15); p.add_argument("--rate",type=float,default=1.0)
    p.add_argument("--db",default="cases/telegram_osint.db"); p.add_argument("--out",default="reports")
    p.add_argument("--no-analysis",action="store_true")
    p.add_argument("--intel-db",default="cases/intelligence.db",help="Persistent historical public-observation database")
    p.add_argument("--search",default="",help="Search previously observed public entities by username/name")
    a=p.parse_args(); load_dotenv()
    if a.search:
        intel=IntelligenceDB(a.intel_db)
        for row in intel.search(a.search): print(row)
        intel.close()
        return 0
    try:t=normalize_target(a.target)
    except ValueError as e:p.error(str(e))
    if a.messages<0:p.error("--messages must be >= 0")
    Path(a.out).mkdir(parents=True,exist_ok=True); db=CaseDB(a.db); intel=IntelligenceDB(a.intel_db); run_id=intel.start_run(t["handle"]); cid=db.create_case(t["handle"]); ev=[]; errors=[]
    try: ev.append(fetch_public_page(t["url"],a.timeout,a.rate))
    except Exception as e: errors.append(f"public page: {type(e).__name__}: {e}")
    if a.messages:
        try:
            from .telegram_api import collect_public
            ev.extend(collect_public(t["username"],a.messages))
        except Exception as e: errors.append(f"telegram api: {type(e).__name__}: {e}")
    for x in ev: db.add_evidence(cid,x)
    intel.ingest(ev); intel.finish_run(run_id,len(ev))
    analysis={} if a.no_analysis else analyze_evidence(ev)
    report=build_report(t,cid,ev,errors,analysis); hp=str(Path(a.out)/f"{t['username']}_{cid}.html"); write_html(report,hp); intel.close(); db.close()
    print(f"Target      : {t['handle']}"); print(f"Evidence    : {len(ev)}"); print(f"Messages    : {analysis.get('message_count',0)}"); print(f"Case ID     : {cid}"); print(f"HTML report : {hp}")
    if analysis.get("related_public_usernames"): print("Related public usernames:",", ".join(analysis["related_public_usernames"][:20]))
    if errors:
        print("\nWarnings:")
        for x in errors: print(f"  - {x}")
    return 0
if __name__=="__main__": raise SystemExit(main())
