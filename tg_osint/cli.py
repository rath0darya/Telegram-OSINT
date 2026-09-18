from __future__ import annotations
import argparse,csv,json
from pathlib import Path
from dotenv import load_dotenv
from .analyzer import analyze_evidence
from .core import CaseDB,normalize_target
from .public_web import fetch_public_page
from .report import build_report,write_json,write_text
def write_csv(report,path):
    p=Path(path);p.parent.mkdir(parents=True,exist_ok=True)
    fields=["source_type","source_url","collected_at","title","sha256","text"]
    with p.open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
        for e in report["evidence"]: w.writerow({k:e.get(k,"") for k in fields})
def main():
    p=argparse.ArgumentParser(prog="tg-osint",description="Telegram public-information OSINT collector for Termux.")
    p.add_argument("target");p.add_argument("--messages",type=int,default=0,help="Collect up to N public messages")
    p.add_argument("--timeout",type=int,default=15);p.add_argument("--rate",type=float,default=1.0)
    p.add_argument("--db",default="cases/telegram_osint.db");p.add_argument("--out",default="reports")
    p.add_argument("--json",action="store_true");p.add_argument("--csv",action="store_true")
    p.add_argument("--no-analysis",action="store_true")
    a=p.parse_args();load_dotenv()
    try:t=normalize_target(a.target)
    except ValueError as e:p.error(str(e))
    if a.messages<0:p.error("--messages must be >= 0")
    Path(a.out).mkdir(parents=True,exist_ok=True);db=CaseDB(a.db);cid=db.create_case(t["handle"])
    ev=[];errors=[]
    try:ev.append(fetch_public_page(t["url"],a.timeout,a.rate))
    except Exception as e:errors.append(f"public page: {type(e).__name__}: {e}")
    if a.messages:
        try:
            from .telegram_api import collect_public
            ev.extend(collect_public(t["username"],a.messages))
        except Exception as e:errors.append(f"telegram api: {type(e).__name__}: {e}")
    for x in ev:db.add_evidence(cid,x)
    analysis={} if a.no_analysis else analyze_evidence(ev)
    report=build_report(t,cid,ev,errors,analysis);stem=f"{t['username']}_{cid}"
    jp=str(Path(a.out)/f"{stem}.json");tp=str(Path(a.out)/f"{stem}.txt");write_json(report,jp);write_text(report,tp)
    cp=None
    if a.csv:cp=str(Path(a.out)/f"{stem}.csv");write_csv(report,cp)
    db.close()
    if a.json:print(json.dumps(report,indent=2,ensure_ascii=False))
    else:
        print(f"Target      : {t['handle']}");print(f"Evidence    : {len(ev)}");print(f"Messages    : {analysis.get('message_count',0)}");print(f"Case ID     : {cid}");print(f"JSON report : {jp}");print(f"Text report : {tp}")
        if cp:print(f"CSV export  : {cp}")
        if analysis.get("related_public_usernames"):print("Related public usernames:",", ".join(analysis["related_public_usernames"][:20]))
        if errors:print("\nWarnings:");[print(f"  - {x}") for x in errors]
    return 0
if __name__=="__main__":raise SystemExit(main())
