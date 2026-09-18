from __future__ import annotations
import json
from pathlib import Path
from .core import Evidence,now_iso
def build_report(target,case_id,evidence,errors,analysis=None):
    return {"schema_version":"1.1.0","tool":"Telegram-OSINT","generated_at":now_iso(),"case_id":case_id,"target":target,"collection_scope":"public_information_only","evidence_count":len(evidence),"errors":errors,"analysis":analysis or {},"evidence":[{"source_type":e.source_type,"source_url":e.source_url,"collected_at":e.collected_at,"title":e.title,"text":e.text,"sha256":e.sha256,"metadata":e.metadata} for e in evidence]}
def write_json(report,path):
    p=Path(path);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding="utf-8")
def write_text(report,path):
    p=Path(path);p.parent.mkdir(parents=True,exist_ok=True);a=report.get("analysis",{})
    lines=["Telegram-OSINT report","="*72,f"Target: {report['target']['handle']}",f"Generated: {report['generated_at']}",f"Evidence: {report['evidence_count']}",f"Public messages: {a.get('message_count',0)}",""]
    for label,key in [("Top words","top_words"),("Hashtags","hashtags"),("Mentions","mentions")]:
        lines.append(label+":");lines += [f"  {x['value']} ({x['count']})" for x in a.get(key,[])[:15]];lines.append("")
    lines.append("Evidence:")
    for i,e in enumerate(report["evidence"],1):lines += [f"[{i}] {e['source_type']}",f"URL: {e['source_url']}",f"Collected: {e['collected_at']}",f"Title: {e.get('title') or ''}",f"SHA256: {e['sha256']}",e["text"][:4000],"-"*72]
    if report["errors"]:lines+=["Errors:"]+[f"- {x}" for x in report["errors"]]
    p.write_text("\n".join(lines),encoding="utf-8")
