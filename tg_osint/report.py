from __future__ import annotations
import html
from pathlib import Path
from .core import now_iso

def build_report(target, case_id, evidence, errors, analysis=None):
    return {
        "schema_version":"1.3.0","tool":"Telegram-OSINT","generated_at":now_iso(),
        "case_id":case_id,"target":target,"collection_scope":"public_information_only",
        "evidence_count":len(evidence),"errors":errors,"analysis":analysis or {},
        "evidence":[{"source_type":e.source_type,"source_url":e.source_url,"collected_at":e.collected_at,
        "title":e.title,"text":e.text,"sha256":e.sha256,"metadata":e.metadata} for e in evidence]
    }

def _e(value):
    return html.escape("" if value is None else str(value), quote=True)

def _table(items, empty="No data collected."):
    if not items:
        return f'<tr><td colspan="2" class="muted">{_e(empty)}</td></tr>'
    return "".join(f"<tr><td>{_e(x.get('value'))}</td><td>{_e(x.get('count'))}</td></tr>" for x in items)

def write_html(report, path):
    p=Path(path); p.parent.mkdir(parents=True,exist_ok=True)
    a=report.get("analysis",{}); iocs=a.get("iocs",{}); eng=a.get("engagement",{})
    cards=[]
    for i,e in enumerate(report["evidence"],1):
        meta="".join(f'<div class="meta"><span>{_e(k)}</span><strong>{_e(v)}</strong></div>' for k,v in (e.get("metadata") or {}).items() if v not in (None,""))
        cards.append(f'''<article class="evidence"><div class="ehead"><span class="badge">{_e(e["source_type"])}</span><span class="muted">#{i}</span></div>
<h3>{_e(e.get("title") or "Untitled evidence")}</h3><a class="url" href="{_e(e["source_url"])}" rel="noopener noreferrer">{_e(e["source_url"])}</a>
<div class="metagrid"><div class="meta"><span>Collected</span><strong>{_e(e["collected_at"])}</strong></div><div class="meta"><span>SHA-256</span><strong class="hash">{_e(e["sha256"])}</strong></div>{meta}</div>
<pre>{_e(e.get("text",""))}</pre></article>''')
    ioc_cards=[]
    for label,key in (("URLs","urls"),("Usernames","usernames"),("Emails","emails"),("Domains","domains"),("IPv4","ipv4")):
        vals=iocs.get(key,[]); body="".join(f"<li>{_e(v)}</li>" for v in vals) or '<li class="muted">None found</li>'
        ioc_cards.append(f'<div class="ioc"><h3>{label} <span>{len(vals)}</span></h3><ul>{body}</ul></div>')
    activity="".join(f"<tr><td>{_e(k)}</td><td>{_e(v)}</td></tr>" for k,v in a.get("activity_by_day",{}).items()) or '<tr><td colspan="2" class="muted">No dated messages collected.</td></tr>'
    warnings="".join(f"<li>{_e(x)}</li>" for x in report["errors"])
    doc=f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark light">
<title>Telegram-OSINT — {_e(report["target"]["handle"])}</title>
<style>
:root{{--bg:#0b1020;--panel:#121a2b;--panel2:#182238;--text:#edf2f7;--muted:#9aa8bd;--line:#2b3952;--accent:#65b7ff;--danger:#ff8b8b}}
@media(prefers-color-scheme:light){{:root{{--bg:#f4f7fb;--panel:#fff;--panel2:#eef3f9;--text:#172033;--muted:#5d6a7e;--line:#d9e1ec;--accent:#1769aa;--danger:#b42318}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}main{{width:min(1080px,calc(100% - 20px));margin:18px auto 55px}}.hero{{background:linear-gradient(135deg,var(--panel),var(--panel2));border:1px solid var(--line);border-radius:22px;padding:24px;box-shadow:0 15px 40px #0002}}.nav{{display:flex;gap:8px;flex-wrap:wrap;margin-top:18px}}.nav a{{background:var(--panel2);border:1px solid var(--line);padding:7px 10px;border-radius:10px;color:var(--accent);font-size:.85rem}}h1{{font-size:clamp(1.7rem,5vw,2.6rem);margin:.2em 0}}h2{{font-size:1.2rem}}h3{{margin:8px 0;overflow-wrap:anywhere}}section{{margin:20px 0}}.muted{{color:var(--muted)}}.grid,.iocgrid,.metagrid{{display:grid;gap:12px}}.grid{{grid-template-columns:repeat(auto-fit,minmax(145px,1fr))}}.iocgrid{{grid-template-columns:repeat(auto-fit,minmax(210px,1fr))}}.metagrid{{grid-template-columns:repeat(auto-fit,minmax(210px,1fr));margin-top:12px}}.card,.evidence,.ioc{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:15px;box-shadow:0 5px 18px #0002}}.stat strong{{display:block;font-size:1.55rem}}.badge{{display:inline-block;background:var(--panel2);color:var(--accent);border-radius:999px;padding:4px 9px;font-size:.78rem}}.ehead{{display:flex;justify-content:space-between}}.url{{color:var(--accent);overflow-wrap:anywhere}}.meta{{background:var(--panel2);border-radius:9px;padding:8px 10px;min-width:0}}.meta span{{display:block;color:var(--muted);font-size:.75rem}}.meta strong{{display:block;overflow-wrap:anywhere}}.hash{{font: .75rem ui-monospace,SFMono-Regular,Menlo,monospace}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:var(--panel2);padding:12px;border-radius:10px;max-height:520px;overflow:auto}}table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:8px 9px;border-bottom:1px solid var(--line);vertical-align:top}}th{{color:var(--muted)}}.ioc ul{{max-height:220px;overflow:auto;padding-left:20px}}.errors{{border-color:var(--danger)}}@media(max-width:700px){{main{{width:calc(100% - 12px);margin-top:8px}}.hero{{padding:18px;border-radius:16px}}.card,.evidence,.ioc{{padding:12px;border-radius:11px}}.grid{{grid-template-columns:repeat(2,minmax(0,1fr))}}.iocgrid{{grid-template-columns:1fr}}.metagrid{{grid-template-columns:1fr}}}}@media(max-width:420px){{.grid{{grid-template-columns:1fr}}h1{{font-size:2.2rem}}}}@media print{{body{{background:#fff;color:#111}}.card,.evidence,.ioc{{box-shadow:none;break-inside:avoid}}a{{color:#111}}}}
</style></head><body><main>
<header class="hero"><span class="badge">Telegram-OSINT · Public information only</span><h1>{_e(report["target"]["handle"])}</h1><div class="muted">Generated {_e(report["generated_at"])} · Case #{_e(report["case_id"])}</div><nav class="nav"><a href="#overview">Overview</a><a href="#indicators">Indicators</a><a href="#messages">Messages</a><a href="#evidence">Evidence</a></nav></header>
<section class="grid"><div class="card stat"><span class="muted">Evidence</span><strong>{report["evidence_count"]}</strong></div><div class="card stat"><span class="muted">Messages</span><strong>{a.get("message_count",0)}</strong></div><div class="card stat"><span class="muted">URLs</span><strong>{len(iocs.get("urls",[]))}</strong></div><div class="card stat"><span class="muted">Usernames</span><strong>{len(iocs.get("usernames",[]))}</strong></div><div class="card stat"><span class="muted">Domains</span><strong>{len(iocs.get("domains",[]))}</strong></div></section>
<section id="overview"><h2>Engagement</h2><div class="grid"><div class="card stat"><span class="muted">Total views</span><strong>{eng.get("total_views",0)}</strong></div><div class="card stat"><span class="muted">Average views</span><strong>{eng.get("average_views",0)}</strong></div><div class="card stat"><span class="muted">Max views</span><strong>{eng.get("max_views",0)}</strong></div><div class="card stat"><span class="muted">Total forwards</span><strong>{eng.get("total_forwards",0)}</strong></div></div></section>
<section id="indicators"><h2>Indicators &amp; References</h2><div class="iocgrid">{"".join(ioc_cards)}</div></section>
<section class="grid"><div class="card"><h2>Top words</h2><table><tr><th>Term</th><th>Count</th></tr>{_table(a.get("top_words",[]))}</table></div><div class="card"><h2>Hashtags</h2><table><tr><th>Tag</th><th>Count</th></tr>{_table(a.get("hashtags",[]))}</table></div><div class="card"><h2>Mentions</h2><table><tr><th>Username</th><th>Count</th></tr>{_table(a.get("mentions",[]))}</table></div></section>
<section><div class="card"><h2>Activity by day</h2><table><tr><th>Date</th><th>Messages</th></tr>{activity}</table></div></section>
<section id="evidence"><h2>Collection Evidence</h2>{"".join(cards) or '<div class="card muted">No evidence was collected.</div>'}</section>
{f'<section><div class="card errors"><h2>Collection warnings</h2><ul>{warnings}</ul></div></section>' if warnings else ""}
<footer class="muted">Report schema 1.2.0 · HTML only · public-information-only collection</footer>
</main></body></html>'''
    p.write_text(doc,encoding="utf-8")
