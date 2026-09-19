from __future__ import annotations

import html
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .core import now_iso

DISPLAY_TZ = timezone(timedelta(hours=5, minutes=30), name="IST")
DISPLAY_TZ_LABEL = "IST"


def build_report(target, case_id, evidence, errors, analysis=None, intel=None):
    resolved_id = next(
        ((e.metadata or {}).get("entity", {}).get("id") for e in evidence
         if isinstance((e.metadata or {}).get("entity"), dict)
         and (e.metadata or {}).get("entity", {}).get("id") is not None),
        None,
    )
    history = intel.entity_history(int(resolved_id)) if intel is not None and resolved_id is not None else {}
    return {
        "schema_version": "1.5.1",
        "tool": "Telegram-OSINT",
        "generated_at": now_iso(),
        "case_id": case_id,
        "target": target,
        "resolved_telegram_id": resolved_id,
        "collection_scope": "public_information_only",
        "display_timezone": "UTC+05:30",
        "display_timezone_label": DISPLAY_TZ_LABEL,
        "evidence_count": len(evidence),
        "errors": errors,
        "analysis": analysis or {},
        "history": history,
        "evidence": [
            {"source_type": e.source_type, "source_url": e.source_url, "collected_at": e.collected_at,
             "title": e.title, "text": e.text, "sha256": e.sha256, "metadata": e.metadata}
            for e in evidence
        ],
    }


def _e(v):
    if v is None:
        return ""
    value = str(v)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is not None and "T" in value:
            value = parsed.astimezone(DISPLAY_TZ).strftime("%d %b %Y, %I:%M:%S %p") + f" {DISPLAY_TZ_LABEL}"
    except (ValueError, TypeError):
        pass
    return html.escape(value, quote=True)


def _table(rows, columns, empty="No data observed."):
    if not rows:
        return f'<tr><td colspan="{len(columns)}" class="muted">{_e(empty)}</td></tr>'
    return "".join("<tr>" + "".join(f"<td>{_e(r.get(c))}</td>" for c in columns) + "</tr>" for r in rows)


def write_html(report, path):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    a = report.get("analysis", {})
    history = report.get("history", {})
    entity = history.get("entity", {})
    identifiers = history.get("identifiers", [])
    profiles = history.get("profiles", [])
    memberships = history.get("memberships", [])
    messages = history.get("messages", [])
    relationships = history.get("relationships", [])
    iocs = a.get("iocs", {})
    eng = a.get("engagement", {})

    usernames = [x for x in identifiers if x.get("identifier_type") == "telegram_username"]
    names = [x for x in identifiers if x.get("identifier_type") == "display_name"]

    def chips(items, prefix=""):
        return "".join(f'<span class="chip">{_e(prefix + str(x.get("value","")))}</span>' for x in items) or '<span class="muted">None observed</span>'

    profile_rows = [
        {"observed_at": x.get("observed_at"), "username": x.get("username") or "—",
         "name": x.get("display_name") or x.get("title") or "—", "about": x.get("about") or "—"}
        for x in profiles
    ]
    membership_rows = [
        {"observed": x.get("observed_at"), "chat": x.get("chat_title") or "—",
         "username": x.get("chat_username") or "—", "type": x.get("chat_type") or "—",
         "status": x.get("status") or "unknown", "role": x.get("role") or "member"}
        for x in memberships
    ]
    message_rows = [
        {"date": x.get("message_date") or x.get("observed_at"),
         "chat": x.get("chat_title") or x.get("chat_username") or x.get("chat_type") or "—",
         "text": (x.get("text") or "")[:320]}
        for x in messages
    ]
    relation_rows = [
        {"observed": x.get("observed_at"), "relation": x.get("edge_type"),
         "id": x.get("target_telegram_id") or x.get("source_telegram_id") or "—",
         "username": x.get("target_username") or "—", "source": x.get("source_url") or "—"}
        for x in relationships
    ]

    ioc_cards = []
    for label, key in (("URLs", "urls"), ("Usernames", "usernames"), ("Emails", "emails"), ("Domains", "domains"), ("IPv4", "ipv4")):
        vals = iocs.get(key, [])
        body = "".join(f"<li>{_e(v)}</li>" for v in vals) or '<li class="muted">None observed</li>'
        ioc_cards.append(f'<article class="ioc"><div class="ioc-head"><h3>{label}</h3><strong>{len(vals)}</strong></div><ul>{body}</ul></article>')

    evidence_cards = []
    for i, e in enumerate(report["evidence"], 1):
        evidence_cards.append(f'''<details class="evidence">
<summary><strong>{_e(e.get("title") or "Evidence")}</strong><span class="muted">#{i} · {_e(e.get("source_type"))}</span></summary>
<div class="evidence-body"><a href="{_e(e.get("source_url"))}" rel="noopener noreferrer">{_e(e.get("source_url"))}</a>
<div class="meta"><span>Collected</span><strong>{_e(e.get("collected_at"))}</strong></div>
<pre>{_e(e.get("text",""))}</pre>
<div class="meta"><span>SHA-256</span><code>{_e(e.get("sha256"))}</code></div>
<details><summary>Raw metadata</summary><pre>{_e(e.get("metadata",{}))}</pre></details></div></details>''')

    warnings = "".join(f"<li>{_e(x)}</li>" for x in report["errors"])
    current_username = entity.get("username")
    current_name = entity.get("display_name")
    resolved = report.get("resolved_telegram_id") or "Unknown"

    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark light"><title>Telegram-OSINT — {_e(report["target"]["handle"])}</title>
<style>
:root{{--bg:#07111f;--panel:#0d1a2b;--panel2:#13243a;--text:#edf6ff;--muted:#8fa5bd;--line:#28415e;--accent:#55b8ff;--accent2:#8b7cff;--good:#4ade9a;--warn:#ffd166;--danger:#ff6b7a;--shadow:0 16px 45px #0005}}
@media(prefers-color-scheme:light){{:root{{--bg:#eef3f8;--panel:#ffffff;--panel2:#f2f6fb;--text:#142033;--muted:#62738a;--line:#d5dfeb;--accent:#1267a8;--accent2:#6654d9;--good:#16784d;--warn:#8a5a00;--danger:#b42318;--shadow:0 12px 30px #18304a1a}}}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:radial-gradient(circle at 15% -10%,#2468a522,transparent 34%),var(--bg);color:var(--text);font:15px/1.6 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}
main{{width:min(1160px,calc(100% - 22px));margin:18px auto 64px}}a{{color:var(--accent);overflow-wrap:anywhere}}code,pre{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}}
.hero{{position:relative;overflow:hidden;padding:30px;border:1px solid var(--line);border-radius:26px;background:linear-gradient(135deg,var(--panel),var(--panel2));box-shadow:var(--shadow)}}
.hero:after{{content:"";position:absolute;width:260px;height:260px;border-radius:50%;right:-90px;top:-120px;background:linear-gradient(135deg,var(--accent),var(--accent2));opacity:.16;filter:blur(8px)}}
h1{{font-size:clamp(2rem,5vw,3rem);line-height:1.05;margin:.2em 0 .35em;letter-spacing:-.03em}}h2{{font-size:1.25rem;margin:0 0 12px}}h3{{margin:5px 0}}section{{margin:20px 0}}
.nav{{display:flex;gap:8px;flex-wrap:wrap;margin-top:20px}}.nav a{{padding:7px 11px;border:1px solid var(--line);border-radius:10px;background:#ffffff08;text-decoration:none;transition:.18s}}.nav a:hover{{border-color:var(--accent);transform:translateY(-1px)}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));gap:12px}}.wide{{grid-column:1/-1}}
.card,.ioc,.evidence{{background:linear-gradient(145deg,var(--panel),var(--panel2));border:1px solid var(--line);border-radius:16px;padding:16px;box-shadow:0 7px 24px #0002}}
.stat{{position:relative;overflow:hidden}}.stat:before{{content:"";position:absolute;left:0;top:0;width:100%;height:3px;background:linear-gradient(90deg,var(--accent),var(--accent2))}}
.stat strong{{display:block;font-size:1.55rem;margin-top:3px;overflow-wrap:anywhere}}.muted{{color:var(--muted)}}
.chip,.badge{{display:inline-block;padding:5px 10px;border:1px solid var(--line);border-radius:999px;background:#ffffff09;font-size:.78rem;margin:2px 3px 2px 0}}.badge{{border-color:#55b8ff55}}
.iocgrid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px}}.ioc{{border-top:3px solid var(--accent)}}.ioc:nth-child(2n){{border-top-color:var(--accent2)}}.ioc-head{{display:flex;justify-content:space-between;align-items:center}}.ioc-head strong{{font-size:1.45rem}}.ioc ul{{max-height:190px;overflow:auto;padding-left:20px}}
.table-wrap{{overflow:auto;border:1px solid var(--line);border-radius:11px}}table{{width:100%;border-collapse:collapse;min-width:620px}}th,td{{padding:10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}tr:last-child td{{border-bottom:0}}th{{color:var(--muted);font-size:.82rem;text-transform:uppercase;letter-spacing:.04em;background:#ffffff05}}
.evidence{{padding:0;overflow:hidden}}.evidence summary{{cursor:pointer;padding:14px 16px;display:flex;justify-content:space-between;gap:12px;list-style:none}}.evidence summary::-webkit-details-marker{{display:none}}.evidence summary:before{{content:"＋";color:var(--accent);font-weight:700;margin-right:8px}}.evidence[open] summary:before{{content:"−"}}.evidence-body{{padding:0 16px 16px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#0003;padding:12px;border-radius:10px;max-height:520px;overflow:auto}}.meta{{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:9px 0;border-bottom:1px solid var(--line)}}
.warn{{border-color:var(--danger);box-shadow:0 0 0 1px #ff6b7a22 inset}}footer{{margin-top:30px;padding-top:16px;border-top:1px solid var(--line)}}
@media(max-width:650px){{main{{width:calc(100% - 12px);margin-top:8px}}.hero,.card,.ioc{{padding:13px;border-radius:13px}}.hero{{padding:20px}}.grid{{grid-template-columns:repeat(2,minmax(0,1fr))}}.iocgrid{{grid-template-columns:1fr}}.meta{{display:block}}.meta strong,.meta code{{display:block;margin-top:3px;overflow-wrap:anywhere}}}}
@media(max-width:420px){{.grid{{grid-template-columns:1fr}}h1{{font-size:2.15rem}}}}
@media print{{body{{background:#fff;color:#111}}.hero,.card,.ioc,.evidence{{box-shadow:none;break-inside:avoid}}.nav{{display:none}}}}
</style></head><body><main>
<header class="hero"><div class="muted">Telegram-OSINT · public information only</div>
<h1>{_e(report["target"]["handle"])}</h1>
<div class="badge">Telegram ID: {_e(resolved)}</div>
<div class="badge">{_e("@" + current_username if current_username else "No current public username")}</div>
<div class="badge">{_e(current_name or "No current display name")}</div>
<p class="muted">Generated {_e(report["generated_at"])} · Display timezone: Asia/Kolkata (IST, UTC+05:30) · Case #{_e(report["case_id"])}</p>
<nav class="nav"><a href="#identity">Identity</a><a href="#history">History</a><a href="#activity">Activity</a><a href="#relationships">Relationships</a><a href="#indicators">Indicators</a><a href="#evidence">Evidence</a></nav></header>

<section id="identity" class="grid">
<div class="card stat"><span class="muted">Stable Telegram ID</span><strong>{_e(resolved)}</strong></div>
<div class="card stat"><span class="muted">First observed</span><strong>{_e(entity.get("first_observed") or "Unknown")}</strong></div>
<div class="card stat"><span class="muted">Last observed</span><strong>{_e(entity.get("last_observed") or "Unknown")}</strong></div>
<div class="card stat"><span class="muted">Evidence</span><strong>{report["evidence_count"]}</strong></div>
<div class="card stat"><span class="muted">Messages analyzed</span><strong>{a.get("message_count",0)}</strong></div>
</section>

<section id="history" class="card"><h2>Username &amp; profile history</h2>
<p class="muted">Only observations collected by this tool are shown. This is not a complete lifetime history.</p>
<div class="table-wrap"><table><tr><th>Observed (IST)</th><th>Username</th><th>Name</th><th>About</th></tr>{_table(profile_rows,["observed_at","username","name","about"],"No profile snapshots collected.")}</table></div>
<h3>Observed usernames</h3><p>{chips(usernames,"@")}</p><h3>Observed display names</h3><p>{chips(names)}</p></section>

<section id="activity" class="grid">
<div class="card wide"><h2>Messages authored by this ID</h2><div class="table-wrap"><table><tr><th>Date (IST)</th><th>Chat</th><th>Message</th></tr>{_table(message_rows,["date","chat","text"],"No authored messages stored.")}</table></div></div>
<div class="card wide"><h2>Groups &amp; channels observed</h2><div class="table-wrap"><table><tr><th>Observed (IST)</th><th>Chat</th><th>Username</th><th>Type</th><th>Status</th><th>Role</th></tr>{_table(membership_rows,["observed","chat","username","type","status","role"],"No membership observations collected.")}</table></div></div>
</section>

<section id="relationships" class="card"><h2>Observed relationships</h2><p class="muted">Relations come from explicit Telegram message metadata or public mentions; ambiguous text is not treated as identity proof.</p>
<div class="table-wrap"><table><tr><th>Observed (IST)</th><th>Relation</th><th>Telegram ID</th><th>Username</th><th>Source</th></tr>{_table(relation_rows,["observed","relation","id","username","source"],"No relationships observed.")}</table></div></section>

<section id="indicators"><h2>Indicators &amp; references</h2><div class="iocgrid">{"".join(ioc_cards)}</div></section>
<section class="grid"><div class="card"><h2>Engagement</h2><p>Views: <strong>{eng.get("total_views",0)}</strong><br>Average views: <strong>{eng.get("average_views",0)}</strong><br>Forwards: <strong>{eng.get("total_forwards",0)}</strong></p></div>
<div class="card"><h2>Activity by day</h2><div class="table-wrap"><table><tr><th>Date</th><th>Messages</th></tr>{_table([{"date":k,"count":v} for k,v in a.get("activity_by_day",{}).items()],["date","count"],"No dated messages.")}</table></div></div></section>

<section id="evidence"><h2>Collection evidence</h2>{"".join(evidence_cards) or '<div class="card muted">No evidence was collected.</div>'}</section>
{f'<section><div class="card warn"><h2>Collection warnings</h2><ul>{warnings}</ul></div></section>' if warnings else ""}
<footer class="muted">Report schema 1.5.1 · Stored timestamps remain machine-readable; report timestamps are displayed in IST (UTC+05:30) · public-information-only collection · historical completeness is not guaranteed.</footer>
</main></body></html>"""
    p.write_text(doc, encoding="utf-8")
