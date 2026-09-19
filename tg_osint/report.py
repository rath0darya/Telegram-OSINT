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
        "schema_version": "1.9.0",
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
    labels = {c: c.replace("_", " ").title() for c in columns}
    if not rows:
        return f'<tr><td colspan="{len(columns)}" class="muted">{_e(empty)}</td></tr>'
    return "".join(
        "<tr>" + "".join(
            f'<td data-label="{_e(labels[c])}">{_e(row.get(c))}</td>' for c in columns
        ) + "</tr>" for row in rows
    )


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
    reactions = history.get("reactions", [])
    iocs = a.get("iocs", {})
    context_iocs = a.get("reference_iocs", {})
    eng = a.get("engagement", {})
    collection = next((x.get("metadata", {}).get("collection", {}) for x in report.get("evidence", []) if x.get("source_type") == "telegram_api_public_entity"), {})
    collection_warnings = []
    for key in ("global_author_errors", "history_errors", "search_errors", "discovery_errors"):
        for item in collection.get(key, []) or []:
            collection_warnings.append(f"{key.replace('_', ' ').title()}: {item}")

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
    context_ioc_cards = []
    for label, key in (("URLs", "urls"), ("Usernames", "usernames"), ("Emails", "emails"), ("Domains", "domains"), ("IPv4", "ipv4")):
        vals = context_iocs.get(key, [])
        body = "".join(f"<li>{_e(v)}</li>" for v in vals) or '<li class="muted">None observed</li>'
        context_ioc_cards.append(f'<article class="ioc context-ioc"><div class="ioc-head"><h3>{label}</h3><strong>{len(vals)}</strong></div><ul>{body}</ul></article>')

    resolved = report.get("resolved_telegram_id")
    resolved_display = resolved if resolved is not None else "Unknown"

    evidence_cards = []
    for i, e in enumerate(report["evidence"], 1):
        metadata = e.get("metadata") or {}
        author = metadata.get("author") if isinstance(metadata.get("author"), dict) else {}
        author_id = author.get("id")
        exact_target_author = (
            e.get("source_type") == "telegram_public_message"
            and resolved is not None
            and author_id is not None
            and str(author_id) == str(resolved)
        )
        if e.get("source_type") == "telegram_public_message":
            mapping_label = (
                '<div class="meta"><span>Target mapping</span><strong>EXACT AUTHOR ID MATCH — attributed to target</strong></div>'
                if exact_target_author else
                '<div class="meta"><span>Target mapping</span><strong>NO — context only; different/unknown author ID</strong></div>'
            )
            ids = f'<div class="meta"><span>Raw Telegram IDs</span><code>message={_e(metadata.get("message_id"))} · chat={_e((metadata.get("chat") or {}).get("id"))} · author={_e(author_id)}</code></div>'
        else:
            mapping_label = '<div class="meta"><span>Target mapping</span><strong>IDENTITY/PROFILE EVIDENCE — not a message authorship claim</strong></div>'
            ids = ""
        evidence_cards.append(f'''<details class="evidence">
<summary><strong>{_e(e.get("title") or "Evidence")}</strong><span class="muted">#{i} · {_e(e.get("source_type"))}</span></summary>
<div class="evidence-body"><a href="{_e(e.get("source_url"))}" rel="noopener noreferrer">{_e(e.get("source_url"))}</a>
<div class="meta"><span>Collected</span><strong>{_e(e.get("collected_at"))}</strong></div>
{mapping_label}
{ids}
<pre>{_e(e.get("text",""))}</pre>
<div class="meta"><span>SHA-256</span><code>{_e(e.get("sha256"))}</code></div>
<details><summary>Raw metadata — collected fields</summary><pre>{_e(e.get("metadata",{}))}</pre></details></div></details>''')

    warnings = "".join(f"<li>{_e(x)}</li>" for x in report["errors"])
    current_username = entity.get("username")
    current_name = entity.get("display_name")
    resolved = report.get("resolved_telegram_id")
    resolved_display = resolved if resolved is not None else "Unknown"

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
@media(max-width:760px){{main{{width:calc(100% - 12px);margin-top:8px}}.hero,.card,.ioc{{padding:13px;border-radius:13px}}.hero{{padding:20px}}.grid{{grid-template-columns:repeat(2,minmax(0,1fr))}}.iocgrid{{grid-template-columns:1fr}}.meta{{display:block}}.meta strong,.meta code{{display:block;margin-top:3px;overflow-wrap:anywhere}}table{{min-width:0;display:block}}thead,tbody,tr{{display:block}}th{{display:none}}tr{{padding:9px 11px;border-bottom:1px solid var(--line)}}tr:last-child{{border-bottom:0}}td{{display:grid;grid-template-columns:minmax(105px,34%) 1fr;gap:10px;padding:6px 0;border:0}}td:before{{content:attr(data-label);color:var(--muted);font-size:.76rem;font-weight:600;text-transform:uppercase;letter-spacing:.03em}}.table-wrap{{overflow:visible}}}}
@media(max-width:420px){{.grid{{grid-template-columns:1fr}}h1{{font-size:2.15rem}}td{{grid-template-columns:1fr;gap:2px}}td:before{{font-size:.7rem}}}}
@media print{{body{{background:#fff;color:#111}}.hero,.card,.ioc,.evidence{{box-shadow:none;break-inside:avoid}}.nav{{display:none}}}}
</style></head><body><main>
<header class="hero"><div class="muted">Telegram-OSINT · public information only</div>
<h1>{_e(report["target"]["handle"])}</h1>
<div class="badge">Telegram ID: {_e(resolved_display)}</div>
<div class="badge">{_e("@" + current_username if current_username else "No current public username")}</div>
<div class="badge">{_e(current_name or "No current display name")}</div>
<p class="muted">Generated {_e(report["generated_at"])} · Display timezone: Asia/Kolkata (IST, UTC+05:30) · Case #{_e(report["case_id"])}</p>
<nav class="nav"><a href="#identity">Identity</a><a href="#history">History</a><a href="#activity">Activity</a><a href="#relationships">Relationships</a><a href="#indicators">Indicators</a><a href="#evidence">Evidence</a></nav></header>

<section id="identity" class="grid">
<div class="card stat"><span class="muted">Stable Telegram ID</span><strong>{_e(resolved_display)}</strong></div>
<div class="card stat"><span class="muted">First observed</span><strong>{_e(entity.get("first_observed") or "Unknown")}</strong></div>
<div class="card stat"><span class="muted">Last observed</span><strong>{_e(entity.get("last_observed") or "Unknown")}</strong></div>
<div class="card stat"><span class="muted">Evidence</span><strong>{report["evidence_count"]}</strong></div>
<div class="card stat"><span class="muted">Target-authored messages</span><strong>{a.get("authored_message_count",0)}</strong></div>
<div class="card stat"><span class="muted">Collected messages</span><strong>{a.get("message_count",0)}</strong></div>
<div class="card stat"><span class="muted">Context references</span><strong>{a.get("non_authored_message_count",0)}</strong></div>
<div class="card stat"><span class="muted">Target-authored chats</span><strong>{a.get("chat_count",0)}</strong></div>
<div class="card stat"><span class="muted">Context-observed chats</span><strong>{a.get("all_observed_chat_count",0)}</strong></div>
<div class="card stat"><span class="muted">Observed relationships</span><strong>{len(relationships)}</strong></div>

</section>

<section id="history" class="card"><h2>Username &amp; profile history</h2>
<p class="muted">Only observations collected by this tool are shown. This is not a complete lifetime history.</p>
<div class="table-wrap"><table><tr><th>Observed (IST)</th><th>Username</th><th>Name</th><th>About</th></tr>{_table(profile_rows,["observed_at","username","name","about"],"No profile snapshots collected.")}</table></div>
<h3>Observed usernames</h3><p>{chips(usernames,"@")}</p><h3>Observed display names</h3><p>{chips(names)}</p></section>

<section id="activity" class="grid">
<div class="card wide"><h2>Messages authored by this ID</h2><div class="table-wrap"><table><tr><th>Date (IST)</th><th>Chat</th><th>Message</th></tr>{_table(message_rows,["date","chat","text"],"No authored messages stored.")}</table></div></div>
<div class="card wide"><h2>Groups &amp; channels observed</h2><div class="table-wrap"><table><tr><th>Observed (IST)</th><th>Chat</th><th>Username</th><th>Type</th><th>Status</th><th>Role</th></tr>{_table(membership_rows,["observed","chat","username","type","status","role"],"No membership observations collected.")}</table></div></div>
</section>

<section class="card coverage"><h2>Collection coverage</h2><div class="grid"><div><span class="muted">History seen</span><br><strong>{collection.get("history_seen",0)}</strong></div><div><span class="muted">Search references seen</span><br><strong>{collection.get("search_seen",0)}</strong></div><div><span class="muted">Search references with text</span><br><strong>{collection.get("search_with_text",0)}</strong></div><div><span class="muted">Reaction records</span><br><strong>{len(reactions)}</strong></div><div><span class="muted">Discovered public chats</span><br><strong>{collection.get("discovered_chat_count",0)}</strong></div><div><span class="muted">Chat scan messages</span><br><strong>{collection.get("chat_scan_seen",0)}</strong></div><div><span class="muted">Target-author matches</span><br><strong>{a.get("authored_message_count",0)}</strong></div>
<div><span class="muted">Context/reference messages</span><br><strong>{a.get("non_authored_message_count",0)}</strong></div></div><p class="muted">History/search collection is retried up to three times. A failed stage is reported separately from a successful identity/profile observation. Search results are reference observations; they do not prove that the target authored those messages. Collection errors are surfaced rather than silently discarded.</p></section>

<section class="card coverage"><h2>Identity policy</h2><p class="muted"><strong>Telegram ID is authoritative.</strong> A message is classified as target-authored only when Telegram exposes the exact resolved Telegram user ID as its author. Current or historical usernames, display names, similar names, or matching text are contextual references and never become target identity by themselves.</p><p class="muted">This report can therefore contain many collected/reference messages while showing zero target-authored messages. That is intentional identity protection, not a conversion of text similarity into identity.</p></section>

<section class="card coverage"><h2>Data quality</h2><div class="grid">
<div><span class="muted">Target-author matches</span><br><strong>{collection.get("chat_scan_matches",0)}</strong></div>
<div><span class="muted">Unattributed messages</span><br><strong>{a.get("unattributed_message_count",0)}</strong></div>
<div><span class="muted">Membership observations</span><br><strong>{collection.get("membership_observations",0)}</strong></div>
<div><span class="muted">Discovery errors</span><br><strong>{len(collection.get("discovery_errors",[]) or [])}</strong></div>
<div><span class="muted">Author-ID mismatches</span><br><strong>{a.get("author_mismatch_count",0)}</strong></div>
</div><p class="muted">Target-authored counts use exact Telegram ID equality. Context/reference counts include messages collected around the target but not proven to be authored by the target. Counts are observations available to the authenticated Telegram session. A zero means no observation was collected in the accessible scope; it is not proof that the underlying event never happened.</p></section>

<section id="relationships" class="card"><h2>Observed relationships</h2><p class="muted">Relations come from explicit Telegram message metadata or public mentions; ambiguous text is not treated as identity proof.</p>
<div class="table-wrap"><table><tr><th>Observed (IST)</th><th>Relation</th><th>Telegram ID</th><th>Username</th><th>Source</th></tr>{_table(relation_rows,["observed","relation","id","username","source"],"No relationships observed.")}</table></div></section>

<section id="indicators"><h2>Target indicators</h2><p class="muted">Only indicators extracted from messages authored by the exact resolved Telegram ID are attributed to the target.</p><div class="iocgrid">{"".join(ioc_cards)}</div></section>
<section class="card"><h2>Unattributed indicators — preserved, never mapped to target</h2><p class="muted">These indicators were extracted from messages whose exposed author ID did not exactly match Telegram ID {resolved}. They are preserved one-by-one as collection context only. They are not target indicators, not target usernames/emails/domains/URLs, and do not create an identity mapping.</p><div class="iocgrid">{"".join(context_ioc_cards)}</div></section>
<section class="grid"><div class="card"><h2>Engagement</h2><p>Views: <strong>{eng.get("total_views",0)}</strong><br>Average views: <strong>{eng.get("average_views",0)}</strong><br>Forwards: <strong>{eng.get("total_forwards",0)}</strong></p></div>
<div class="card"><h2>Activity by day</h2><div class="table-wrap"><table><tr><th>Date</th><th>Messages</th></tr>{_table([{"date":k,"count":v} for k,v in a.get("activity_by_day",{}).items()],["date","count"],"No dated messages.")}</table></div></div></section>

<section id="evidence"><div class="section-head"><div><h2>Collection evidence</h2><p class="muted">Every stored message is shown individually. Authorship requires an exact Telegram numeric ID match.</p></div><div class="evidence-tools"><input id="evidenceSearch" type="search" placeholder="Filter evidence..."><button type="button" id="openEvidence">Open all</button><button type="button" id="closeEvidence">Close all</button></div></div>{"".join(evidence_cards) or '<div class="card muted">No evidence was collected.</div>'}</section>
{f'<section><div class="card warn"><h2>Collection warnings</h2><ul>{warnings}</ul></div></section>' if warnings else ""}
{f'<section><div class="card warn"><h2>Collector diagnostics</h2><ul>{"".join(f"<li>{_e(x)}</li>" for x in collection_warnings)}</ul></div></section>' if collection_warnings else ""}
<footer class="muted">Report schema 1.9.0 · Stored timestamps remain machine-readable; report timestamps are displayed in IST (UTC+05:30) · public-information-only collection · historical completeness is not guaranteed.</footer>
</main><script>const q=document.getElementById("evidenceSearch");const cards=[...document.querySelectorAll(".evidence")];q?.addEventListener("input",()=>{{const term=q.value.trim().toLowerCase();cards.forEach(x=>x.hidden=term&&!x.innerText.toLowerCase().includes(term));}});document.getElementById("openEvidence")?.addEventListener("click",()=>cards.forEach(x=>x.open=true));document.getElementById("closeEvidence")?.addEventListener("click",()=>cards.forEach(x=>x.open=false));</script></body></html>"""
    p.write_text(doc, encoding="utf-8")
