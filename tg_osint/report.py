from __future__ import annotations

import html
from collections import Counter
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
            value = parsed.astimezone(DISPLAY_TZ).strftime("%d.%m.%Y %H:%M:%S") + f" {DISPLAY_TZ_LABEL}"
    except (ValueError, TypeError):
        pass
    return html.escape(value, quote=True)


def _raw(v):
    return "" if v is None else str(v)


def _table(rows, columns, headers=None, main=None, empty="Нет данных."):
    headers = headers or [c.replace("_", " ").title() for c in columns]
    main = main or (columns[0] if columns else None)
    if not rows:
        return f'<tr><td colspan="{len(columns)+1}" class="muted">{_e(empty)}</td></tr>'
    out = []
    for i, row in enumerate(rows, 1):
        cells = [f"<td>{i}</td>"]
        for c, label in zip(columns, headers):
            val = row.get(c)
            cls = ' data-main' if c == main else ''
            if val is None or val == "":
                val = "—"
            cells.append(f'<td class="{ "mono" if c.endswith("_id") else ""}" data-label="{_e(label)}"{cls}>{_e(val)}</td>')
        out.append("<tr>" + "".join(cells) + "</tr>")
    return "".join(out)


def write_html(report, path):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    a = report.get("analysis", {})
    history = report.get("history", {}) or {}
    entity = history.get("entity", {}) or {}
    identifiers = history.get("identifiers", []) or []
    profiles = history.get("profiles", []) or []
    memberships = history.get("memberships", []) or []
    messages = history.get("messages", []) or []
    relationships = history.get("relationships", []) or []
    reactions = history.get("reactions", []) or []
    iocs = a.get("iocs", {}) or {}
    context_iocs = a.get("reference_iocs", {}) or {}
    collection = next(
        (x.get("metadata", {}).get("collection", {})
         for x in report.get("evidence", [])
         if x.get("source_type") == "telegram_api_public_entity"),
        {},
    ) or {}

    target = report.get("target", {}) or {}
    handle = target.get("handle") or target.get("username") or "Unknown"
    username = entity.get("username") or target.get("username")
    display_name = entity.get("display_name") or target.get("display_name") or handle
    resolved = report.get("resolved_telegram_id")
    resolved_display = resolved if resolved is not None else "Unknown"

    usernames = [x for x in identifiers if x.get("identifier_type") == "telegram_username"]
    names = [x for x in identifiers if x.get("identifier_type") == "display_name"]

    profile_rows = [
        {"value": x.get("display_name") or x.get("title") or "—",
         "known": ("сейчас · " if x.get("is_current") else "") + _raw(x.get("observed_at") or "—")}
        for x in profiles
    ]
    if not profile_rows and display_name:
        profile_rows = [{"value": display_name, "known": "сейчас"}]

    username_rows = [
        {"value": "@" + str(x.get("value", "")).lstrip("@"),
         "known": ("сейчас · " if x.get("is_current") else "") + _raw(x.get("observed_at") or "—")}
        for x in usernames
    ]
    if not username_rows and username:
        username_rows = [{"value": "@" + str(username).lstrip("@"), "known": "сейчас"}]

    def chat_name(x):
        return x.get("chat_title") or x.get("chat_username") or x.get("chat_type") or "Unknown"

    group_rows = [
        {"chat": chat_name(x), "username": ("@" + str(x.get("chat_username")).lstrip("@")) if x.get("chat_username") else "—",
         "how": "писал" if x.get("status") in ("message", "active") else "в составе",
         "date": x.get("observed_at") or "—"}
        for x in memberships
    ]
    if not group_rows:
        group_rows = [
            {"chat": chat_name(x), "username": ("@" + str(x.get("chat_username")).lstrip("@")) if x.get("chat_username") else "—",
             "how": "писал", "date": x.get("observed_at") or x.get("message_date") or "—"}
            for x in messages
        ]

    chat_counter = Counter(chat_name(x) for x in messages)
    chat_rows = [{"chat": k, "count": v} for k, v in chat_counter.most_common()]

    message_rows = [
        {"message": x.get("text") or "", "date": x.get("message_date") or x.get("observed_at") or "—",
         "chat": chat_name(x)}
        for x in messages
    ]

    relation_rows = [
        {"person": x.get("target_username") or x.get("target_telegram_id") or x.get("source_telegram_id") or "Unknown",
         "username": x.get("target_username") or "—",
         "id": x.get("target_telegram_id") or x.get("source_telegram_id") or "—",
         "kind": x.get("edge_type") or "наблюдение",
         "where": x.get("source_url") or "—"}
        for x in relationships
    ]

    def reaction_rows(items):
        rows = []
        for x in items:
            person = x.get("user") or x.get("target") or {}
            if not isinstance(person, dict):
                person = {}
            rows.append({
                "person": person.get("display_name") or person.get("username") or x.get("username") or x.get("telegram_id") or "Unknown",
                "username": ("@" + str(person.get("username") or x.get("username")).lstrip("@")) if (person.get("username") or x.get("username")) else "—",
                "id": person.get("id") or x.get("telegram_id") or x.get("target_telegram_id") or "—",
                "count": x.get("count") or x.get("reaction_count") or 1,
                "main": x.get("reaction") or x.get("emoji") or "—",
                "where": x.get("source_url") or x.get("message_url") or "—",
            })
        return rows

    reaction_in = reaction_rows(reactions)
    reaction_out = [
        {"person": x.get("target_username") or x.get("target_telegram_id") or "Unknown",
         "username": ("@" + str(x.get("target_username")).lstrip("@")) if x.get("target_username") else "—",
         "id": x.get("target_telegram_id") or "—", "count": x.get("count") or 1,
         "main": x.get("reaction") or x.get("emoji") or "—", "where": x.get("source_url") or "—"}
        for x in reactions if x.get("target_telegram_id") is not None
    ]

    observed_dates = []
    for e in report.get("evidence", []):
        v = e.get("collected_at")
        if v:
            try:
                observed_dates.append(datetime.fromisoformat(v.replace("Z", "+00:00")).astimezone(DISPLAY_TZ))
            except ValueError:
                pass
    for x in messages:
        v = x.get("message_date") or x.get("observed_at")
        if v:
            try:
                observed_dates.append(datetime.fromisoformat(str(v).replace("Z", "+00:00")).astimezone(DISPLAY_TZ))
            except ValueError:
                pass
    if observed_dates:
        start, end = min(observed_dates), max(observed_dates)
    else:
        now = datetime.now(DISPLAY_TZ)
        start = end = now

    buckets = [0] * 56
    span = max((end - start).total_seconds(), 1)
    for d in observed_dates:
        idx = min(55, max(0, int(((d - start).total_seconds() / span) * 55)))
        buckets[idx] += 1
    peak = max(buckets or [1])
    plot = "".join(
        f'<i class="{"z" if not n else ""}" style="--v:{n/peak:.3f}"></i>'
        for n in buckets
    )
    mid = start + (end - start) * 0.5
    axis = f'<span style="left:50%">{_e(mid.strftime("%Y"))}</span>' if start.year != end.year else ""
    tape_marks = len(observed_dates)

    def chips(items, prefix=""):
        vals = []
        for x in items:
            v = x.get("value")
            if v:
                vals.append(f'<span class="chip">{_e(prefix + str(v).lstrip("@") if prefix else v)}</span>')
        return "".join(vals) or '<span class="muted">Нет наблюдений</span>'

    def ioc_section(title, source):
        cards = []
        for label, key in (("URLs", "urls"), ("Usernames", "usernames"), ("Emails", "emails"), ("Domains", "domains"), ("IPv4", "ipv4")):
            vals = source.get(key, []) or []
            body = "".join(f"<li>{_e(v)}</li>" for v in vals) or '<li class="muted">Нет наблюдений</li>'
            cards.append(f'<article class="ioc"><div class="ioc-head"><h3>{label}</h3><strong>{len(vals)}</strong></div><ul>{body}</ul></article>')
        return f'<section class="ioc-block"><div class="sect-title"><h2>{_e(title)}</h2><span class="muted">из собранных сообщений</span></div><div class="iocgrid">{"".join(cards)}</div></section>'

    evidence_cards = []
    for i, e in enumerate(report.get("evidence", []), 1):
        metadata = e.get("metadata") or {}
        author = metadata.get("author") if isinstance(metadata.get("author"), dict) else {}
        author_id = author.get("id")
        exact = (
            e.get("source_type") == "telegram_public_message"
            and resolved is not None
            and author_id is not None
            and str(author_id) == str(resolved)
        )
        if e.get("source_type") == "telegram_public_message":
            mapping = (
                '<div class="meta"><span>Атрибуция</span><strong>ТОЧНОЕ СОВПАДЕНИЕ ID — сообщение принадлежит цели</strong></div>'
                if exact else
                '<div class="meta"><span>Атрибуция</span><strong title="NO — context only; different/unknown author ID">НЕТ — контекст; ID автора отличается или неизвестен</strong></div>'
            )
            ids = f'<div class="meta"><span>Telegram ID</span><code>message={_e(metadata.get("message_id"))} · chat={_e((metadata.get("chat") or {}).get("id"))} · author={_e(author_id)}</code></div>'
        else:
            mapping = '<div class="meta"><span>Тип</span><strong>Профильная / идентификационная запись</strong></div>'
            ids = ""
        evidence_cards.append(
            f'<details class="evidence"><summary><strong>{_e(e.get("title") or "Evidence")}</strong><span class="muted">#{i} · {_e(e.get("source_type"))}</span></summary>'
            f'<div class="evidence-body"><a href="{_e(e.get("source_url"))}" rel="noopener noreferrer">{_e(e.get("source_url"))}</a>'
            f'<div class="meta"><span>Собрано</span><strong>{_e(e.get("collected_at"))}</strong></div>{mapping}{ids}'
            f'<pre>{_e(e.get("text") or "")}</pre><div class="meta"><span>SHA-256</span><code>{_e(e.get("sha256"))}</code></div>'
            f'<details><summary>Сырые метаданные</summary><pre>{_e(e.get("metadata") or {})}</pre></details></div></details>'
        )

    warnings = "".join(f"<li>{_e(x)}</li>" for x in report.get("errors", []))
    collection_warnings = []
    for key in ("global_author_errors", "history_errors", "search_errors", "discovery_errors"):
        for item in collection.get(key, []) or []:
            collection_warnings.append(f"{key.replace('_', ' ').title()}: {item}")

    html_doc = f'''<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Telegram-OSINT — отчёт по {_e(handle)}</title>
<style>
:root{{--void:#070a0e;--panel:#0e141b;--panel-2:#121a23;--raise:#18232f;--zebra:#111922;
--line:#1e2b37;--hair:#17222c;--ink:#e3ecf4;--dim:#93a6b7;--faint:#5f7284;
--accent:#f2a93b;--on-accent:#0b0f14;--link:#63c5ea;--react:#e486b4;--alert:#ff7e70;
--shadow:0 1px 0 rgba(255,255,255,.03) inset,0 18px 40px -30px #000;
--ui:system-ui,-apple-system,"Segoe UI Variable Text","Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
--mono:"JetBrains Mono","Cascadia Code",ui-monospace,"SF Mono","Segoe UI Mono",Consolas,"Liberation Mono",Menlo,monospace;
--gutter:22px;--bar:54px;--rad:14px}}
@media(prefers-color-scheme:light){{:root{{color-scheme:light;--void:#eaeef3;--panel:#fff;--panel-2:#f5f8fb;--raise:#e9eff5;--zebra:#f7f9fb;--line:#dbe3ec;--hair:#e9eef4;--ink:#101823;--dim:#54677a;--faint:#8496a6;--accent:#9a5d04;--on-accent:#fff;--link:#0d6ea6;--react:#a63f76;--alert:#b3261e;--shadow:0 1px 2px rgba(16,26,38,.05),0 14px 30px -24px rgba(16,26,38,.55)}}}}
:root[data-theme="light"]{{color-scheme:light;--void:#eaeef3;--panel:#fff;--panel-2:#f5f8fb;--raise:#e9eff5;--zebra:#f7f9fb;--line:#dbe3ec;--hair:#e9eef4;--ink:#101823;--dim:#54677a;--faint:#8496a6;--accent:#9a5d04;--on-accent:#fff;--link:#0d6ea6;--react:#a63f76;--alert:#b3261e}}
*{{box-sizing:border-box}}[hidden]{{display:none!important}}html{{-webkit-text-size-adjust:100%;scroll-behavior:smooth}}
body{{margin:0;background:var(--void);color:var(--ink);font-family:var(--ui);font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}}
a{{color:var(--link);text-decoration:none}}a:hover{{text-decoration:underline;text-underline-offset:2px}}
:focus-visible{{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}}.muted{{color:var(--faint)}}
.page{{max-width:1440px;margin:0 auto;padding:18px var(--gutter) 72px}}.card{{background:var(--panel);border:1px solid var(--line);border-radius:var(--rad);box-shadow:var(--shadow)}}
.top{{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:12px;height:var(--bar);padding:0 var(--gutter);background:color-mix(in srgb,var(--panel) 86%,transparent);border-bottom:1px solid var(--line);backdrop-filter:blur(14px)}}
.top .brand{{display:flex;align-items:center;gap:9px;font-weight:700;font-size:15px;flex:none}}.top .brand i{{width:9px;height:9px;border-radius:50%;background:var(--accent);box-shadow:0 0 0 4px color-mix(in srgb,var(--accent) 18%,transparent)}}
.top .kind{{flex:none;font-family:var(--mono);font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:var(--faint);padding-left:12px;border-left:1px solid var(--line)}}
.top .stamp{{flex:none;font-family:var(--mono);font-size:11px;color:var(--faint);font-variant-numeric:tabular-nums}}
.find{{position:relative;flex:1 1 auto;max-width:440px;margin-left:auto}}.find input{{width:100%;height:34px;padding:0 38px 0 32px;color:var(--ink);background:var(--panel-2);border:1px solid var(--line);border-radius:9px;font-family:var(--ui);font-size:13px}}
.find input::placeholder{{color:var(--faint)}}.find input:focus{{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 14%,transparent)}}
.find .glass{{position:absolute;left:11px;top:11px;width:11px;height:11px;border:1.6px solid var(--faint);border-radius:50%;pointer-events:none}}.find .glass:after{{content:"";position:absolute;left:9px;top:9px;width:6px;height:1.6px;background:var(--faint);transform:rotate(45deg)}}
.find kbd{{position:absolute;right:9px;top:9px;padding:0 5px;border-radius:5px;border:1px solid var(--line);background:var(--panel);color:var(--faint);font-family:var(--mono);font-size:10px;line-height:15px;pointer-events:none}}
.theme{{flex:none;width:34px;height:34px;display:grid;place-items:center;color:var(--dim);background:var(--panel-2);border:1px solid var(--line);border-radius:9px;cursor:pointer;font-size:14px}}
.hero{{margin-top:18px;padding:22px var(--gutter) 0;overflow:hidden}}.who{{display:flex;align-items:flex-start;gap:18px;flex-wrap:wrap}}
.sigil{{flex:none;width:62px;height:62px;border-radius:16px;display:grid;place-items:center;font-family:var(--mono);font-size:22px;font-weight:600;color:#fff;background:linear-gradient(145deg,#6b5dd3,#26304b);border:1px solid #ffffff2b}}
.who .names{{flex:1 1 260px;min-width:0}}h1{{margin:0;font-size:clamp(24px,3.4vw,34px);line-height:1.12;font-weight:700;letter-spacing:-.025em;overflow-wrap:anywhere}}
.chips{{display:flex;flex-wrap:wrap;align-items:center;gap:7px;margin-top:11px}}.chip{{display:inline-flex;align-items:center;gap:6px;height:26px;padding:0 10px;border-radius:7px;background:var(--panel-2);border:1px solid var(--line);font-family:var(--mono);font-size:12px;color:var(--dim)}}
.chip.handle{{color:var(--link);border-color:color-mix(in srgb,var(--link) 35%,var(--line))}}.chip b{{font-weight:600;color:var(--ink);font-variant-numeric:tabular-nums}}
.cta{{flex:none;display:inline-flex;align-items:center;gap:8px;height:36px;padding:0 16px;border-radius:9px;background:var(--accent);color:var(--on-accent);font-weight:600;font-size:13px}}.cta:hover{{filter:brightness(1.08);text-decoration:none}}
.tape{{margin:22px calc(var(--gutter)*-1) 0;padding:16px var(--gutter) 14px;border-top:1px solid var(--hair);background:var(--panel-2)}}
.tape .cap{{display:flex;justify-content:space-between;align-items:baseline;gap:12px;margin-bottom:10px;font-family:var(--mono);font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--faint)}}
.plot{{display:flex;align-items:flex-end;gap:1px;height:46px}}.plot i{{flex:1 1 0;min-width:0;border-radius:1px 1px 0 0;background:linear-gradient(180deg,var(--accent),color-mix(in srgb,var(--accent) 30%,transparent));height:calc(8% + var(--v,0)*92%)}}.plot i.z{{background:var(--line);height:3px;border-radius:1px}}
.axis{{position:relative;height:14px;margin-top:6px}}.axis span{{position:absolute;transform:translateX(-50%);font-family:var(--mono);font-size:10px;color:var(--faint);font-variant-numeric:tabular-nums}}
.ends{{display:flex;justify-content:space-between;margin-top:2px;font-family:var(--mono);font-size:12px;color:var(--dim);font-variant-numeric:tabular-nums}}
.facts{{display:flex;flex-wrap:wrap;gap:14px 30px;padding:15px var(--gutter);margin:0 calc(var(--gutter)*-1);border-top:1px solid var(--hair)}}.fact{{display:flex;flex-direction:column;gap:3px;min-width:0}}.fact .l{{font-family:var(--mono);font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--faint)}}.fact .v{{font-size:13.5px;overflow-wrap:anywhere;font-variant-numeric:tabular-nums}}
.tiles{{display:grid;grid-template-columns:repeat(auto-fit,minmax(148px,1fr));gap:10px;margin-top:10px}}.tile{{padding:13px 15px 14px;background:var(--panel);border:1px solid var(--line);border-radius:11px}}.tile .n{{display:block;font-family:var(--mono);font-size:26px;font-weight:600;line-height:1.1;letter-spacing:-.02em;font-variant-numeric:tabular-nums}}.tile:first-child .n{{color:var(--accent)}}.tile .l{{display:block;margin-top:5px;font-family:var(--mono);font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--faint)}}
.shell{{display:grid;grid-template-columns:206px minmax(0,1fr);gap:14px;margin-top:14px}}.side .inner{{position:sticky;top:calc(var(--bar) + 14px)}}.side .label{{display:block;margin:0 0 8px 12px;font-family:var(--mono);font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:var(--faint)}}
.side nav{{display:flex;flex-direction:column;gap:1px}}.side a{{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:7px 10px 7px 12px;border-radius:8px;border-left:2px solid transparent;color:var(--dim);font-size:12.5px;line-height:1.3}}.side a b{{font-family:var(--mono);font-size:11px;font-weight:500;color:var(--faint);font-variant-numeric:tabular-nums}}.side a:hover,.side a.on{{background:var(--panel);color:var(--ink);text-decoration:none}}.side a.on{{border-left-color:var(--accent)}}.side a.on b{{color:var(--accent)}}.side .switch{{position:absolute;width:1px;height:1px;opacity:0}}
.sect{{margin-bottom:12px;scroll-margin-top:calc(var(--bar) + 12px)}}.head{{position:sticky;top:var(--bar);z-index:5;display:flex;align-items:center;gap:10px;padding:0 14px;height:46px;cursor:pointer;list-style:none;background:var(--panel);border-radius:var(--rad) var(--rad) 0 0;border-bottom:1px solid transparent}}.head::-webkit-details-marker{{display:none}}.sect[open] .head{{border-bottom-color:var(--hair)}}
.head .chev{{flex:none;width:8px;height:8px;margin-left:3px;border-right:1.6px solid var(--faint);border-bottom:1.6px solid var(--faint);transform:rotate(-45deg);transition:transform .18s ease}}.sect[open] .head .chev{{transform:rotate(45deg)}}.head .t{{font-weight:600;font-size:14px;letter-spacing:-.01em}}.head .n{{margin-left:auto;min-width:26px;height:22px;padding:0 8px;display:inline-flex;align-items:center;justify-content:center;border-radius:7px;background:var(--panel-2);border:1px solid var(--line);font-family:var(--mono);font-size:11px;color:var(--dim)}}
.copy{{width:26px;height:22px;display:inline-flex;align-items:center;justify-content:center;border-radius:7px;border:1px solid transparent;color:var(--faint);font-size:12px;cursor:pointer}}.copy:hover{{color:var(--ink);border-color:var(--line);background:var(--panel-2)}}.copy.done{{color:var(--accent)}}.fold{{overflow-x:auto;border-radius:0 0 var(--rad) var(--rad)}}
table{{width:100%;border-collapse:collapse;font-size:13.5px}}th{{background:var(--panel-2);color:var(--faint);font-family:var(--mono);font-weight:500;font-size:10px;letter-spacing:.13em;text-transform:uppercase;text-align:left;white-space:nowrap;padding:9px 13px;border-bottom:1px solid var(--hair)}}td{{padding:10px 13px;vertical-align:top;overflow-wrap:break-word;unicode-bidi:isolate}}tr:nth-child(even){{background:var(--zebra)}}tr:not(:first-child):hover{{background:var(--raise)}}th:first-child,td:first-child{{padding-left:18px}}th:last-child,td:last-child{{padding-right:18px}}td:not([data-main]){{font-family:var(--mono);font-size:12px;color:var(--dim);font-variant-numeric:tabular-nums}}td[data-main]{{font-weight:600;max-width:520px}}td.mono{{font-family:var(--mono);font-weight:500;font-size:13px}}td:not([data-label]){{width:1%;white-space:nowrap;text-align:right;font-size:11px;color:var(--faint)}}td b{{color:var(--accent);font-weight:600}}.k{{display:none}}.note{{margin:0;padding:12px 18px;border-top:1px solid var(--hair);font-size:12.5px;color:var(--faint)}}.note.alert{{color:var(--alert)}}.fold>.note:first-child{{border-top:0}}.nores{{display:none;padding:26px var(--gutter);text-align:center;color:var(--faint);font-size:13px}}
.src{{display:inline-flex;align-items:center;gap:7px;white-space:nowrap}}.src:before{{content:"";flex:none;width:7px;height:7px;border-radius:2px;background:var(--faint)}}.src.api:before{{background:var(--link)}}.src.msg:before{{background:var(--accent)}}.src.both:before{{background:linear-gradient(135deg,var(--link) 50%,var(--accent) 50%)}}.src.rx:before{{background:var(--react)}}
.sect-title{{display:flex;justify-content:space-between;align-items:baseline;gap:12px;margin:20px 0 10px}}.sect-title h2{{margin:0;font-size:16px}}.ioc-block{{margin-bottom:18px}}.iocgrid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px}}.ioc{{padding:13px 15px 14px;background:var(--panel);border:1px solid var(--line);border-radius:11px}}.ioc-head{{display:flex;justify-content:space-between;align-items:center}}.ioc-head h3{{margin:0;font-size:13px}}.ioc-head strong{{font-family:var(--mono);font-size:18px;color:var(--accent)}}.ioc ul{{max-height:160px;overflow:auto;padding-left:20px;margin-bottom:0}}.evidence{{padding:0;margin-bottom:10px;background:var(--panel);border:1px solid var(--line);border-radius:var(--rad);box-shadow:var(--shadow);overflow:hidden}}.evidence summary{{cursor:pointer;padding:12px 14px;display:flex;justify-content:space-between;gap:12px;list-style:none}}.evidence summary::-webkit-details-marker{{display:none}}.evidence summary:before{{content:"＋";color:var(--accent);font-weight:700;margin-right:8px}}.evidence[open] summary:before{{content:"−"}}.evidence-body{{padding:0 14px 14px}}.meta{{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:8px 0;border-bottom:1px solid var(--hair)}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:var(--panel-2);padding:12px;border-radius:9px;max-height:500px;overflow:auto}}
@media(max-width:900px){{.shell{{display:block}}.side{{margin-bottom:12px}}.side .inner{{position:static}}.side .label{{display:flex;align-items:center;justify-content:space-between;height:38px;margin:0;padding:0 14px;cursor:pointer;color:var(--dim);background:var(--panel);border:1px solid var(--line);border-radius:10px}}.side .label:after{{content:"▾";font-size:12px}}.side .switch:checked~.label:after{{content:"▴"}}.side nav{{display:none;padding:8px;margin-top:6px;background:var(--panel);border:1px solid var(--line);border-radius:10px;max-height:52vh;overflow:auto}}.side .switch:checked~nav{{display:flex}}.top .kind{{display:none}}}}
@media(max-width:620px){{:root{{--gutter:14px;--bar:50px}}.top .stamp{{display:none}}.find{{max-width:none}}.hero{{padding-top:18px}}.sigil{{width:48px;height:48px;border-radius:13px;font-size:17px}}.cta{{width:100%;justify-content:center;order:3}}.tile .n{{font-size:22px}}table{{display:block;background:var(--panel)}}tr:first-child{{display:none}}tr,tr:nth-child(even){{display:block;padding:12px 14px;background:var(--panel);border-bottom:1px solid var(--hair)}}tr:last-child{{border-bottom:0}}tr:not(:first-child):hover{{background:var(--panel)}}td{{display:block;width:auto;padding:0;text-align:left}}td:not([data-label]),td[data-label][data-empty]{{display:none}}td[data-main]{{font-family:var(--ui);font-size:14.5px;font-weight:600;line-height:1.35;padding-bottom:5px;max-width:none}}td[data-label]:not([data-main]){{font-family:var(--mono);font-size:11.5px;line-height:1.6;color:var(--dim)}}.k{{display:inline;color:var(--faint)}}}}
@media print{{:root{{color-scheme:light;--void:#eaeef3;--panel:#fff;--panel-2:#f5f8fb;--raise:#e9eff5;--zebra:#f7f9fb;--line:#dbe3ec;--hair:#e9eef4;--ink:#101823;--dim:#54677a;--faint:#8496a6;--accent:#9a5d04;--on-accent:#fff;--link:#0d6ea6;--react:#a63f76;--alert:#b3261e}}body{{background:#fff}}.top{{position:static;border-bottom:2px solid #000}}.find,.theme,.side,.copy,.chev{{display:none}}.shell{{display:block}}.card,.evidence{{box-shadow:none}}.head{{position:static}}tr{{break-inside:avoid}}}}
</style></head><body>
<header class="top"><div class="brand"><i></i>Telegram-OSINT</div><div class="kind">Отчёт по пользователю</div><div class="stamp">{_e(report.get("generated_at"))}</div>
<div class="find"><span class="glass"></span><input id="q" placeholder="Поиск по отчёту…" autocomplete="off"><kbd>/</kbd></div>
<button class="theme" id="theme" type="button" title="Переключить тему">◐</button></header>
<div class="page">
<section class="hero card"><div class="who"><div class="sigil">{_e(("".join(w[0] for w in str(display_name).split()[:2]) or "?").upper())}</div>
<div class="names"><h1>{_e(display_name)}</h1><div class="chips"><span class="chip">ID <b>{_e(resolved_display)}</b></span>{f'<a class="chip handle" href="{_e(target.get("url") or ("https://t.me/" + str(username)))}">@{_e(str(username).lstrip("@"))}</a>' if username else '<span class="chip">username не наблюдался</span>'}<span class="chip">{_e(report.get("collection_scope"))}</span></div></div>
{f'<a class="cta" href="{_e(target.get("url") or ("https://t.me/" + str(username)))}">Открыть в Telegram</a>' if username else ''}</div>
<div class="tape"><div class="cap"><span>Лента наблюдений</span><span>{tape_marks} отметок</span></div><div class="plot">{plot}</div><div class="axis">{axis}</div><div class="ends"><span>{_e(start.strftime("%d.%m.%Y"))}</span><span>{_e(end.strftime("%d.%m.%Y"))}</span></div></div>
<div class="facts"><div class="fact"><span class="l">Первое наблюдение</span><span class="v">{_e(start.strftime("%d.%m.%Y %H:%M"))}</span></div><div class="fact"><span class="l">Последнее наблюдение</span><span class="v">{_e(end.strftime("%d.%m.%Y %H:%M"))}</span></div><div class="fact"><span class="l">Часовой пояс</span><span class="v">Asia/Kolkata · UTC+05:30</span></div></div></section>
<div class="tiles"><div class="tile"><span class="n">{len(memberships)}</span><span class="l">групп</span></div><div class="tile"><span class="n">{len(messages)}</span><span class="l">сообщений</span></div><div class="tile"><span class="n">{len(reaction_in)}</span><span class="l">реакций</span></div><div class="tile"><span class="n">{len(report.get("evidence", []))}</span><span class="l">источников</span></div></div>

<div class="shell"><aside class="side"><div class="inner"><input class="switch" id="nav-switch" type="checkbox"><label class="label" for="nav-switch">Разделы</label><nav>
<a href="#names"><span>История имён</span><b>{len(profile_rows)}</b></a><a href="#usernames"><span>История @username</span><b>{len(username_rows)}</b></a><a href="#reactions0"><span>Кто ставил реакции</span><b>{len(reaction_in)}</b></a><a href="#reactions1"><span>Кому ставил реакции</span><b>{len(reaction_out)}</b></a><a href="#groups"><span>Группы</span><b>{len(group_rows)}</b></a><a href="#admin"><span>Администрирование</span><b>0</b></a><a href="#chats"><span>Сообщения по чатам</span><b>{len(chat_rows)}</b></a><a href="#messages"><span>Сообщения</span><b>{len(message_rows)}</b></a><a href="#evidence"><span>Свидетельства</span><b>{len(report.get("evidence", []))}</b></a></nav></div></aside><main>

<details class="card sect" id="names" open><summary class="head"><i class="chev"></i><span class="t">История имён</span><b class="n">{len(profile_rows)}</b><span class="copy" role="button" tabindex="0" title="Скопировать таблицу">⧉</span></summary><div class="fold"><table><tr><th></th><th>Значение</th><th>Известно с</th></tr>{_table(profile_rows, ["value","known"], ["Значение","Известно с"], "value", "Нет наблюдений имени.")}</table></div></details>

<details class="card sect" id="usernames" open><summary class="head"><i class="chev"></i><span class="t">История @username</span><b class="n">{len(username_rows)}</b><span class="copy" role="button" tabindex="0" title="Скопировать таблицу">⧉</span></summary><div class="fold"><table><tr><th></th><th>Значение</th><th>Известно с</th></tr>{_table(username_rows, ["value","known"], ["Значение","Известно с"], "value", "Нет наблюдений username.")}</table></div></details>

<details class="card sect" id="reactions0" open><summary class="head"><i class="chev"></i><span class="t">Кто ставил реакции</span><b class="n">{len(reaction_in)}</b><span class="copy" role="button" tabindex="0" title="Скопировать таблицу">⧉</span></summary><div class="fold"><table><tr><th></th><th>Человек</th><th>@username</th><th>ID</th><th>Реакций</th><th>В основном</th><th>Где</th></tr>{_table(reaction_in, ["person","username","id","count","main","where"], ["Человек","@username","ID","Реакций","В основном","Где"], "person", "Нет наблюдений реакций.")}</table><p class="note">Показываются только реакции, которые Telegram-OSINT реально собрал в текущей доступной области данных.</p></div></details>

<details class="card sect" id="reactions1" open><summary class="head"><i class="chev"></i><span class="t">Кому ставил реакции</span><b class="n">{len(reaction_out)}</b><span class="copy" role="button" tabindex="0" title="Скопировать таблицу">⧉</span></summary><div class="fold"><table><tr><th></th><th>Человек</th><th>@username</th><th>ID</th><th>Реакций</th><th>В основном</th><th>Где</th></tr>{_table(reaction_out, ["person","username","id","count","main","where"], ["Человек","@username","ID","Реакций","В основном","Где"], "person", "Нет исходящих реакций, доступных для отображения.")}</table></div></details>

<details class="card sect" id="groups" open><summary class="head"><i class="chev"></i><span class="t">Группы</span><b class="n">{len(group_rows)}</b><span class="copy" role="button" tabindex="0" title="Скопировать таблицу">⧉</span></summary><div class="fold"><table><tr><th></th><th>Чат</th><th>Как узнали</th><th>Дата записи</th></tr>{_table(group_rows, ["chat","how","date"], ["Чат","Как узнали","Дата записи"], "chat", "Нет наблюдений групп/чатов.")}</table></div></details>

<details class="card sect" id="admin" open><summary class="head"><i class="chev"></i><span class="t">Администрирование</span><b class="n">0</b><span class="copy" role="button" tabindex="0" title="Скопировать таблицу">⧉</span></summary><div class="fold"><p class="note">Администраторские права не были подтверждены собранными данными.</p></div></details>

<details class="card sect" id="chats" open><summary class="head"><i class="chev"></i><span class="t">Сообщения по чатам</span><b class="n">{len(chat_rows)}</b><span class="copy" role="button" tabindex="0" title="Скопировать таблицу">⧉</span></summary><div class="fold"><table><tr><th></th><th>Чат</th><th>Сообщений</th></tr>{_table(chat_rows, ["chat","count"], ["Чат","Сообщений"], "chat", "Нет сообщений.")}</table></div></details>

<details class="card sect" id="messages" open><summary class="head"><i class="chev"></i><span class="t">Сообщения</span><b class="n">{len(message_rows)}</b><span class="copy" role="button" tabindex="0" title="Скопировать таблицу">⧉</span></summary><div class="fold"><table><tr><th></th><th>Сообщение</th><th>Дата</th><th>Чат</th></tr>{_table(message_rows, ["message","date","chat"], ["Сообщение","Дата","Чат"], "message", "Нет сообщений, авторство которых подтверждено Telegram ID.")}</table><p class="note">Сообщение считается принадлежащим цели только при точном совпадении Telegram numeric ID автора с разрешённым ID цели.</p></div></details>

<div id="indicators">{ioc_section("Индикаторы цели", iocs)}</div>
<div id="context">{ioc_section("Контекстные индикаторы", context_iocs)}</div>

<section id="evidence"><div class="sect-title"><div><h2>Свидетельства</h2><span class="muted">Каждая запись встроена в этот HTML; внешний сервис для просмотра не нужен.</span></div><span class="muted">{len(report.get("evidence", []))} записей</span></div>
<div id="evidence-list">{"".join(evidence_cards) or '<p class="note">Свидетельства не собраны.</p>'}</div></section>

{f'<section id="warnings"><div class="sect-title"><h2>Предупреждения</h2></div><div class="card"><ul>{warnings}</ul></div></section>' if warnings else ""}
{f'<section id="diagnostics"><div class="sect-title"><h2>Диагностика коллектора</h2></div><div class="card"><ul>{"".join(f"<li>{_e(x)}</li>" for x in collection_warnings)}</ul></div></section>' if collection_warnings else ""}

<section id="technical"><div class="sect-title"><h2>Технические сведения</h2></div><div class="card"><div class="meta"><span>Схема отчёта</span><code>1.9.0</code></div><div class="meta"><span>Область сбора</span><strong>{_e(report.get("collection_scope"))}</strong></div><div class="meta"><span>Часовой пояс</span><strong>Asia/Kolkata (IST, UTC+05:30)</strong></div><div class="meta"><span>Записей evidence</span><strong>{len(report.get("evidence", []))}</strong></div><div class="meta"><span>Ключи анализа</span><code>{_e(", ".join(sorted(a.keys())))}</code></div><p class="note">Этот документ автономен: данные, стили и логика интерфейса встроены в один HTML-файл. Он не требует удалённой таблицы отношений, внешней базы отчётов, удалённого JS/CSS или внешнего API для отображения.</p></div></section>

<footer class="note">Telegram-OSINT · схема 1.9.0 · публичная информация · полнота исторических наблюдений не гарантируется.</footer>
</main></div>
<script>
(function(){{
var root=document.documentElement;
var theme=document.getElementById("theme");
if(theme) theme.addEventListener("click",function(){{
var cur=root.getAttribute("data-theme");
root.setAttribute("data-theme",cur==="light"?"dark":"light");
}});
var q=document.getElementById("q");
var sects=[].slice.call(document.querySelectorAll(".sect"));
if(q){{
var nav=[].slice.call(document.querySelectorAll(".side a"));
var index=sects.map(function(sect){{
var rows=[].slice.call(sect.querySelectorAll("tr")).filter(function(tr){{return tr.cells.length&&tr.cells[0].tagName!=="TH";}});
return {{sect:sect,badge:sect.querySelector(".n"),rows:rows,text:rows.map(function(tr){{return tr.textContent.toLowerCase();}})}};
}});
function run(){{
var term=q.value.trim().toLowerCase();var any=false;
index.forEach(function(x){{
var hits=0;
x.rows.forEach(function(tr,i){{var ok=!term||x.text[i].indexOf(term)>-1;tr.hidden=!ok;if(ok)hits++;}});
var live=!term||hits>0;x.sect.hidden=!live;
if(x.badge)x.badge.textContent=term?String(hits):String(x.rows.length);
var a=nav.find(function(n){{return n.hash==="#"+x.sect.id;}});
if(a)a.hidden=!live;
if(term&&live)x.sect.open=true;if(live)any=true;
}});
var empty=document.getElementById("nores");if(empty)empty.hidden=any;
}}
q.addEventListener("input",run);q.addEventListener("keydown",function(e){{if(e.key==="Escape"){{q.value="";run();}}}});window.addEventListener("keydown",function(e){{if(e.key==="/"&&document.activeElement!==q){{e.preventDefault();q.focus();}}}});
}}
sects.forEach(function(sect){{
var btn=sect.querySelector(".copy");if(!btn)return;
btn.addEventListener("click",function(e){{
e.preventDefault();e.stopPropagation();var lines=[];
sect.querySelectorAll("tr").forEach(function(tr){{if(!tr.hidden)lines.push([].slice.call(tr.cells).map(function(td){{return td.textContent.replace(/\\s+/g," ").trim();}}).join("\\t");}});
var text=lines.join("\\n");var done=function(){{btn.classList.add("done");setTimeout(function(){{btn.classList.remove("done");}},900);}};
if(navigator.clipboard&&navigator.clipboard.writeText)navigator.clipboard.writeText(text).then(done,function(){{}});else{{var t=document.createElement("textarea");t.value=text;document.body.appendChild(t);t.select();try{{document.execCommand("copy");done();}}catch(err){{}}document.body.removeChild(t);}}
}});
}});
var links=[].slice.call(document.querySelectorAll(".side a"));var targets=links.map(function(a){{return document.getElementById(a.hash.slice(1));}});
function sync(){{
var line=parseFloat(getComputedStyle(root).getPropertyValue("--bar"))+2,open=-1;
targets.forEach(function(t,i){{if(t&&!t.hidden&&t.getBoundingClientRect().top<=line)open=i;}});
links.forEach(function(a,i){{a.className=i===open?"on":"";}});
}}
window.addEventListener("scroll",sync,{{passive:true}});window.addEventListener("resize",sync);sync();
}})();
</script></body></html>'''
    p.write_text(html_doc, encoding="utf-8")
