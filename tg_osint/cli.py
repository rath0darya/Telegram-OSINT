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
    p = argparse.ArgumentParser(prog="tg-osint", description="Telegram public-information OSINT collector for Termux.")
    p.add_argument("target", nargs="?")
    p.add_argument("--messages", type=int, default=0, help="Collect up to N accessible public messages")
    p.add_argument("--timeout", type=int, default=15)
    p.add_argument("--rate", type=float, default=1.0)
    p.add_argument("--db", default="cases/telegram_osint.db")
    p.add_argument("--out", default="reports")
    p.add_argument("--no-analysis", action="store_true")
    p.add_argument("--intel-db", default="cases/intelligence.db")
    p.add_argument("--search", default="", help="Search historical public entities")
    p.add_argument("--history", type=int, default=None, help="Show stored history for a Telegram numeric ID")
    a = p.parse_args()
    load_dotenv()

    intel = IntelligenceDB(a.intel_db)
    if a.search:
        for row in intel.search(a.search):
            print(row)
        intel.close()
        return 0
    if a.history is not None:
        history = intel.entity_history(a.history)
        if not history:
            print(f"No stored history for Telegram ID {a.history}.")
        else:
            print(f"Telegram ID: {history['entity'].get('telegram_id')}")
            print(f"First observed: {history['entity'].get('first_observed')}")
            print(f"Last observed : {history['entity'].get('last_observed')}")
            print("\nIdentifiers:")
            for x in history["identifiers"]:
                print(f"  {x['identifier_type']}: {x['value']} [{x['first_observed']} -> {x['last_observed']}]")
            print(f"\nProfile snapshots: {len(history['profiles'])}")
            print(f"Messages authored: {len(history['messages'])}")
            print(f"Membership observations: {len(history['memberships'])}")
            print(f"Relationships: {len(history['relationships'])}")
        intel.close()
        return 0

    if not a.target:
        p.error("target is required unless --search or --history is used")
    try:
        t = normalize_target(a.target)
    except ValueError as e:
        p.error(str(e))
    if a.messages < 0:
        p.error("--messages must be >= 0")

    Path(a.out).mkdir(parents=True, exist_ok=True)
    db = CaseDB(a.db)
    run_id = intel.start_run(t["handle"])
    cid = db.create_case(t["handle"])
    ev = []
    errors = []

    if t["url"]:
        try:
            ev.append(fetch_public_page(t["url"], a.timeout, a.rate))
        except Exception as e:
            errors.append(f"public page: {type(e).__name__}: {e}")

    if a.messages:
        try:
            from .telegram_api import collect_public
            api_target = t["telegram_id"] if t["target_type"] == "telegram_id" else t["username"]
            ev.extend(collect_public(api_target, a.messages))
        except Exception as e:
            errors.append(f"telegram api: {type(e).__name__}: {e}")

    for x in ev:
        db.add_evidence(cid, x)
    intel.ingest(ev)
    intel.finish_run(run_id, len(ev))
    resolved_id = next(((x.metadata or {}).get("entity", {}).get("id") for x in ev if x.source_type == "telegram_api_public_entity" and isinstance((x.metadata or {}).get("entity"), dict)), None)
    analysis = {} if a.no_analysis else analyze_evidence(ev, int(resolved_id) if resolved_id is not None else None)
    report = build_report(t, cid, ev, errors, analysis, intel=intel)
    hp = str(Path(a.out) / f"{t['handle'].replace('-', 'neg-')}_{cid}.html")
    write_html(report, hp)
    intel.close()
    db.close()

    collection = next((x.metadata.get("collection", {}) for x in ev if x.source_type == "telegram_api_public_entity"), {})
    print(f"Target      : {t['handle']}")
    print(f"Evidence    : {len(ev)}")
    print(f"Messages    : {analysis.get('message_count', 0)}")
    print(f"Case ID     : {cid}")
    print(f"HTML report : {hp}")
    if collection:
        print(f"API messages: requested={collection.get('messages_requested', 0)} seen={collection.get('messages_seen', 0)} with_text={collection.get('messages_with_text', 0)}")
        print(f"History: seen={collection.get('history_seen', 0)} with_text={collection.get('history_with_text', 0)}")
        print(f"Global author search: seen={collection.get('global_author_seen', 0)}")
        print(f"Public search: seen={collection.get('global_reference_seen', collection.get('search_seen', 0))} with_text={collection.get('search_with_text', 0)}")
        print(f"Discovered public chats: {collection.get('discovered_chat_count', 0)}")
        print(f"Chat scan: seen={collection.get('chat_scan_seen', 0)} target-author-matches={collection.get('chat_scan_matches', 0)}")
        print(f"Membership observations: {collection.get('membership_observations', 0)}")
        for author_error in collection.get("global_author_errors", []):
            print(f"Global author search warning: {author_error}")
        for history_error in collection.get("history_errors", []):
            print(f"History warning: {history_error}")
        for search_error in collection.get("search_errors", []):
            print(f"Search warning: {search_error}")
        print(f"Resolved ID : {collection.get('resolved_telegram_id')}")
    if not ev and not errors:
        errors.append("No evidence was produced; Telegram entity resolution did not return data.")
    if errors:
        print("\nWarnings:")
        for x in errors:
            print(f"  - {x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
