from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from dotenv import load_dotenv

from .core import CaseDB, normalize_target
from .public_web import fetch_public_page
from .report import build_report, write_json, write_text

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="tg-osint",
        description="Telegram public-information OSINT collector for Termux."
    )
    parser.add_argument("target", help="@username or public t.me URL")
    parser.add_argument("--messages", type=int, default=0,
                        help="Optional number of public messages via Telethon (0 disables API mode)")
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--rate", type=float, default=1.0)
    parser.add_argument("--db", default="cases/telegram_osint.db")
    parser.add_argument("--out", default="reports")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    load_dotenv()
    try:
        target = normalize_target(args.target)
    except ValueError as exc:
        parser.error(str(exc))

    Path(args.out).mkdir(parents=True, exist_ok=True)
    db = CaseDB(args.db)
    case_id = db.create_case(target["handle"])
    evidence = []
    errors = []

    try:
        evidence.append(fetch_public_page(target["url"], timeout=args.timeout, rate_limit=args.rate))
    except Exception as exc:
        errors.append(f"public page: {type(exc).__name__}: {exc}")

    if args.messages > 0:
        try:
            from .telegram_api import collect_public
            evidence.extend(collect_public(target["username"], args.messages))
        except Exception as exc:
            errors.append(f"telegram api: {type(exc).__name__}: {exc}")

    for ev in evidence:
        db.add_evidence(case_id, ev)

    report = build_report(target, case_id, evidence, errors)
    stem = target["username"]
    json_path = str(Path(args.out) / f"{stem}_{case_id}.json")
    text_path = str(Path(args.out) / f"{stem}_{case_id}.txt")
    write_json(report, json_path)
    write_text(report, text_path)
    db.close()

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(f"Target      : {target['handle']}")
        print(f"Public URL  : {target['url']}")
        print(f"Evidence    : {len(evidence)}")
        print(f"Case ID     : {case_id}")
        print(f"JSON report : {json_path}")
        print(f"Text report : {text_path}")
        if errors:
            print("\nWarnings:")
            for e in errors:
                print(f"  - {e}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
