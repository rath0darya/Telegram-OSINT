from __future__ import annotations

import asyncio
import os
from typing import Any

from .core import Evidence, extract_iocs, now_iso, sha256_text


async def _collect(target: str | int, limit: int = 0) -> list[Evidence]:
    from telethon import TelegramClient

    api_id = os.getenv("TELEGRAM_API_ID")
    api_hash = os.getenv("TELEGRAM_API_HASH")
    session = os.getenv("TELEGRAM_SESSION", "telegram_osint")
    if not api_id or not api_hash:
        raise RuntimeError("TELEGRAM_API_ID and TELEGRAM_API_HASH are required for API mode.")

    client = TelegramClient(session, int(api_id), api_hash)
    await client.start()
    out: list[Evidence] = []
    try:
        entity = await client.get_entity(target)
        entity_id = getattr(entity, "id", target)
        public_username = getattr(entity, "username", None)
        handle = f"@{public_username}" if public_username else str(entity_id)

        data = {
            "id": entity_id,
            "username": public_username,
            "title": getattr(entity, "title", None),
            "first_name": getattr(entity, "first_name", None),
            "last_name": getattr(entity, "last_name", None),
            "about": getattr(entity, "about", None),
            "verified": getattr(entity, "verified", None),
            "scam": getattr(entity, "scam", None),
            "fake": getattr(entity, "fake", None),
        }

        message_count_seen = 0
        message_count_with_text = 0

        if limit > 0:
            async for msg in client.iter_messages(entity, limit=min(limit, 100)):
                message_count_seen += 1
                body = msg.message or ""
                if not body:
                    continue

                message_count_with_text += 1
                payload = {
                    "message_id": msg.id,
                    "date": msg.date.isoformat() if msg.date else None,
                    "text": body[:20000],
                    "views": getattr(msg, "views", None),
                    "forwards": getattr(msg, "forwards", None),
                }
                raw = str(payload)
                out.append(Evidence(
                    source_type="telegram_public_message",
                    source_url=(
                        f"https://t.me/{public_username}/{msg.id}"
                        if public_username
                        else f"telegram://id/{entity_id}/{msg.id}"
                    ),
                    collected_at=now_iso(),
                    title=f"Public message {msg.id}",
                    text=body[:20000],
                    sha256=sha256_text(raw),
                    metadata={**payload, "iocs": extract_iocs(body)},
                ))

        entity_text = str(data)
        entity_source = (
            f"https://t.me/{public_username}"
            if public_username
            else f"telegram://id/{entity_id}"
        )
        out.insert(0, Evidence(
            source_type="telegram_api_public_entity",
            source_url=entity_source,
            collected_at=now_iso(),
            title=data.get("title") or public_username or str(entity_id),
            text=entity_text,
            sha256=sha256_text(entity_text),
            metadata={
                "entity": data,
                "collection": {
                    "messages_requested": max(0, min(limit, 100)),
                    "messages_seen": message_count_seen,
                    "messages_with_text": message_count_with_text,
                },
                "iocs": extract_iocs(entity_text),
            },
        ))
    finally:
        await client.disconnect()
    return out


def collect_public(target: str | int, limit: int = 0) -> list[Evidence]:
    return asyncio.run(_collect(target, limit))
