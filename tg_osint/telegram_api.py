from __future__ import annotations

import asyncio
import os
from typing import Any

from .core import Evidence, extract_iocs, now_iso, sha256_text

async def _collect(username: str, limit: int = 0) -> list[Evidence]:
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
        entity = await client.get_entity(username)
        data = {
            "id": getattr(entity, "id", None),
            "username": getattr(entity, "username", None),
            "title": getattr(entity, "title", None),
            "first_name": getattr(entity, "first_name", None),
            "last_name": getattr(entity, "last_name", None),
            "about": getattr(entity, "about", None),
            "verified": getattr(entity, "verified", None),
            "scam": getattr(entity, "scam", None),
            "fake": getattr(entity, "fake", None),
        }
        text = str(data)
        out.append(Evidence(
            source_type="telegram_api_public_entity",
            source_url=f"https://t.me/{username}",
            collected_at=now_iso(),
            title=data.get("title") or data.get("username"),
            text=text,
            sha256=sha256_text(text),
            metadata={"entity": data, "iocs": extract_iocs(text)},
        ))

        if limit > 0:
            async for msg in client.iter_messages(entity, limit=min(limit, 100)):
                body = msg.message or ""
                if not body:
                    continue
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
                    source_url=f"https://t.me/{username}/{msg.id}",
                    collected_at=now_iso(),
                    title=f"Public message {msg.id}",
                    text=body[:20000],
                    sha256=sha256_text(raw),
                    metadata={**payload, "iocs": extract_iocs(body)},
                ))
    finally:
        await client.disconnect()
    return out

def collect_public(username: str, limit: int = 0) -> list[Evidence]:
    return asyncio.run(_collect(username, limit))
