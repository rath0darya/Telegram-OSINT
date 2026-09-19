from __future__ import annotations

import asyncio
import os
import re
from typing import Any

from .core import Evidence, extract_iocs, now_iso, sha256_text


def _entity_data(entity: Any) -> dict:
    first = getattr(entity, "first_name", None)
    last = getattr(entity, "last_name", None)
    title = getattr(entity, "title", None)
    username = getattr(entity, "username", None)
    return {
        "id": getattr(entity, "id", None),
        "username": username,
        "title": title,
        "first_name": first,
        "last_name": last,
        "display_name": title or " ".join(x for x in (first, last) if x) or username,
        "about": getattr(entity, "about", None),
        "verified": getattr(entity, "verified", None),
        "scam": getattr(entity, "scam", None),
        "fake": getattr(entity, "fake", None),
        "entity_type": type(entity).__name__,
    }


def _chat_data(entity: Any) -> dict:
    kind = type(entity).__name__.lower()
    if "channel" in kind:
        chat_type = "channel" if getattr(entity, "broadcast", False) else "supergroup"
    elif "chat" in kind:
        chat_type = "group"
    elif "user" in kind:
        chat_type = "user"
    else:
        chat_type = "unknown"
    return {"id": getattr(entity, "id", None), "username": getattr(entity, "username", None), "title": getattr(entity, "title", None), "type": chat_type}


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
        data = _entity_data(entity)
        data["resolved_from"] = str(target)

        seen = 0
        with_text = 0

        async def collect_one(msg, search_context=False):
            nonlocal seen, with_text
            seen += 1
            body = msg.message or ""
            if not body:
                return
            with_text += 1

            author = None
            try:
                sender = await msg.get_sender()
                if sender is not None:
                    author = _entity_data(sender)
            except Exception:
                pass

            forward_from = None
            try:
                sender_id = getattr(getattr(msg, "forward", None), "sender_id", None)
                if sender_id:
                    sender = await client.get_entity(sender_id)
                    forward_from = _entity_data(sender)
            except Exception:
                pass

            reply_to_author = None
            try:
                reply = await msg.get_reply_message()
                if reply is not None:
                    sender = await reply.get_sender()
                    if sender is not None:
                        reply_to_author = _entity_data(sender)
            except Exception:
                pass

            mentions = []
            for ent in getattr(msg, "entities", None) or []:
                if hasattr(ent, "user_id"):
                    try:
                        mentioned = await client.get_entity(ent.user_id)
                        mentions.append(_entity_data(mentioned))
                    except Exception:
                        pass
                elif ent.__class__.__name__.lower().endswith("messageentitymention"):
                    offset = getattr(ent, "offset", 0)
                    length = getattr(ent, "length", 0)
                    token = body[offset:offset + length]
                    if re.fullmatch(r"@[A-Za-z0-9_]{5,32}", token):
                        mentions.append({"username": token[1:]})

            chat = entity
            try:
                resolved_chat = await msg.get_chat()
                if resolved_chat is not None:
                    chat = resolved_chat
            except Exception:
                pass
            chat_data = _chat_data(chat)
            chat_username = chat_data.get("username")
            source = (
                f"https://t.me/{chat_username}/{msg.id}"
                if chat_username
                else f"telegram://message/{chat_data.get('id')}/{msg.id}"
            )
            payload = {
                "message_id": msg.id,
                "date": msg.date.isoformat() if msg.date else None,
                "text": body[:20000],
                "views": getattr(msg, "views", None),
                "forwards": getattr(msg, "forwards", None),
                "chat": chat_data,
                "author": author,
                "reply_to_message_id": getattr(getattr(msg, "reply_to", None), "reply_to_msg_id", None),
                "reply_to_author": reply_to_author,
                "forward_from": forward_from,
                "mentions": mentions,
                "search_context": search_context,
            }
            out.append(
                Evidence(
                    "telegram_public_message",
                    source,
                    now_iso(),
                    f"Public message {msg.id}",
                    body[:20000],
                    sha256_text(str(payload)),
                    {**payload, "iocs": extract_iocs(body)},
                )
            )

        if limit > 0:
            async for msg in client.iter_messages(entity, limit=limit):
                await collect_one(msg)

            # Also search Telegram's public message index for the resolved username.
            # These are reference/mention observations, not proof that the target authored them.
            if public_username:
                try:
                    async for msg in client.iter_messages(
                        None, search=f"@{public_username}", limit=min(limit, 100)
                    ):
                        await collect_one(msg, search_context=True)
                except Exception:
                    pass

        source = f"https://t.me/{public_username}" if public_username else f"telegram://id/{entity_id}"
        entity_text = str(data)
        out.insert(0, Evidence("telegram_api_public_entity", source, now_iso(), data.get("title") or data.get("display_name") or public_username or str(entity_id), entity_text, sha256_text(entity_text), {"entity": data, "collection": {"messages_requested": max(0, limit), "messages_seen": seen, "messages_with_text": with_text, "resolved_telegram_id": entity_id}, "iocs": extract_iocs(entity_text)}))
    finally:
        await client.disconnect()
    return out


def collect_public(target: str | int, limit: int = 0) -> list[Evidence]:
    return asyncio.run(_collect(target, limit))
