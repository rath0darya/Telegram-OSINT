from __future__ import annotations

import asyncio
import os
import re
from typing import Any

from .core import Evidence, extract_iocs, now_iso, sha256_text


def _utf16_slice(text: str, offset: int, length: int) -> str:
    raw = text.encode("utf-16-le")
    return raw[offset * 2:(offset + length) * 2].decode("utf-16-le", errors="ignore")


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
    from telethon import TelegramClient, functions, types

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
        search_seen = 0
        search_with_text = 0
        search_errors = []
        discovery_errors = []
        discovered_chats = []
        chat_scan_seen = 0
        chat_scan_matches = 0
        membership_observations = 0
        stored_message_keys = set()

        async def collect_one(msg, search_context=False):
            nonlocal seen, with_text, search_seen, search_with_text
            key = (getattr(msg, "chat_id", None), getattr(msg, "id", None))
            if key in stored_message_keys:
                return
            stored_message_keys.add(key)
            seen += 1
            if search_context:
                search_seen += 1
            body = msg.message or ""
            if not body:
                return
            with_text += 1
            if search_context:
                search_with_text += 1

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
                    token = _utf16_slice(body, offset, length)
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
            reaction_summary = []
            try:
                for reaction in getattr(getattr(msg, "reactions", None), "results", None) or []:
                    reaction_obj = getattr(reaction, "reaction", None)
                    reaction_value = getattr(reaction_obj, "emoticon", None) or getattr(reaction_obj, "document_id", None) or type(reaction_obj).__name__
                    reaction_summary.append({"reaction": reaction_value, "count": getattr(reaction, "count", 0)})
            except Exception:
                reaction_summary = []
            payload = {
                "message_id": msg.id,
                "date": msg.date.isoformat() if msg.date else None,
                "edit_date": msg.edit_date.isoformat() if getattr(msg, "edit_date", None) else None,
                "text": body[:20000],
                "grouped_id": getattr(msg, "grouped_id", None),
                "post_author": getattr(msg, "post_author", None),
                "via_bot_id": getattr(msg, "via_bot_id", None),
                "media_type": type(getattr(msg, "media", None)).__name__ if getattr(msg, "media", None) is not None else None,
                "reaction_summary": reaction_summary,
                "views": getattr(msg, "views", None),
                "forwards": getattr(msg, "forwards", None),
                "chat": chat_data,
                "author": author,
                "reply_to_message_id": getattr(getattr(msg, "reply_to", None), "reply_to_msg_id", None),
                "reply_to_author": reply_to_author,
                "forward_from": forward_from,
                "mentions": mentions,
                "search_context": search_context,
                "resolved_target_id": entity_id,
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

        history_errors = []

        async def collect_history():
            async for msg in client.iter_messages(entity, limit=limit):
                await collect_one(msg)

        global_author_seen = 0
        global_author_errors = []
        global_reference_seen = 0

        async def collect_global_author_messages():
            nonlocal global_author_seen
            # Keep this as an optional accelerator. Telegram may reject the
            # from_user peer for global search even after entity resolution.
            author_peer = await client.get_input_entity(entity)
            async for msg in client.iter_messages(
                None, from_user=author_peer, limit=min(limit, 100)
            ):
                global_author_seen += 1
                await collect_one(msg, search_context=False)

        async def collect_public_search():
            nonlocal global_reference_seen
            if not public_username:
                return
            seen_keys = set()
            for query in (f"@{public_username}", public_username):
                async for msg in client.iter_messages(
                    None, search=query, limit=min(limit, 100)
                ):
                    key = (getattr(msg, "chat_id", None), getattr(msg, "id", None))
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    global_reference_seen += 1
                    await collect_one(msg, search_context=True)

        async def discover_public_chats():
            nonlocal discovered_chats
            queries = []
            if public_username:
                queries.extend([public_username, f"@{public_username}"])
            display_name = data.get("display_name")
            if display_name:
                queries.append(display_name)
            seen_chat_ids = set()
            for query in dict.fromkeys(q for q in queries if q):
                try:
                    result = await client(functions.contacts.SearchRequest(
                        q=query,
                        limit=100,
                    ))
                    for item in list(getattr(result, "chats", None) or []) + list(getattr(result, "users", None) or []):
                        if isinstance(item, types.Channel):
                            if getattr(item, "username", None) or getattr(item, "access_hash", None):
                                chat_id = getattr(item, "id", None)
                                if chat_id not in seen_chat_ids:
                                    seen_chat_ids.add(chat_id)
                                    discovered_chats.append(item)
                        elif isinstance(item, types.Chat):
                            chat_id = getattr(item, "id", None)
                            if chat_id not in seen_chat_ids:
                                seen_chat_ids.add(chat_id)
                                discovered_chats.append(item)
                except Exception as exc:
                    discovery_errors.append(f"{query}: {type(exc).__name__}: {exc}")

        async def scan_discovered_chats():
            nonlocal chat_scan_seen, chat_scan_matches, membership_observations
            remaining = max(0, limit)
            target_id = int(entity_id)
            for chat in discovered_chats:
                if remaining <= 0:
                    break
                try:
                    # Resolve the chat before iteration so Telegram has the
                    # correct input peer/access hash.
                    chat_entity = await client.get_input_entity(chat)
                    chat_data = _chat_data(chat)
                    scanned_here = 0
                    async for msg in client.iter_messages(chat_entity, limit=remaining):
                        scanned_here += 1
                        before = len(out)
                        await collect_one(msg, search_context=False)
                        chat_scan_seen += 1
                        remaining -= 1
                        # Count only newly stored messages whose sender is the
                        # resolved target. The final author ID is checked below.
                        if len(out) > before:
                            body = msg.message or ""
                            try:
                                sender = await msg.get_sender()
                                if getattr(sender, "id", None) == target_id:
                                    chat_scan_matches += 1
                            except Exception:
                                pass
                        if remaining <= 0:
                            break

                    # Record a membership/role observation when Telegram exposes
                    # it through the authenticated account. This does not infer
                    # membership from message authorship.
                    try:
                        permissions = await client.get_permissions(chat_entity, entity)
                        role = "member"
                        if getattr(permissions, "is_creator", False):
                            role = "creator"
                        elif getattr(permissions, "is_admin", False):
                            role = "admin"
                        status = "current_member" if getattr(permissions, "is_member", True) else "not_current_member"
                        membership_observations += 1
                        membership_payload = {
                            "membership": {
                                "chat": chat_data,
                                "status": status,
                                "role": role,
                                "observed_via": "telegram_permissions",
                            },
                            "entity": data,
                        }
                        membership_text = str(membership_payload)
                        out.append(Evidence(
                            "telegram_public_membership",
                            f"https://t.me/{chat_data.get('username')}" if chat_data.get("username") else f"telegram://chat/{chat_data.get('id')}",
                            now_iso(),
                            f"Membership observation for {chat_data.get('title') or chat_data.get('username') or chat_data.get('id')}",
                            membership_text,
                            sha256_text(membership_text),
                            membership_payload,
                        ))
                    except Exception:
                        pass
                except Exception as exc:
                    discovery_errors.append(
                        f"chat {getattr(chat, 'id', None)}: {type(exc).__name__}: {exc}"
                    )
        if limit > 0:
            for attempt in range(3):
                try:
                    await collect_history()
                    break
                except Exception as exc:
                    err = f"{type(exc).__name__}: {exc}"
                    history_errors.append(err)
                    if attempt < 2:
                        await asyncio.sleep(1.5 * (attempt + 1))
                    else:
                        break

            for attempt in range(3):
                try:
                    await collect_global_author_messages()
                    break
                except Exception as exc:
                    err = f"{type(exc).__name__}: {exc}"
                    global_author_errors.append(err)
                    if attempt < 2:
                        await asyncio.sleep(1.5 * (attempt + 1))
                    else:
                        break

            if public_username:
                for attempt in range(3):
                    try:
                        await collect_public_search()
                        break
                    except Exception as exc:
                        err = f"{type(exc).__name__}: {exc}"
                        search_errors.append(err)
                        if attempt < 2:
                            await asyncio.sleep(1.5 * (attempt + 1))
                        else:
                            break

            # Broad public-surface discovery is the fallback when Telegram's
            # global from_user index cannot resolve the target peer.
            await discover_public_chats()
            await scan_discovered_chats()

        source = f"https://t.me/{public_username}" if public_username else f"telegram://id/{entity_id}"
        entity_text = str(data)
        out.insert(0, Evidence("telegram_api_public_entity", source, now_iso(), data.get("title") or data.get("display_name") or public_username or str(entity_id), entity_text, sha256_text(entity_text), {"entity": data, "collection": {"messages_requested": max(0, limit), "messages_seen": seen, "messages_with_text": with_text, "history_seen": seen - search_seen, "history_with_text": with_text - search_with_text, "search_seen": search_seen, "search_with_text": search_with_text, "search_errors": search_errors, "history_errors": history_errors, "global_author_seen": global_author_seen, "global_author_errors": global_author_errors, "global_reference_seen": global_reference_seen, "discovered_chat_count": len(discovered_chats), "chat_scan_seen": chat_scan_seen, "chat_scan_matches": chat_scan_matches, "membership_observations": membership_observations, "discovery_errors": discovery_errors, "resolved_telegram_id": entity_id}, "iocs": extract_iocs(entity_text)}))
    finally:
        await client.disconnect()
    return out


def collect_public(target: str | int, limit: int = 0) -> list[Evidence]:
    return asyncio.run(_collect(target, limit))
