from __future__ import annotations

import os
from typing import Any

from .core import Evidence, extract_iocs, now_iso, sha256_text


def _entity_data(entity: Any) -> dict:
    return {
        "id": getattr(entity, "id", None),
        "username": getattr(entity, "username", None),
        "title": getattr(entity, "title", None),
        "about": getattr(entity, "about", None),
        "verified": getattr(entity, "verified", None),
        "scam": getattr(entity, "scam", None),
        "fake": getattr(entity, "fake", None),
        "megagroup": getattr(entity, "megagroup", None),
        "broadcast": getattr(entity, "broadcast", None),
        "participants_count": getattr(entity, "participants_count", None),
        "entity_type": type(entity).__name__,
    }


def _public_chat_type(entity: Any) -> str:
    kind = type(entity).__name__.lower()
    if kind in {"chat", "fakechat"}:
        return "group"
    if "channel" in kind or kind in {"fakebroadcast", "fakechannel"}:
        if getattr(entity, "broadcast", False):
            return "channel"
        return "supergroup"
    return "unknown"


def _message_url(entity: Any, message_id: int) -> str:
    username = getattr(entity, "username", None)
    if username:
        return f"https://t.me/{username}/{message_id}"
    return f"telegram://message/{getattr(entity, 'id', None)}/{message_id}"


async def _collect_group(target: str | int, limit: int = 500, participant_limit: int = 0, admins_only: bool = False) -> list[Evidence]:
    from telethon import TelegramClient, types

    api_id = os.getenv("TELEGRAM_API_ID")
    api_hash = os.getenv("TELEGRAM_API_HASH")
    session = os.getenv("TELEGRAM_SESSION", "telegram_osint")
    if not api_id or not api_hash:
        raise RuntimeError("TELEGRAM_API_ID and TELEGRAM_API_HASH are required for API mode.")

    client = TelegramClient(session, int(api_id), api_hash)
    await client.start()
    out: list[Evidence] = []
    seen_messages: set[tuple[int | None, int | None]] = set()

    try:
        entity = await client.get_entity(target)
        username = getattr(entity, "username", None)
        if not username:
            raise ValueError(
                "Public Group OSINT requires a public Telegram username/link. "
                "Private or invite-only groups are not collected."
            )
        chat_type = _public_chat_type(entity)
        if chat_type not in {"group", "supergroup", "channel"}:
            raise ValueError("Target is not a public group, supergroup, or channel.")

        group = _entity_data(entity)
        group["chat_type"] = chat_type
        group["public"] = True
        group_payload = {
            "entity": group,
            "collection_mode": "public_group_osint",
            "messages_requested": int(limit),
            "participants_requested": int(participant_limit),
            "admins_only": bool(admins_only),
        }
        group_text = str(group_payload)
        out.append(Evidence(
            "telegram_public_group",
            f"https://t.me/{username}",
            now_iso(),
            f"Public Telegram {chat_type}: {group.get('title') or username}",
            group_text,
            sha256_text(group_text),
            group_payload,
        ))

        async def collect_message(msg):
            key = (getattr(msg, "chat_id", None), getattr(msg, "id", None))
            if key in seen_messages:
                return
            seen_messages.add(key)
            body = msg.message or ""
            author = None
            try:
                sender = await msg.get_sender()
                if sender is not None:
                    author = {
                        "id": getattr(sender, "id", None),
                        "username": getattr(sender, "username", None),
                        "first_name": getattr(sender, "first_name", None),
                        "last_name": getattr(sender, "last_name", None),
                        "display_name": getattr(sender, "title", None)
                        or " ".join(x for x in (getattr(sender, "first_name", None), getattr(sender, "last_name", None)) if x)
                        or getattr(sender, "username", None),
                        "entity_type": type(sender).__name__,
                    }
            except Exception:
                pass

            reply_to_author = None
            try:
                reply = await msg.get_reply_message()
                if reply is not None:
                    sender = await reply.get_sender()
                    if sender is not None:
                        reply_to_author = {
                            "id": getattr(sender, "id", None),
                            "username": getattr(sender, "username", None),
                            "display_name": getattr(sender, "title", None)
                            or " ".join(x for x in (getattr(sender, "first_name", None), getattr(sender, "last_name", None)) if x)
                            or getattr(sender, "username", None),
                        }
            except Exception:
                pass

            mentions = []
            for ent in getattr(msg, "entities", None) or []:
                user_id = getattr(ent, "user_id", None)
                if user_id is not None:
                    try:
                        mentioned = await client.get_entity(user_id)
                        mentions.append({
                            "id": getattr(mentioned, "id", None),
                            "username": getattr(mentioned, "username", None),
                            "display_name": getattr(mentioned, "title", None)
                            or " ".join(x for x in (getattr(mentioned, "first_name", None), getattr(mentioned, "last_name", None)) if x),
                        })
                    except Exception:
                        pass

            reactions = []
            try:
                for reaction in getattr(getattr(msg, "reactions", None), "results", None) or []:
                    obj = getattr(reaction, "reaction", None)
                    value = getattr(obj, "emoticon", None) or getattr(obj, "document_id", None) or type(obj).__name__
                    reactions.append({"reaction": value, "count": getattr(reaction, "count", 0)})
            except Exception:
                pass

            payload = {
                "message_id": getattr(msg, "id", None),
                "date": msg.date.isoformat() if getattr(msg, "date", None) else None,
                "edit_date": msg.edit_date.isoformat() if getattr(msg, "edit_date", None) else None,
                "text": body,
                "chat": group,
                "author": author,
                "reply_to_message_id": getattr(getattr(msg, "reply_to", None), "reply_to_msg_id", None),
                "reply_to_author": reply_to_author,
                "mentions": mentions,
                "media_type": type(getattr(msg, "media", None)).__name__ if getattr(msg, "media", None) is not None else None,
                "views": getattr(msg, "views", None),
                "forwards": getattr(msg, "forwards", None),
                "reaction_summary": reactions,
                "iocs": extract_iocs(body),
                "public_group_context": True,
                "target_authorship_rule": "not_applicable_group_collection",
            }
            text = body or "[non-text Telegram message]"
            out.append(Evidence(
                "telegram_public_message",
                _message_url(entity, getattr(msg, "id", 0)),
                now_iso(),
                f"Public group message {getattr(msg, 'id', None)}",
                text,
                sha256_text(str(payload)),
                payload,
            ))

        async for msg in client.iter_messages(entity, limit=max(0, int(limit))):
            await collect_message(msg)

        if participant_limit > 0:
            iterator_filter = types.ChannelParticipantsAdmins if admins_only else None
            try:
                async for user in client.iter_participants(
                    entity,
                    limit=min(int(participant_limit), 200),
                    filter=iterator_filter,
                ):
                    participant = getattr(user, "participant", None)
                    data = {
                        "id": getattr(user, "id", None),
                        "username": getattr(user, "username", None),
                        "first_name": getattr(user, "first_name", None),
                        "last_name": getattr(user, "last_name", None),
                        "display_name": " ".join(
                            x for x in (getattr(user, "first_name", None), getattr(user, "last_name", None)) if x
                        ) or getattr(user, "username", None),
                        "verified": getattr(user, "verified", None),
                        "scam": getattr(user, "scam", None),
                        "fake": getattr(user, "fake", None),
                    }
                    participant_type = type(participant).__name__ if participant is not None else None
                    payload = {
                        "entity": data,
                        "chat": group,
                        "participant_type": participant_type,
                        "observation": "public_participant_list_exposed_by_telegram",
                        "admins_only": bool(admins_only),
                        "membership": {
                            "chat": group,
                            "status": "observed_public_participant",
                            "role": "admin" if admins_only else "member",
                            "observed_via": "telegram_public_participant_list",
                            "target_telegram_id": data.get("id"),
                        },
                    }
                    ptext = str(payload)
                    out.append(Evidence(
                        "telegram_public_group_participant",
                        f"https://t.me/{username}",
                        now_iso(),
                        f"Public group participant: {data.get('display_name') or data.get('id')}",
                        ptext,
                        sha256_text(ptext),
                        payload,
                    ))
            except Exception as exc:
                warning = {
                    "chat": group,
                    "participant_collection_error": f"{type(exc).__name__}: {exc}",
                    "participants_requested": int(participant_limit),
                    "admins_only": bool(admins_only),
                }
                wtext = str(warning)
                out.append(Evidence(
                    "telegram_public_group_diagnostic",
                    f"https://t.me/{username}",
                    now_iso(),
                    "Participant collection warning",
                    wtext,
                    sha256_text(wtext),
                    warning,
                ))
        return out
    finally:
        await client.disconnect()


def collect_public_group(target: str | int, limit: int = 500, participant_limit: int = 0, admins_only: bool = False) -> list[Evidence]:
    import asyncio
    return asyncio.run(_collect_group(target, limit, participant_limit, admins_only))
