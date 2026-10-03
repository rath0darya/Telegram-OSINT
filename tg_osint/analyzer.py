from __future__ import annotations
import re
from collections import Counter
from datetime import datetime
from .core import extract_iocs
WORD_RE=re.compile(r"[A-Za-z][A-Za-z0-9_'-]{2,}")
HASHTAG_RE=re.compile(r"(?<!\\w)#([A-Za-z0-9_]{2,64})")

def analyze_evidence(evidence: list, target_id: int | None = None) -> dict:
    """Analyze Telegram evidence with Telegram ID as the only authorship key.

    Usernames, display names and arbitrary text are contextual references only.
    They never promote a message to target-authored evidence.
    """
    messages=[e for e in evidence if e.source_type=="telegram_public_message"]
    group_mode = any((e.metadata or {}).get("public_group_context") for e in messages) and target_id is None
    def author_id(e):
        author=(e.metadata or {}).get("author")
        return author.get("id") if isinstance(author, dict) else None
    authored=[e for e in messages if target_id is not None and author_id(e) == target_id]
    reference=[e for e in messages if (e.metadata or {}).get("search_context") and e not in authored]
    unattributed=[e for e in messages if author_id(e) is None]
    non_authored=[e for e in messages if e not in authored]
    author_ids={author_id(e) for e in messages if author_id(e) is not None}
    author_mismatch_count=sum(1 for e in messages if author_id(e) is not None and author_id(e) != target_id)
    def message_iocs(items):
        combined="\\n".join(e.text for e in items)
        return extract_iocs(combined)
    target_iocs=message_iocs(authored)
    reference_iocs=message_iocs(non_authored)
    chats={((e.metadata or {}).get("chat") or {}).get("id") for e in authored if ((e.metadata or {}).get("chat") or {}).get("id") is not None}
    all_chats={((e.metadata or {}).get("chat") or {}).get("id") for e in messages if ((e.metadata or {}).get("chat") or {}).get("id") is not None}
    scope_messages = messages if group_mode else authored
    combined="\\n".join(e.text for e in scope_messages)
    iocs=message_iocs(scope_messages)
    if group_mode:
        target_iocs=iocs
    words=Counter(w.lower() for w in WORD_RE.findall(combined))
    hashtags=Counter(x.lower() for x in HASHTAG_RE.findall(combined))
    mentions=Counter(i.lower() for e in scope_messages for i in extract_iocs(e.text)["usernames"])
    dates=Counter(); views=[]; forwards=[]
    for e in scope_messages:
        m=e.metadata or {}; d=m.get("date")
        if d:
            try: dates[datetime.fromisoformat(d.replace("Z","+00:00")).strftime("%Y-%m-%d")]+=1
            except ValueError: pass
        if isinstance(m.get("views"),int): views.append(m["views"])
        if isinstance(m.get("forwards"),int): forwards.append(m["forwards"])
    return {"message_count":len(messages),"authored_message_count":len(authored),"reference_message_count":len(reference),"context_message_count":len(non_authored),"unattributed_message_count":len(unattributed),"non_authored_message_count":len(non_authored),"author_id_observed_count":len(author_ids),"author_mismatch_count":author_mismatch_count,"chat_count":len(chats),"all_observed_chat_count":len(all_chats),"iocs":iocs,
      "target_iocs":target_iocs,"reference_iocs":reference_iocs,
      "top_words":[{"value":k,"count":v} for k,v in words.most_common(30)],
      "hashtags":[{"value":k,"count":v} for k,v in hashtags.most_common(30)],
      "mentions":sorted(set(iocs["usernames"])),
      "activity_by_day":dict(sorted(dates.items())),
      "engagement":{"messages_with_views":len(views),"total_views":sum(views),"average_views":round(sum(views)/len(views),2) if views else 0,"max_views":max(views) if views else 0,"total_forwards":sum(forwards),"average_forwards":round(sum(forwards)/len(forwards),2) if forwards else 0},
      "related_public_usernames":sorted(set(target_iocs["usernames"])),
      "identity_rule":"telegram_id_exact_match_only",
      "identity_warnings":["Username/name/text matches are contextual references and are not treated as the target identity.","A Telegram ID match is required to classify a message as target-authored."]}
