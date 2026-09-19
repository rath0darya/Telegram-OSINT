from __future__ import annotations
import re
from collections import Counter
from datetime import datetime
from .core import extract_iocs
WORD_RE=re.compile(r"[A-Za-z][A-Za-z0-9_'-]{2,}")
HASHTAG_RE=re.compile(r"(?<!\w)#([A-Za-z0-9_]{2,64})")
def analyze_evidence(evidence: list, target_id: int | None = None) -> dict:
    messages=[e for e in evidence if e.source_type=="telegram_public_message"]
    def author_id(e):
        author=(e.metadata or {}).get("author")
        return author.get("id") if isinstance(author, dict) else None
    authored=[e for e in messages if target_id is not None and author_id(e) == target_id]
    reference=[e for e in messages if (e.metadata or {}).get("search_context")]
    unattributed=[e for e in messages if author_id(e) is None]
    chats={((e.metadata or {}).get("chat") or {}).get("id") for e in messages if ((e.metadata or {}).get("chat") or {}).get("id") is not None}
    combined="\n".join(e.text for e in evidence)
    iocs=extract_iocs(combined); words=Counter(w.lower() for w in WORD_RE.findall(combined))
    hashtags=Counter(x.lower() for x in HASHTAG_RE.findall(combined))
    mentions=Counter(i.lower() for e in evidence for i in extract_iocs(e.text)["usernames"])
    dates=Counter(); views=[]; forwards=[]
    for e in messages:
        m=e.metadata or {}; d=m.get("date")
        if d:
            try: dates[datetime.fromisoformat(d.replace("Z","+00:00")).strftime("%Y-%m-%d")]+=1
            except ValueError: pass
        if isinstance(m.get("views"),int): views.append(m["views"])
        if isinstance(m.get("forwards"),int): forwards.append(m["forwards"])
    return {"message_count":len(messages),"authored_message_count":len(authored),"reference_message_count":len(reference),"unattributed_message_count":len(unattributed),"chat_count":len(chats),"iocs":iocs,
      "top_words":[{"value":k,"count":v} for k,v in words.most_common(30)],
      "hashtags":[{"value":k,"count":v} for k,v in hashtags.most_common(30)],
      "mentions":sorted(set(iocs["usernames"])),
      "activity_by_day":dict(sorted(dates.items())),
      "engagement":{"messages_with_views":len(views),"total_views":sum(views),"average_views":round(sum(views)/len(views),2) if views else 0,"max_views":max(views) if views else 0,"total_forwards":sum(forwards),"average_forwards":round(sum(forwards)/len(forwards),2) if forwards else 0},
      "related_public_usernames":sorted(set(iocs["usernames"]))}
