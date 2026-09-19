from __future__ import annotations

import requests
from bs4 import BeautifulSoup
from .core import Evidence, extract_iocs, now_iso, sha256_text, sleep_rate

UA = "Telegram-OSINT/0.1 (+public-research; contact repository maintainer)"

def fetch_public_page(url: str, timeout: int = 15, rate_limit: float = 1.0) -> Evidence:
    sleep_rate(rate_limit)
    last_error = None
    for attempt in range(3):
        try:
            r = requests.get(
                url,
                headers={"User-Agent": UA},
                timeout=timeout,
                allow_redirects=True,
            )
            r.raise_for_status()
            break
        except requests.RequestException as exc:
            last_error = exc
            if attempt == 2:
                raise
            sleep_rate(min(2.0 * (attempt + 1), 5.0))
    if last_error is not None and "r" not in locals():
        raise last_error
    soup = BeautifulSoup(r.text, "html.parser")
    title = soup.title.get_text(" ", strip=True) if soup.title else None

    desc = ""
    meta = soup.find("meta", attrs={"name":"description"})
    if meta:
        desc = meta.get("content","").strip()

    og = {}
    for tag in soup.find_all("meta"):
        prop = tag.get("property") or tag.get("name")
        content = tag.get("content")
        if prop and content and prop.startswith("og:"):
            og[prop] = content.strip()

    text = soup.get_text(" ", strip=True)
    evidence_text = "\n".join(x for x in [desc, text[:12000]] if x)

    return Evidence(
        source_type="telegram_public_page",
        source_url=r.url,
        collected_at=now_iso(),
        title=title,
        text=evidence_text,
        sha256=sha256_text(r.text),
        metadata={
            "http_status": r.status_code,
            "content_type": r.headers.get("content-type"),
            "final_url": r.url,
            "open_graph": og,
            "iocs": extract_iocs(evidence_text),
        },
    )
