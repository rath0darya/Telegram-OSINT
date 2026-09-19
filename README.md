# Telegram-OSINT

A Termux-friendly, modular Telegram public-information OSINT toolkit.

## Scope

This project collects and preserves **publicly accessible Telegram information**. It does not attempt to obtain private phone numbers, IP addresses, passwords, private messages, account takeover data, or other non-public account information.

## Features

- Normalize `@username`, `t.me/username`, and public Telegram URLs
- Fetch public Telegram page metadata
- Optional Telethon integration for public entity metadata and public messages
- Extract links, usernames, emails, domains and common IOCs from public text
- Local SQLite case database
- Evidence records with timestamps and SHA-256 hashes
- Responsive HTML reports (the only report format)
- Configurable rate limiting and request timeout
- Real local analysis: top terms, hashtags, mentions, activity-by-day and engagement
- Related public username extraction from collected evidence
- Mobile-friendly, desktop-friendly, and print-friendly HTML evidence views
- Offline-friendly report inspection
- No RaaSHub/RaaSHub-AI dependency

## Install on Termux

```bash
pkg update
pkg install python -y
git clone https://github.com/rath0darya/Telegram-OSINT
cd Telegram-OSINT
python -m pip install -r requirements.txt
chmod +x tg-osint
```

Run:

```bash
./tg-osint @telegram
./tg-osint https://t.me/telegram
./tg-osint @telegram --messages 100
./tg-osint @telegram --messages 200
```

### Optional Telegram API access

For richer public entity/message collection, create Telegram API credentials at my.telegram.org and configure them locally. Never commit credentials.

```bash
cp .env.example .env
# edit .env
```

Then:

```bash
./tg-osint @publicchannel --messages 20
```

The optional API collector is deliberately limited to public entity metadata and public messages.

## Output

Reports are written under `reports/` by default as `.html` files only. The responsive report contains collection statistics, engagement, IOC sections, activity tables, message analysis, evidence cards, hashes, metadata, and collection warnings. It adapts to mobile and desktop screens and includes print-friendly CSS.

## Ethics / authorization

Use this project only for lawful research and information that you are authorized to collect. Respect Telegram's Terms, robots/rate limits, privacy expectations, and applicable law.

