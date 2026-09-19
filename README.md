# Telegram-OSINT

A Termux-friendly Telegram public-information OSINT toolkit with an ID-first historical intelligence layer.

## Architecture

resolve username -> numeric Telegram ID -> collect public observations -> store -> correlate -> search -> HTML report

The numeric Telegram ID is the primary identity key once Telegram resolves the target. Usernames and display names are stored as time-stamped observations so later runs can show changes without creating a new entity.

## Scope

This project is limited to lawful public information and data the authenticated Telegram account can legitimately obtain through normal Telegram APIs. It does not bypass access controls or attempt to obtain private phone numbers, IP addresses, passwords, private messages, account takeover data, or hidden account information.

Membership/admin information is recorded only when Telegram actually exposes the observation to the collector. Missing data means unknown, not proof that a person is not a member or admin. The database represents observed history; it cannot reconstruct complete lifetime history or future events.

## Features

- Resolve public usernames to stable Telegram numeric IDs
- Preserve observed username and display-name history
- Store profile snapshots over time
- Store accessible public messages with author IDs when exposed
- Store message date/edit date, views, forwards, replies, forward sources, explicit mentions, media type and reaction aggregates
- Distinguish authored-message history from public search/reference observations
- Preserve collection diagnostics so failed public searches are visible instead of silently treated as empty results
- Store reaction aggregates as historical message observations
- Maintain evidence-backed relationship edges and deterministic SHA-256 provenance
- Build observed mentioned/replied/forwarded relationship edges
- Store membership observations supplied by collection code
- Persistent SQLite historical intelligence database
- Search by username, name or Telegram ID
- HTML-only responsive investigation reports
- Expandable raw evidence and metadata
- SHA-256 evidence hashes and collection timestamps
- Local IOC and message analysis
- No RaaSHub/RaaSHub-AI dependency

## Termux install

    pkg update
    pkg install python -y
    git clone https://github.com/rath0darya/Telegram-OSINT
    cd Telegram-OSINT
    python -m pip install -r requirements.txt
    chmod +x tg-osint

Optional Telegram API access uses TELEGRAM_API_ID and TELEGRAM_API_HASH in a local .env file.

## Collection

    ./tg-osint @publicchannel --messages 200
    ./tg-osint 123456789 --messages 200

Username collection resolves the current public username to the Telegram ID first. Subsequent runs can therefore associate newly observed usernames with the same numeric identity.

## Historical search

    ./tg-osint --search old_username
    ./tg-osint --search 123456789
    ./tg-osint --history 123456789

The history command shows stored identifiers, profile snapshots, authored messages, membership observations and relationships.

## Groups, channels and admin observations

The data model supports chat membership status and role observations, including member/admin-style roles when Telegram exposes them. The collector records chats and membership/activity observations that Telegram actually exposes through the authenticated account and public message history. It does not claim to enumerate every group or channel a user has ever joined. Private or inaccessible membership is not reconstructed.

## Production collection model

A run is an observation snapshot, not a claim of complete lifetime history. Re-running the collector against the same Telegram ID accumulates profile, identifier, message, chat, reaction and relationship observations in SQLite. Public search hits are explicitly marked as reference observations and are never silently counted as target-authored messages. Search failures are retained in collection diagnostics.

The tool deliberately does not attempt to recover private messages, private phone numbers, IP addresses, passwords, hidden membership, deleted/private data, account credentials or access-controlled information. Unknown remains unknown.

## Reports

Reports are written as HTML only under reports/ and include collection coverage diagnostics, identity history, authored/reference message separation, observed chats, relationships, indicators, engagement, reactions and expandable raw evidence. They contain stable ID identity, observed username/name history, profile snapshots, messages authored by the resolved ID when available, observed group/channel membership information, relationships, indicators, engagement and expandable evidence.

## Tests

    python -m unittest discover -s tests -v

## Ethics / authorization

Use this project only for lawful research and information you are authorized to collect. Respect Telegram Terms, rate limits, privacy expectations and applicable law.