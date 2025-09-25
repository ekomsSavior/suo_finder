# suo_finder

Python tools to **search GitHub for potential malicious `.suo` files** and triage them safely for reporting/research.
All scanning is **read-only**: the scripts **never deserialize** or execute anything; they just fetch bytes and look for harmless string/byte patterns.

---

## Why look at `.suo` files?

* **What is a `.suo`?**
  Visual Studio **Solution User Options** file. It stores *user-specific* state (breakpoints, window layout, recent files, etc.). It is **not** source code, and it’s **not** used by VS Code. Historically it’s a **binary** file and should usually **not** be committed to a repo.

* **How attackers abuse it**
  `.suo` files can be:

  * Used to **stash opaque binary blobs** (exfil data, secrets, staged payloads) inside a repo where reviewers don’t look closely.
  * Contain **serialized .NET object metadata** (strings such as `BinaryFormatter`, `ObjectDataProvider`) that *may* hint a tool once serialized complex objects into it. That doesn’t auto-execute; it’s just a **signal** for deeper manual review.
  * Planted in **malware-adjacent repos** (e.g., RAT/hVNC loaders) as a place to hide indicators (URLs/IPs/base64 blobs).

> ⚠️ **Important**: Opening a `.suo` in Visual Studio **does not inherently auto-run code**. The risk is *operational* (smuggling & confusion) and *tooling-dependent* (unsafe deserializers in custom tools). Treat suspicious `.suo` as untrusted binary and analyze offline.

---

## What’s in this repo?

* `suo_finder.py` – finds `.suo` files via GitHub search and flags ones with **serialization-like strings**. Also pulls **commit metadata** (author/date/SHA/message).
* `suo_ranker.py` – everything above **plus** a **risk score** and reasons (binary vs XML, serialization markers, URLs/IPs/base64, high entropy, repo keywords like `hvnc/rat/loader`, etc.). Outputs a ranked CSV for quick triage.

Both scripts:

* Only read public GitHub content.
* Never deserialize or execute anything.
* Write CSV output you can safely review.

---

## Installation

```bash
git clone https://github.com/ekomsSavior/suo_finder.git
cd suo_finder
```
---

## Auth / Rate limits

Create a Personal Access Token on your github account with **no scopes** (or `public_repo` only if GitHub forces a scope). Short expiry is best.

```bash
export GITHUB_TOKEN="ghp_your_token_here"
# quick sanity check:
curl -sS -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user
```

> Even with a token, GitHub’s **code search** endpoint is throttled (≈10 req/min). File/commit fetches use the higher REST limit (up to ~5k/hr).

---

## Quick Start

### Finder 

```bash
python3 suo_finder.py --max 100
```

### Ranker (risk-scored triage)

```bash
python3 suo_ranker.py --max 300 --min-score 3
```

**Useful flags (ranker):**

* `--include-xml`  Include likely-benign SVNBridge XML `.suo` placeholders.
* `--outfile FILE` Choose output CSV name.
* `--per-page N`   GitHub search page size (default 30).
* `--pause SECS`   Delay between search pages (rate-limit friendly).

Run unbuffered to see progress immediately:

```bash
python3 -u suo_ranker.py --max 300 --min-score 3
```

---

## Output fields (ranker)

`score` – Higher = more suspicious (**heuristic**, not proof).
`reasons` – Why it was scored (e.g., `binary,serialization_markers,urls_present,repo_ctx:hvnc`).
`matches` – Serialization-related strings seen in the bytes (safe).
`urls` / `ips` – Extracted indicators (truncated for safety).
`b64_preview` – Starts of long base64-like blobs (truncated).
`entropy` – Byte entropy estimate (≈0–8). Higher in binary/packed content.
`repo`, `path`, `html_url` – Where it was found.
Commit context: `commit_sha`, `commit_author_*`, `commit_date`, `commit_message`, `commit_url`.

---

## Triage tips (defensive only)

1. **Start with top scores**; cross-check `reasons`.
2. **Binary + serialization markers** are higher interest than XML placeholders.
3. Look for **URLs/IPs/base64 blobs** that seem like C2/download endpoints.
4. Check **commit message / author** context and repo theme (e.g., `hVNC`, `RAT`, `loader`).
5. **Do not** deserialize. For manual review, use `strings`, `hexdump`, `xxd`, `binwalk` inside an **isolated VM**.

---

## Responsible reporting

* Gather immutable evidence (links, commit SHAs, redacted previews).
* Report via GitHub’s **abuse/security** flows.
* Optional: coordinate with relevant CERT if active harm is likely.
* For public write-ups, **redact** sensitive indicators; focus on methodology and remediation.

---

## Limitations

* Heuristics can produce **false positives** (especially SVNBridge XML `.suo` artifacts).
* No exploitation, no deserialization — by design.
* Code search throttling can slow large scans; use `--max` and be polite with `--pause`.


## Safety & ethics

only use on networks and systems you have permission to test on.
use responsibly.

---

