# suo_finder

Python tools to **search GitHub for potential malicious `.suo` files**, then **triage them safely** for research and responsible reporting.

All scanning is **read-only**: the tools **never deserialize** or execute anything; they fetch bytes and look for harmless string/byte patterns.

---

## Why `.suo`?

**What is a `.suo`?**
Visual Studio **Solution User Options**. It stores user-specific state (breakpoints, layout, MRU lists). It’s typically **binary** and shouldn’t live in source repos.

**Why scan them?**
Attackers can hide **opaque blobs** (secrets, indicators, staged payloads) in `.suo` files where reviews are lax. You can also find **serialized .NET strings** (e.g., `BinaryFormatter`, `ObjectDataProvider`) that *hint* at past serialization activity. None of this auto-execs; it’s just a **signal** to investigate **safely**.

> Opening a `.suo` in Visual Studio **does not inherently auto-run code**. Treat suspicious `.suo` as **untrusted binaries** and analyze offline.

---

## What’s in this repo

* **`suo_finder.py`** — Searches GitHub for `.suo` files, flags **serialization-like strings**, and adds **commit metadata** (author/date/SHA/message).

  * Extended output columns (context-aware):

    * `context_hits` — repo/path/commit message hits for keywords like `hvnc,rat,loader,botnet,…`
    * `readme_poc` / `readme_poc_terms` / `readme_excerpt` — best-effort README scan for *PoC/educational* disclaimers
    * `vs_exec_indicators` — best-effort repo-wide code search for Visual Studio **open/compile** risk primitives (e.g., `PreBuildEvent`, `#import "script:`, `COMFileReference`, `helpstringdll`, `.tlb`)
  * Skips obvious **SVNBridge XML placeholders** by default (toggle with `--include-xml`).

* **`suo_ranker.py`** — Optional: adds a **heuristic risk score** (binary vs XML, serialization markers, URLs/IPs/base64, entropy, repo keywords) and reasons, for quick sorting.

* **`triage_finder_csv.py`** — Reads Finder/Ranker CSVs, downloads a **small subset** of artifacts, and writes a **redacted Markdown report** to `notes/REPORT.md`.

  * Saves raw bytes into `raw/` for offline inspection (never execute).

Repo example layout:

```
suo_finder/
├── suo_finder.py
├── suo_ranker.py
├── triage_finder_csv.py
├── suo_candidates_with_commits.csv
├── raw/              # fetched samples (binary) – do not run/open in VS
└── notes/REPORT.md   # redacted triage report for sharing/reporting
```

---

## Install

```bash
git clone https://github.com/ekomsSavior/suo_finder.git
cd suo_finder
```

---

## Auth / Rate limits

Create a short-lived GitHub token (no scopes needed for public search):

```bash
export GITHUB_TOKEN="ghp_your_token_here"
curl -sS -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user
```

* **Code search**: ~10 requests/min (GitHub throttle)
* **Other REST** (file/commit): up to ~5k/hr
  Use `--pause` to be polite.

---

## Quick start (3 steps)

### 1) Finder — collect candidates

```bash
# skip obvious SVNBridge XML placeholders (default)
python3 suo_finder.py --max 150

# include XML placeholders too (optional)
python3 suo_finder.py --max 150 --include-xml

# refine “context” keywords (optional)
python3 suo_finder.py --max 150 --context "hvnc,rat,loader,c2,backdoor,tinynuke"
```

**Finder CSV columns** (core):

```
repo,path,html_url,matches,preview,
commit_sha,commit_author_login,commit_author_name,commit_author_email,
commit_date,commit_message,commit_url
```

**Extended columns** (if using the bundled extended finder):

```
context_hits,readme_poc,readme_poc_terms,readme_excerpt,vs_exec_indicators
```

---

### 2) Triage — fetch a *small* subset & produce a redacted report

```bash
# analyze up to 12 rows from the finder CSV and write notes/REPORT.md
python3 triage_finder_csv.py --csv suo_candidates_with_commits.csv --max-files 12

# include XML/SVNBridge placeholders too (optional)
python3 triage_finder_csv.py --csv suo_candidates_with_commits.csv --max-files 12 --include-xml
```

This will create:

* `raw/<owner_repo>__<path>` — raw bytes (up to a safe size cap)
* `notes/REPORT.md` — **redacted** evidence per item:

  * Repo, path, HTML/commit links, author/date
  * `matches` (serialization strings)
  * Redacted **URLs/IPs** and **base64-like** counts (not full IOCs)
  * A ~300-byte **safe preview** (text only; redacted)

> The triage script never deserializes or executes content. It just reads bytes, extracts harmless strings, and redacts sensitive bits.

---

### 3) (Optional) Ranker — add a quick suspicion score

```bash
python3 suo_ranker.py --max 300 --min-score 3
python3 -u suo_ranker.py --max 300 --min-score 3   # unbuffered live output
```

**Ranker CSV fields** add: `score`, `reasons`, `urls`, `ips`, `b64_preview`, `entropy`.

---

## Interpreting results

* **PoC / research repos** (e.g., explicit “for learning/recoded” in README):

  * `readme_poc=yes`, meaningful `context_hits`, usually empty `vs_exec_indicators`.
  * Keep as educational examples; generally **deprioritize for reporting**.

* **Benign leftovers** (SVNBridge/XML):

  * XML previews, `readme_poc=no`, empty `context_hits` and `vs_exec_indicators`.
  * Ignore.

* **Potential abuse / supply-chain-ish**:

  * `readme_poc=no`, normal-looking repo name, but **non-empty `vs_exec_indicators`** (e.g., `prebuild_or_postbuild`, `powershell_bypass`, `import_script_moniker`, `comfile_reference`, `helpstringdll`, `tlb_ref`).
  * **Prioritize for manual review** and likely **report**.

A simple quick-rank from Finder output:

```bash
awk -F, 'BEGIN{OFS=","}
NR==1{print $0",risk_score"; next}
{
  score=0
  if($17!="") score+=5;           # vs_exec_indicators (col 17)
  if($13!="") score+=3;           # context_hits (col 13)
  if($14=="yes") score-=3;        # readme_poc (col 14)
  print $0,score
}' suo_candidates_with_commits.csv | sort -t, -k18,18nr | column -s, -t | sed -n "1,20p"
```

---

## Safe manual review (defensive only)

Inside an **isolated VM**:

```bash
# metadata & type
file raw/*

# quick strings preview
for f in raw/*; do echo "---- $f ----"; strings -a "$f" | head -n 50; done

# indicators (redacted in public reports)
for f in raw/*; do
  echo "---- $f ----"
  strings -a "$f" | grep -Eoi 'https?://[^"<> ]+' | sort -u       # URLs
  strings -a "$f" | grep -Eo '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b'    # IPs
  strings -a "$f" | grep -E '[A-Za-z0-9+/=]{40,}' | head -n 3     # base64-like
done
```

Never deserialize. Never open in Visual Studio. Capture only links/SHAs/previews.

---

## Responsible reporting

1. Gather immutable evidence:

   * Repo/path `html_url`, commit URL, **commit SHA**
   * Redacted preview and indicator counts from `notes/REPORT.md`
2. Submit via GitHub’s **abuse/security** flow.
3. In public write-ups, **redact** sensitive IOCs and emphasize **methodology** and **remediation**.


---

## Ethics

* Analyze only data you’re permitted to.
* Keep research defensive.
* Share responsibly.

