#!/usr/bin/env python3
# suo_finder.py
# Defensive scanner: finds public .suo files on GitHub and flags likely serialized-object indicators for manual review.
# Adds commit metadata (author, date, sha, message, commit URL) for context.
#
# Usage:
#   GITHUB_TOKEN=ghp_xxx python3 suo_finder.py --max 100
#
# Author: ek0ms savi0r

import os
import sys
import time
import base64
import csv
import argparse
import requests
from urllib.parse import urlencode, quote_plus

GITHUB_API = "https://api.github.com"
TOKEN = os.environ.get("GITHUB_TOKEN", None)

HEADERS = {"Accept": "application/vnd.github.v3+json"}
if TOKEN:
    HEADERS["Authorization"] = f"token {TOKEN}"

# Heuristic strings that often indicate serialized .NET / XML / SOAP objects
PATTERN_STRINGS = [
    "BinaryFormatter",
    "System.Runtime.Serialization.Formatters.Binary",
    "ISerializable",
    "System.Windows.Data.ObjectDataProvider",
    "ObjectDataProvider",
    "<soap:",
    "<?xml",
    "xmlns:x",
    "TypeName=",
    "mscorlib",
    "System.",
    "assembly",
    "SerializedObject",
    "FormatterAssemblyStyle",
    "StreamingContext",
]
PATTERNS = [p.encode("utf-8") for p in PATTERN_STRINGS] + [p.lower().encode("utf-8") for p in PATTERN_STRINGS]

MAX_BYTES_PER_FILE = 5 * 1024 * 1024  # 5 MiB

def github_code_search(query, page=1, per_page=30):
    q = urlencode({"q": query})
    url = f"{GITHUB_API}/search/code?{q}&page={page}&per_page={per_page}"
    r = requests.get(url, headers=HEADERS, timeout=30)
    r.raise_for_status()
    return r.json()

def fetch_raw(url):
    r = requests.get(url, headers=HEADERS, timeout=30, stream=True)
    r.raise_for_status()
    content = b""
    for chunk in r.iter_content(8192):
        content += chunk
        if len(content) > MAX_BYTES_PER_FILE:
            break
    return content

def find_matches(content_bytes):
    matches = set()
    lower = content_bytes.lower()
    for p in PATTERNS:
        # decode only for storing readable names; check both original and lower
        if p in content_bytes or p in lower:
            try:
                matches.add(p.decode("utf-8", errors="ignore"))
            except Exception:
                matches.add(str(p))
    return sorted(matches)

def safe_preview(content_bytes):
    try:
        text = content_bytes.decode("utf-8", errors="replace")
        return text[:250].replace("\n", "\\n")
    except Exception:
        return content_bytes[:120].hex()

def fetch_commit_metadata(repo_full_name, path):
    """
    Best-effort: fetch the most recent commit that touched `path` in the repo.
    Returns dict with keys: sha, author_name, author_login, author_email, date, message, html_url
    """
    try:
        owner_repo = repo_full_name  # e.g., "owner/repo"
        # path must be URL-encoded
        url = f"{GITHUB_API}/repos/{owner_repo}/commits?path={quote_plus(path)}&per_page=1"
        r = requests.get(url, headers=HEADERS, timeout=20)
        r.raise_for_status()
        commits = r.json()
        if not commits:
            return {}
        c = commits[0]
        sha = c.get("sha")
        # Prefer the author.login (github account) but fall back to commit.commit.author
        author_login = c.get("author", {}).get("login") if c.get("author") else None
        commit_author = c.get("commit", {}).get("author", {})
        author_name = commit_author.get("name")
        author_email = commit_author.get("email")
        date = commit_author.get("date")
        message = c.get("commit", {}).get("message", "")
        html_url = c.get("html_url")  # web link to commit
        return {
            "commit_sha": sha,
            "commit_author_login": author_login or "",
            "commit_author_name": author_name or "",
            "commit_author_email": author_email or "",
            "commit_date": date or "",
            "commit_message": message.replace("\n", " "),
            "commit_url": html_url or ""
        }
    except requests.HTTPError as e:
        # don't crash on GitHub API hiccups
        print(f"[!] HTTP error fetching commits for {repo_full_name}/{path}: {e}", file=sys.stderr)
        return {}
    except Exception as e:
        print(f"[!] Error fetching commits for {repo_full_name}/{path}: {e}", file=sys.stderr)
        return {}

def scan_items(items, writer, results_needed=None):
    """
    Scan a page of search results (items). Writes candidate rows to CSV via writer.
    Returns number of candidates added.
    """
    added = 0
    for it in items:
        repo = it.get("repository", {}).get("full_name")
        path = it.get("path")
        html_url = it.get("html_url")
        api_file_url = it.get("url")
        if not (repo and path and api_file_url):
            continue
        try:
            r = requests.get(api_file_url, headers=HEADERS, timeout=30)
            r.raise_for_status()
            j = r.json()
            if j.get("encoding") == "base64" and "content" in j:
                content = base64.b64decode(j["content"])
            elif "download_url" in j and j["download_url"]:
                content = fetch_raw(j["download_url"])
            else:
                # fallback: try to fetch download_url if present
                download_url = j.get("download_url")
                if download_url:
                    content = fetch_raw(download_url)
                else:
                    continue
        except requests.HTTPError as e:
            print(f"[!] HTTP error fetching {repo}/{path}: {e}", file=sys.stderr)
            continue
        except Exception as e:
            print(f"[!] Error fetching {repo}/{path}: {e}", file=sys.stderr)
            continue

        matches = find_matches(content)
        if matches:
            preview = safe_preview(content)
            commit_meta = fetch_commit_metadata(repo, path)
            row = {
                "repo": repo,
                "path": path,
                "html_url": html_url,
                "matches": ";".join(matches),
                "preview": preview,
                # commit metadata (may be empty dict)
                "commit_sha": commit_meta.get("commit_sha", ""),
                "commit_author_login": commit_meta.get("commit_author_login", ""),
                "commit_author_name": commit_meta.get("commit_author_name", ""),
                "commit_author_email": commit_meta.get("commit_author_email", ""),
                "commit_date": commit_meta.get("commit_date", ""),
                "commit_message": commit_meta.get("commit_message", ""),
                "commit_url": commit_meta.get("commit_url", ""),
            }
            writer.writerow(row)
            print(f"[+] Candidate: {repo}/{path} matches: {matches} commit: {row['commit_sha'][:8]}")
            added += 1
            if results_needed and added >= results_needed:
                break
            # polite small pause to reduce burstiness on commits endpoint
            time.sleep(0.25)
    return added

def main():
    ap = argparse.ArgumentParser(description="Find .suo files on GitHub and flag likely serialized-object indicators (defensive only). Adds commit metadata.")
    ap.add_argument("--max", type=int, default=100, help="maximum candidate results to save (default 100)")
    ap.add_argument("--per-page", type=int, default=30, help="GitHub search results per page (max 100)")
    ap.add_argument("--outfile", default="suo_candidates_with_commits.csv", help="CSV output file")
    ap.add_argument("--pause", type=float, default=2.0, help="seconds pause between GitHub API pages (rate-limit polite)")
    args = ap.parse_args()

    query = "extension:suo"
    print("[*] Defensive suo scanner (with commit context) — searching GitHub for:", query)
    print("[*] NOTE: This script does not deserialize content. Run manual review on air-gapped VMs.")

    fieldnames = [
        "repo", "path", "html_url",
        "matches", "preview",
        "commit_sha", "commit_author_login", "commit_author_name", "commit_author_email",
        "commit_date", "commit_message", "commit_url"
    ]
    candidates_found = 0
    page = 1
    total_checked = 0

    with open(args.outfile, "w", newline="", encoding="utf-8") as csvf:
        writer = csv.DictWriter(csvf, fieldnames=fieldnames)
        writer.writeheader()

        while True:
            try:
                res = github_code_search(query, page=page, per_page=args.per_page)
            except requests.HTTPError as e:
                print(f"[!] GitHub API error: {e}. Headers: {getattr(e.response, 'headers', {})}", file=sys.stderr)
                break
            items = res.get("items", [])
            if not items:
                break

            remaining_needed = (args.max - candidates_found) if args.max else None
            added = scan_items(items, writer, results_needed=remaining_needed)
            candidates_found += added
            total_checked += len(items)
            print(f"[*] page {page}: checked {len(items)} items, total checked {total_checked}, candidates so far {candidates_found}")

            if args.max and candidates_found >= args.max:
                print("[*] reached candidate max, stopping.")
                break
            page += 1
            time.sleep(args.pause)

    print(f"[*] Done. Candidate CSV: {args.outfile}")
    print("Next steps (safe & defensive):")
    print("  1) Manually review each candidate in an air-gapped VM. Do not deserialize or run binaries.")
    print("  2) Use commit metadata to triage: suspicious accounts, recent additions, or forks with no history are worth special attention.")
    print("  3) If malicious, collect immutable evidence (screenshots, git refs) and report to GitHub's abuse/security flow.")

if __name__ == "__main__":
    main()
