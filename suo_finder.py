#!/usr/bin/env python3
# suo_finder.py
# Defensive scanner: finds public .suo files on GitHub and flags likely serialized-object indicators for manual review.
# Adds commit metadata (author, date, sha, message, commit URL) for context.
# NEW: skips SVNBridge XML placeholders by default; adds repo context hits; README PoC detection;
#      checks per-repo Visual Studio "open/compile" execution indicators.
#
# Usage:
#   GITHUB_TOKEN=ghp_xxx python3 suo_finder.py --max 100
#
# Author: ek0ms savi0r (updated)

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

# Visual Studio "open/compile" execution indicators to search inside the repo (code search)
VS_INDICATOR_QUERIES = [
    # pre/post build events + dangerous commands
    'repo:{repo} (PreBuildEvent OR PostBuildEvent) extension:csproj',
    'repo:{repo} "powershell -ExecutionPolicy bypass" extension:csproj',
    'repo:{repo} (rundll32 OR mshta OR certutil OR bitsadmin OR curl OR wget) extension:csproj',
    # moniker in #import (C++ / IDL)
    'repo:{repo} "#import \\"script:" extension:cpp',
    'repo:{repo} "#import \\"script:" extension:idl',
    # COM/type-lib references
    'repo:{repo} "<COMFileReference" extension:vcxproj',
    'repo:{repo} "helpstringdll" extension:*',
    'repo:{repo} ".tlb" extension:*',
]

# Terms that suggest the repo README is an "educational PoC"
README_POC_TERMS = [
    "proof of concept", "poc", "educational", "for learning", "do not use illegally",
    "research only", "red team training", "malware analysis", "recoded", "TinyNuke", "hvnc"
]

MAX_BYTES_PER_FILE = 5 * 1024 * 1024  # 5 MiB

def github_code_search(query, page=1, per_page=30):
    q = urlencode({"q": query})
    url = f"{GITHUB_API}/search/code?{q}&page={page}&per_page={per_page}"
    r = requests.get(url, headers=HEADERS, timeout=30)
    r.raise_for_status()
    return r.json()

def fetch_repo_readme(repo_full_name):
    """
    Best-effort: fetch README via contents API.
    Returns lowercased text (decoded) or ''.
    """
    try:
        url = f"{GITHUB_API}/repos/{repo_full_name}/readme"
        r = requests.get(url, headers=HEADERS, timeout=20)
        if r.status_code == 404:
            return ""
        r.raise_for_status()
        j = r.json()
        if j.get("encoding") == "base64" and j.get("content"):
            txt = base64.b64decode(j["content"])
            return txt.decode("utf-8", errors="ignore").lower()
        # fallback raw_url
        raw_url = j.get("download_url")
        if raw_url:
            r2 = requests.get(raw_url, headers=HEADERS, timeout=20)
            if r2.ok:
                return r2.text.lower()
        return ""
    except Exception:
        return ""

def detect_readme_poc(readme_lower):
    """
    Returns (is_poc: bool, matched_terms: list[str], excerpt: str)
    """
    if not readme_lower:
        return (False, [], "")
    hits = [t for t in README_POC_TERMS if t in readme_lower]
    if hits:
        # grab a tiny excerpt around first hit
        idx = readme_lower.find(hits[0])
        start = max(0, idx - 60)
        end = min(len(readme_lower), idx + 120)
        excerpt = readme_lower[start:end].replace("\n", " ")
        return (True, hits, excerpt)
    return (False, [], "")

def repo_vs_exec_indicators(repo_full_name):
    """
    Lightweight per-repo code-search for VS execution-risk indicators.
    Returns list of indicator families matched, e.g. ["prebuild", "powershell", "moniker", "com_tlb"].
    """
    matched = set()
    # Map queries to families
    family_map = {
        0: "prebuild_or_postbuild",
        1: "powershell_bypass",
        2: "dangerous_tools",
        3: "import_script_moniker",
        4: "import_script_moniker",
        5: "comfile_reference",
        6: "helpstringdll",
        7: "tlb_ref",
    }
    # Be polite: a couple of queries per repo; bail early on multiple hits
    for i, qtpl in enumerate(VS_INDICATOR_QUERIES):
        q = qtpl.format(repo=repo_full_name)
        try:
            res = github_code_search(q, page=1, per_page=1)
            if res.get("total_count", 0) > 0:
                matched.add(family_map.get(i, f"q{i}"))
                # small pause to avoid hammering code-search
                time.sleep(0.15)
        except requests.HTTPError:
            # ignore and continue
            continue
        except Exception:
            continue
        # Optional: stop if we already have several indicators
        if len(matched) >= 3:
            break
    return sorted(matched)

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
        url = f"{GITHUB_API}/repos/{owner_repo}/commits?path={quote_plus(path)}&per_page=1"
        r = requests.get(url, headers=HEADERS, timeout=20)
        r.raise_for_status()
        commits = r.json()
        if not commits:
            return {}
        c = commits[0]
        sha = c.get("sha")
        author_login = c.get("author", {}).get("login") if c.get("author") else None
        commit_author = c.get("commit", {}).get("author", {})
        author_name = commit_author.get("name")
        author_email = commit_author.get("email")
        date = commit_author.get("date")
        message = c.get("commit", {}).get("message", "")
        html_url = c.get("html_url")
        return {
            "commit_sha": sha or "",
            "commit_author_login": author_login or "",
            "commit_author_name": author_name or "",
            "commit_author_email": author_email or "",
            "commit_date": date or "",
            "commit_message": (message or "").replace("\n", " "),
            "commit_url": html_url or ""
        }
    except requests.HTTPError as e:
        print(f"[!] HTTP error fetching commits for {repo_full_name}/{path}: {e}", file=sys.stderr)
        return {}
    except Exception as e:
        print(f"[!] Error fetching commits for {repo_full_name}/{path}: {e}", file=sys.stderr)
        return {}

def scan_items(items, writer, include_xml=False, context_terms=None, results_needed=None):
    """
    Scan a page of search results (items). Writes candidate rows to CSV via writer.
    Returns number of candidates added.
    """
    added = 0
    # Small cache so we don’t repeatedly fetch the same repo README/indicators
    repo_cache = {}

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
        if not matches:
            continue

        # Skip obvious SVNBridge XML placeholders unless --include-xml
        path_low = (path or "").lower()
        matches_low = ";".join(matches).lower()
        if (not include_xml) and ("..svnbridge" in path_low) and ("<?xml" in matches_low and "xmlns:x" in matches_low):
            # benign placeholder — skip
            continue

        # Repo-level context and README PoC detection (cached per repo)
        if repo not in repo_cache:
            # README PoC
            rd = fetch_repo_readme(repo)
            poc_flag, poc_terms, poc_excerpt = detect_readme_poc(rd)
            # VS exec indicators (open/compile)
            vs_inds = repo_vs_exec_indicators(repo)
            repo_cache[repo] = {
                "readme_poc": "yes" if poc_flag else "no",
                "readme_poc_terms": ",".join(poc_terms) if poc_terms else "",
                "readme_excerpt": poc_excerpt,
                "vs_exec_indicators": ",".join(vs_inds) if vs_inds else "",
            }
            # be a little gentle with API
            time.sleep(0.15)
        repo_meta = repo_cache[repo]

        # Context keyword hits across repo, path, and commit message
        commit_meta = fetch_commit_metadata(repo, path)
        haystack = " ".join([
            repo.lower(),
            path_low,
            (commit_meta.get("commit_message") or "").lower()
        ])
        context_hits = []
        if context_terms:
            for term in context_terms:
                if term and term.lower() in haystack:
                    context_hits.append(term.lower())
        context_hits = sorted(set(context_hits))

        preview = safe_preview(content)
        row = {
            "repo": repo,
            "path": path,
            "html_url": html_url,
            "matches": ";".join(matches),
            "preview": preview,
            # commit metadata
            "commit_sha": commit_meta.get("commit_sha", ""),
            "commit_author_login": commit_meta.get("commit_author_login", ""),
            "commit_author_name": commit_meta.get("commit_author_name", ""),
            "commit_author_email": commit_meta.get("commit_author_email", ""),
            "commit_date": commit_meta.get("commit_date", ""),
            "commit_message": commit_meta.get("commit_message", ""),
            "commit_url": commit_meta.get("commit_url", ""),
            # NEW columns
            "context_hits": ",".join(context_hits),
            "readme_poc": repo_meta["readme_poc"],
            "readme_poc_terms": repo_meta["readme_poc_terms"],
            "readme_excerpt": repo_meta["readme_excerpt"],
            "vs_exec_indicators": repo_meta["vs_exec_indicators"],
        }
        writer.writerow(row)
        print(f"[+] Candidate: {repo}/{path} matches: {matches} ctx:{row['context_hits']} vs:{row['vs_exec_indicators']} commit:{row['commit_sha'][:8]}")
        added += 1
        if results_needed and added >= results_needed:
            break
        time.sleep(0.25)  # polite pause (commits endpoint + contents)

    return added

def main():
    ap = argparse.ArgumentParser(description="Find .suo files on GitHub and flag likely serialized-object indicators (defensive only). Adds commit/context/PoC/vs-exec metadata.")
    ap.add_argument("--max", type=int, default=100, help="maximum candidate results to save (default 100)")
    ap.add_argument("--per-page", type=int, default=30, help="GitHub search results per page (max 100)")
    ap.add_argument("--outfile", default="suo_candidates_with_commits.csv", help="CSV output file")
    ap.add_argument("--pause", type=float, default=2.0, help="seconds pause between GitHub API pages (rate-limit polite)")
    ap.add_argument("--include-xml", action="store_true", help="include likely XML SVNBridge placeholders (default: skip)")
    ap.add_argument("--context", default="hvnc,rat,loader,stealer,botnet,backdoor,c2,keylogger",
                    help="comma-separated context keywords to highlight (repo/path/commit message)")
    args = ap.parse_args()

    query = "extension:suo"
    print("[*] Defensive suo scanner (with commit & context) — searching GitHub for:", query)
    if not TOKEN:
        print("[!] GITHUB_TOKEN not set — requests may 401 / rate-limit.", file=sys.stderr)
    print("[*] NOTE: This script does not deserialize content. Run manual review on air-gapped VMs.")

    fieldnames = [
        "repo", "path", "html_url",
        "matches", "preview",
        "commit_sha", "commit_author_login", "commit_author_name", "commit_author_email",
        "commit_date", "commit_message", "commit_url",
        # new context columns
        "context_hits", "readme_poc", "readme_poc_terms", "readme_excerpt", "vs_exec_indicators"
    ]
    candidates_found = 0
    page = 1
    total_checked = 0
    context_terms = [t.strip() for t in (args.context or "").split(",") if t.strip()]

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
            added = scan_items(items, writer, include_xml=args.include_xml, context_terms=context_terms, results_needed=remaining_needed)
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
    print("  2) Use context columns: 'context_hits', 'readme_poc', and 'vs_exec_indicators' to triage quickly.")
    print("  3) If malicious, collect immutable evidence (screenshots, git refs) and report to GitHub's abuse/security flow.")

if __name__ == "__main__":
    main()
