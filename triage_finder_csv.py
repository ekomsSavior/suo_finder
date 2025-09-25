#!/usr/bin/env python3
# triage_finder_csv.py — read the finder CSV, fetch raw bytes for a small set,
# extract harmless indicators, and write a redacted Markdown report.
# Defensive only: no deserialization, no execution.

import csv, os, re, sys, argparse, requests
from pathlib import Path

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
B64_RE = re.compile(r"[A-Za-z0-9+/=]{40,}")

def raw_from_html(html_url: str) -> str:
    # https://github.com/A/B/blob/SHA/path -> https://raw.githubusercontent.com/A/B/SHA/path
    return re.sub(r"^https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)$",
                  r"https://raw.githubusercontent.com/\1/\2/\3/\4", html_url)

def redact(s: str) -> str:
    # Mask IP last octet, strip URL paths, truncate long base64-ish runs
    s = IP_RE.sub(lambda m: ".".join(m.group(0).split(".")[:3] + ["x"]), s)
    s = URL_RE.sub(lambda m: (m.group(0).split("/")[0] + "/…") if "/" in m.group(0) else m.group(0), s)
    s = B64_RE.sub(lambda m: (m.group(0)[:20] + "…[truncated]…"), s)
    return s

def safe_preview_bytes(b: bytes, n=300):
    try:
        return b[:n].decode("utf-8", errors="replace").replace("\n", "\\n")
    except Exception:
        return b[:120].hex()

def load_rows(csv_path: Path) -> list[dict]:
    with csv_path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def maybe_filter(rows: list[dict], include_xml: bool) -> list[dict]:
    filtered = []
    for r in rows:
        path = (r.get("path") or "").lower()
        matches = (r.get("matches") or "").lower()
        if not include_xml:
            # drop obvious svnbridge xml placeholders
            if "..svnbridge" in path and ("<?xml" in matches and "xmlns:x" in matches):
                continue
        filtered.append(r)
    return filtered

def main():
    ap = argparse.ArgumentParser(description="Triage finder CSV → redacted Markdown report (defensive only).")
    ap.add_argument("--csv", default="suo_candidates_with_commits.csv",
                    help="Input CSV from suo_finder.py (default: ./suo_candidates_with_commits.csv)")
    ap.add_argument("--max-files", type=int, default=15, help="Max files to fetch and analyze (default: 15)")
    ap.add_argument("--include-xml", action="store_true",
                    help="Include likely XML SVNBridge placeholders (default: skip them)")
    ap.add_argument("--out", default="notes/REPORT.md", help="Output Markdown file (default: notes/REPORT.md)")
    args = ap.parse_args()

    csv_path = Path(args.csv)
    raw_dir = Path("raw")
    notes_dir = Path("notes")
    raw_dir.mkdir(exist_ok=True)
    notes_dir.mkdir(exist_ok=True)

    if not csv_path.exists():
        print(f"[!] CSV not found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    rows = load_rows(csv_path)
    rows = maybe_filter(rows, include_xml=args.include_xml)
    if not rows:
        print("[!] No rows after filtering — try --include-xml or check your CSV.", file=sys.stderr)
        sys.exit(2)

    fetched = []
    for r in rows[:args.max_files]:
        html = r.get("html_url") or ""
        if not html:
            continue
        raw_url = raw_from_html(html)
        out_name = (r.get("repo","").replace("/","_") + "__" +
                    (r.get("path","").replace("/","__").replace(" ","__")))
        out_path = raw_dir / out_name
        try:
            resp = requests.get(raw_url, timeout=30)
            if resp.status_code == 200 and resp.content:
                out_path.write_bytes(resp.content)
                fetched.append((r, resp.content, out_name))
                print(f"[+] saved {out_name} ({len(resp.content)} bytes)")
            else:
                print(f"[!] fetch failed {raw_url} ({resp.status_code})", file=sys.stderr)
        except Exception as e:
            print(f"[!] fetch error {raw_url}: {e}", file=sys.stderr)

    if not fetched:
        print("[!] Nothing fetched — check URLs/CSV.", file=sys.stderr)
        sys.exit(3)

    out_md = Path(args.out)
    with out_md.open("w", encoding="utf-8") as out:
        out.write("# SUO Finder – Redacted Triage Report\n\n")
        out.write(f"Analyzed: {len(fetched)} files\n\n")
        out.write("> This report is strictly defensive. No deserialization or execution was performed.\n\n")
        for r, content, fname in fetched:
            text = content.decode("utf-8", errors="ignore")
            preview = safe_preview_bytes(content, 300)
            urls = sorted(set(URL_RE.findall(text)))
            ips = sorted(set(IP_RE.findall(text)))
            b64_hits = B64_RE.findall(text)

            out.write("## Item\n")
            out.write(f"- Repo: `{r.get('repo','')}`\n")
            out.write(f"- Path: `{r.get('path','')}`\n")
            out.write(f"- HTML: {r.get('html_url','')}\n")
            out.write(f"- Commit: {r.get('commit_url','')} ({(r.get('commit_sha') or '')[:8]})\n")
            author = r.get('commit_author_login') or r.get('commit_author_name') or ''
            out.write(f"- Author: {author}\n")
            out.write(f"- Date: {r.get('commit_date','')}\n")
            out.write(f"- Matches: `{r.get('matches','')}`\n")
            out.write(f"- Saved as: `raw/{fname}`\n")
            if urls:
                out.write(f"- URLs (redacted): {redact(' '.join(urls))}\n")
            if ips:
                out.write(f"- IPs (redacted): {redact(' '.join(ips))}\n")
            if b64_hits:
                out.write(f"- Base64-like blobs: {len(b64_hits)} (redacted)\n")
            out.write("\n### Safe preview (~300 bytes, redacted)\n")
            out.write("```\n")
            out.write(redact(preview))
            out.write("\n```\n\n---\n\n")

    print(f"[+] Report written to {out_md}")

if __name__ == "__main__":
    main()
