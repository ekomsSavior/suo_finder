#!/usr/bin/env python3
# suo_ranker.py
# Defensive: find public .suo files on GitHub, score/rank by risk for manual review.
# Requires: export GITHUB_TOKEN="..."
import os, sys, time, base64, csv, re, math, argparse, requests
from urllib.parse import urlencode, quote_plus

GITHUB_API = "https://api.github.com"
TOKEN = os.environ.get("GITHUB_TOKEN")
HEADERS = {"Accept": "application/vnd.github.v3+json"}
if TOKEN:
    HEADERS["Authorization"] = f"token {TOKEN}"

SERIAL_STRINGS = [
    "BinaryFormatter",
    "System.Runtime.Serialization.Formatters.Binary",
    "ISerializable",
    "System.Windows.Data.ObjectDataProvider",
    "ObjectDataProvider",
    "FormatterAssemblyStyle",
    "StreamingContext",
    "mscorlib",
]
# Lowercased variants checked via .lower()
RISKY_REPO_TERMS = [
    "hvnc","rat","stealer","keylogger","loader","botnet","spy","grabber",
    "crypt","obfuscat","malware","ransom","shell","c2","backdoor"
]
URL_RE = re.compile(rb"(https?://[^\s\"'<>{}]+)", re.I)
IP_RE = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
BASE64_RE = re.compile(rb"(?:[A-Za-z0-9+/]{40,}={0,2})")  # long-ish blob
MAX_BYTES = 5 * 1024 * 1024

def entropy(b: bytes, sample=4096):
    if not b:
        return 0.0
    samp = b[:sample] if len(b) > sample else b
    freq = [0]*256
    for ch in samp:
        freq[ch] += 1
    ent = 0.0
    n = len(samp)
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent  # 0..8

def github_code_search(query, page=1, per_page=30):
    q = urlencode({"q": query})
    url = f"{GITHUB_API}/search/code?{q}&page={page}&per_page={per_page}"
    r = requests.get(url, headers=HEADERS, timeout=30)
    r.raise_for_status()
    return r.json()

def fetch_file_bytes(api_file_url):
    r = requests.get(api_file_url, headers=HEADERS, timeout=30)
    r.raise_for_status()
    j = r.json()
    if j.get("encoding") == "base64" and "content" in j:
        content = base64.b64decode(j["content"])
    elif j.get("download_url"):
        content = requests.get(j["download_url"], headers=HEADERS, timeout=30).content
    else:
        content = b""
    return content[:MAX_BYTES]

def fetch_commit_metadata(repo_full_name, path):
    try:
        url = f"{GITHUB_API}/repos/{repo_full_name}/commits?path={quote_plus(path)}&per_page=1"
        r = requests.get(url, headers=HEADERS, timeout=20)
        r.raise_for_status()
        commits = r.json()
        if not commits:
            return {}
        c = commits[0]
        meta = {
            "commit_sha": c.get("sha",""),
            "commit_url": c.get("html_url",""),
            "commit_message": (c.get("commit",{}) or {}).get("message","").replace("\n"," "),
            "commit_author_login": (c.get("author",{}) or {}).get("login","") if c.get("author") else "",
            "commit_author_name": (c.get("commit",{}) or {}).get("author",{}).get("name",""),
            "commit_date": (c.get("commit",{}) or {}).get("author",{}).get("date",""),
        }
        return meta
    except Exception:
        return {}

def classify_and_score(repo_full_name, path, content, commit_meta, html_url):
    lower_repo = repo_full_name.lower()
    lower_path = path.lower()
    lower_msg  = (commit_meta.get("commit_message","") or "").lower()

    # XML vs binary quick check
    is_xml = content.startswith(b"<?xml") or b"<xml" in content[:256].lower()
    is_svnbridge = ("..svnbridge/" in path) or ("svnbridge" in lower_path)

    # Signals
    matches = []
    c_low = content.lower()
    for s in SERIAL_STRINGS:
        if s.encode() in content or s.lower().encode() in c_low:
            matches.append(s)

    urls = URL_RE.findall(content)[:5]
    ips  = IP_RE.findall(content)[:5]
    b64s = BASE64_RE.findall(content[:200000])[:3]  # scan first 200KB for speed
    ent  = entropy(content, sample=8192)

    # Repo/commit keyword context
    ctx_hits = [kw for kw in RISKY_REPO_TERMS if (kw in lower_repo or kw in lower_path or kw in lower_msg)]

    # Scoring (heuristic)
    score = 0
    reasons = []

    if not is_xml:
        score += 2; reasons.append("binary")
    else:
        reasons.append("xml")

    if matches:
        score += 3; reasons.append("serialization_markers")

    if urls:
        score += 1; reasons.append("urls_present")
    if ips:
        score += 1; reasons.append("ips_present")
    if b64s:
        score += 2; reasons.append("base64_blobs")

    if ent >= 6.5 and not is_xml:
        score += 2; reasons.append(f"high_entropy_{ent:.1f}")

    if ctx_hits:
        score += min(3, len(ctx_hits)); reasons.append("repo_ctx:" + ",".join(ctx_hits))

    # de-bias: downrank obvious SVNBridge XML placeholders
    if is_xml and is_svnbridge and not matches and not b64s:
        score -= 3; reasons.append("svnbridge_placeholder")

    return max(score, 0), reasons, {
        "is_xml": is_xml,
        "is_svnbridge": is_svnbridge,
        "urls": [u.decode(errors="ignore") for u in urls],
        "ips": [i.decode(errors="ignore") for i in ips],
        "b64_preview": [b[:60].decode(errors="ignore") for b in b64s],
        "entropy": ent,
        "matches": matches,
        "html_url": html_url,
    }

def safe_preview(content):
    try:
        return content[:250].decode("utf-8", errors="replace").replace("\n","\\n")
    except Exception:
        return content[:120].hex()

def main():
    ap = argparse.ArgumentParser(description="Rank .suo files by risk (defensive only; no deserialization).")
    ap.add_argument("--max", type=int, default=100, help="max candidates to save")
    ap.add_argument("--per-page", type=int, default=30)
    ap.add_argument("--pause", type=float, default=1.5)
    ap.add_argument("--outfile", default="suo_ranked.csv")
    ap.add_argument("--include-xml", action="store_true", help="include likely XML/SVNBridge placeholders in results")
    ap.add_argument("--min-score", type=int, default=0, help="only write rows with score >= N")
    args = ap.parse_args()

    if not TOKEN:
        print("[!] GITHUB_TOKEN not set — requests may 401 / rate-limit.", file=sys.stderr)

    query = "extension:suo"
    print("[*] Searching:", query)

    rows = []
    page = 1
    total_checked = 0
    candidates = 0

    while True:
        try:
            res = github_code_search(query, page=page, per_page=args.per_page)
        except requests.HTTPError as e:
            print(f"[!] GitHub API error: {e}", file=sys.stderr); break

        items = res.get("items", [])
        if not items:
            break

        for it in items:
            repo = it.get("repository", {}).get("full_name")
            path = it.get("path")
            html_url = it.get("html_url")
            api_file_url = it.get("url")
            if not (repo and path and api_file_url):
                continue

            try:
                content = fetch_file_bytes(api_file_url)
            except Exception as e:
                print(f"[!] fetch error {repo}/{path}: {e}", file=sys.stderr)
                continue

            commit = fetch_commit_metadata(repo, path)
            score, reasons, details = classify_and_score(repo, path, content, commit, html_url)

            # skip pure XML placeholders unless explicitly included
            if not args.include_xml and details["is_xml"] and details["is_svnbridge"] and score < 2:
                continue

            row = {
                "score": score,
                "reasons": ",".join(reasons),
                "repo": repo,
                "path": path,
                "html_url": html_url,
                "matches": ";".join(details["matches"]),
                "urls": ";".join(details["urls"]),
                "ips": ";".join(details["ips"]),
                "b64_preview": ";".join(details["b64_preview"]),
                "entropy": f"{details['entropy']:.2f}",
                "is_xml": details["is_xml"],
                "is_svnbridge": details["is_svnbridge"],
                "preview": safe_preview(content),
                "commit_sha": commit.get("commit_sha",""),
                "commit_author_login": commit.get("commit_author_login",""),
                "commit_author_name": commit.get("commit_author_name",""),
                "commit_date": commit.get("commit_date",""),
                "commit_message": commit.get("commit_message",""),
                "commit_url": commit.get("commit_url",""),
            }
            rows.append(row)
            candidates += 1
            time.sleep(0.2)

        total_checked += len(items)
        print(f"[*] page {page}: checked {len(items)} items, kept {candidates} (running)")
        page += 1
        time.sleep(args.pause)

    # sort & write
    rows = [r for r in rows if r["score"] >= args.min_score]
    rows.sort(key=lambda r: r["score"], reverse=True)
    with open(args.outfile, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else [
            "score","reasons","repo","path","html_url","matches","urls","ips","b64_preview","entropy",
            "is_xml","is_svnbridge","preview","commit_sha","commit_author_login","commit_author_name",
            "commit_date","commit_message","commit_url"
        ])
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

    print(f"[*] Done. Wrote ranked candidates → {args.outfile}")
    if rows[:5]:
        print("[*] Top 5 (score, repo/path):")
        for r in rows[:5]:
            print(f"    {r['score']:>2}  {r['repo']}/{r['path']}  :: {r['reasons']}")
            
if __name__ == "__main__":
    main()

