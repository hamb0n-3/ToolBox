#!/usr/bin/env python3

import argparse
import json
import os
import re
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse, quote
import requests

def env_flag(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}

BASE_API_URL = os.environ.get("BASE_API_URL", "https://example.com/api/")  
START_URI = os.environ.get("START_URI", "/api/")                           # seed endpoint (relative URI)
API_TOKEN = os.environ.get("API_TOKEN", "")                                

OUT_DIR = Path("API-crawler_output")                               
MAX_PAGES = int("200"))                        
PER_REQUEST_SLEEP_SECONDS = float("0.2"))
RATE_LIMIT_BATCH = int("3"))            
RATE_LIMIT_SLEEP_SECONDS = float("10"))  
TIMEOUT_SECONDS = float("20"))
VERBOSE_DEFAULT = env_flag("VERBOSE", "1")

URI_RE = re.compile(r"(/api/[^\s\"'<>]+)")

def verbose_print(enabled: bool, msg: str) -> None:
    if enabled:
        print(msg)

def build_full_url(uri: str) -> str:
    """Normalize a URI into an absolute URL using BASE_API_URL as the root."""
    if uri.startswith(("http://", "https://")):
        return uri
    return urljoin(BASE_API_URL.rstrip("/") + "/", uri)

def fetch_json(session: requests.Session, uri: str, verbose: bool = False):
    """GET BASE_API_URL + uri and return parsed JSON (or None on failure)."""
    url = build_full_url(uri)
    verbose_print(verbose, f"[request] GET {url}")
    try:
        r = session.get(url, timeout=TIMEOUT_SECONDS)
        r.raise_for_status()
        return r.json()
    except (requests.RequestException, ValueError) as e:
        print(f"[skip] {uri} -> {e}")
        return None

def safe_output_path(uri: str) -> Path:
    """Map a URI to a safe output file path under OUT_DIR (one file per URI)."""
    p = urlparse(uri)
    rel = p.path.lstrip("/") or "index"
    if rel.endswith("/"):
        rel += "index"

    # Encode query into filename so /api/x?a=1 and /api/x?a=2 don't collide.
    q = f"__{quote(p.query, safe='')}" if p.query else ""
    path = OUT_DIR / f"{rel}{q}.json"

    # Prevent path traversal by resolving and ensuring it's under OUT_DIR.
    resolved = path.resolve()
    if OUT_DIR.resolve() not in resolved.parents and resolved != OUT_DIR.resolve():
        raise ValueError(f"Refusing to write outside OUT_DIR for uri={uri!r}")
    return path

def write_json(uri: str, data) -> None:
    """Write parsed JSON to disk (pretty-printed) using a file name derived from uri."""
    out_path = safe_output_path(uri)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

def extract_api_uris(obj) -> list[str]:
    """Recursively scan any JSON-like object; return list of discovered '/api/...' URIs."""
    found: list[str] = []

    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                walk(k)
                walk(v)
        elif isinstance(x, list):
            for item in x:
                walk(item)
        elif isinstance(x, str):
            for m in URI_RE.findall(x):
                # Trim common trailing punctuation from embedded links: "/api/foo)," -> "/api/foo"
                uri = m.rstrip(").,;:]}>\"'")
                found.append(uri)

    walk(obj)
    return found

def apply_rate_limit(requests_in_batch: int, verbose: bool) -> int:
    """Sleep when the batch threshold is hit; otherwise apply per-request delay."""
    if RATE_LIMIT_BATCH > 0 and requests_in_batch >= RATE_LIMIT_BATCH:
        verbose_print(
            verbose,
            f"[rate-limit] processed {requests_in_batch} requests; sleeping {RATE_LIMIT_SLEEP_SECONDS}s",
        )
        time.sleep(RATE_LIMIT_SLEEP_SECONDS)
        return 0

    if PER_REQUEST_SLEEP_SECONDS:
        time.sleep(PER_REQUEST_SLEEP_SECONDS)
    return requests_in_batch

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Minimal API spider with optional test mode.")
    parser.add_argument(
        "--test",
        type=int,
        choices=[1, 2, 3],
        help="Run in test mode and cap the crawl to this many requests (1-3).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )
    return parser.parse_args()

def main():
    args = parse_args()
    verbose = args.verbose or VERBOSE_DEFAULT
    max_pages = args.test if args.test else MAX_PAGES

    if not API_TOKEN:
        raise SystemExit("Set API_TOKEN env var (or edit the script) to send Authorization header.")

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # Reuse connections + set headers once.
    session = requests.Session()
    session.headers.update(
        {
            "Authorization": f"Bearer {API_TOKEN}",
            "Accept": "application/json",
        }
    )
    queue: list[str] = [START_URI]
    seen: set[str] = set(queue)      # dedupe queue additions
    visited: set[str] = set()        
    discovered: list[str] = []      
    requests_in_batch = 0

    verbose_print(
        verbose,
        f"[start] BASE_API_URL={BASE_API_URL}, START_URI={START_URI}, OUT_DIR={OUT_DIR}, MAX_PAGES={max_pages}",
    )
    if args.test:
        verbose_print(verbose, f"[test] Running in test mode for {max_pages} request(s).")

    while queue and len(visited) < max_pages:
        uri = queue.pop(0)
        if uri in visited:
            continue
        visited.add(uri)

        verbose_print(verbose, f"[queue] Visiting {uri} (remaining in queue: {len(queue)})")
        data = fetch_json(session, uri, verbose)
        requests_in_batch += 1
        if data is None:
            requests_in_batch = apply_rate_limit(requests_in_batch, verbose)
            continue
        write_json(uri, data)
        verbose_print(verbose, f"[write] Saved {safe_output_path(uri)}")

        for new_uri in extract_api_uris(data):
            if new_uri.startswith("/api/") and new_uri not in seen:
                discovered.append(new_uri)   # append to in-memory list
                queue.append(new_uri)        # spider next
                seen.add(new_uri)
                verbose_print(verbose, f"[discover] {new_uri} (queue size now {len(queue)})")

        requests_in_batch = apply_rate_limit(requests_in_batch, verbose)

    print(f"Done. Visited={len(visited)}, Discovered={len(discovered)}, OutputDir={OUT_DIR.resolve()}")

if __name__ == "__main__":
    main()
