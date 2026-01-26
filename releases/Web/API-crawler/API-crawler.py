#!/usr/bin/env python3
import argparse, json, re, time, os
from collections import deque
from pathlib import Path
from urllib.parse import urljoin, urlparse, quote
import requests

BASE_API_URL = "https://example.com/api/"
START_URI = "/api/"
API_TOKEN = os.environ.get("API-CRAWLER_TOKEN", "")
OUT_DIR = Path("API-crawler_output")
MAX_PAGES = 200
PER_SLEEP = 0.2
BATCH = 3
BATCH_SLEEP = 10.0
TIMEOUT = 20.0

URI_RE = re.compile(r"(/api/[^\s\"'<>]+)")

def safe_output_path(uri: str) -> Path:
    p = urlparse(uri)
    rel = p.path.lstrip("/") or "index"
    if rel.endswith("/"):
        rel += "index"
    name = f"{rel}{'__'+quote(p.query, safe='') if p.query else ''}.json"
    path = OUT_DIR / name
    resolved = path.resolve()
    if OUT_DIR.resolve() not in resolved.parents and resolved != OUT_DIR.resolve():
        raise ValueError(f"Refusing to write outside OUT_DIR for {uri}")
    return path

def save_json(uri: str, data) -> None:
    path = safe_output_path(uri)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

def extract_api_uris(obj):
    stack = [obj]
    while stack:
        x = stack.pop()
        if isinstance(x, dict):
            stack.extend(x.values()); stack.extend(x.keys())
        elif isinstance(x, list):
            stack.extend(x)
        elif isinstance(x, str):
            for m in URI_RE.findall(x):
                yield m.rstrip(").,;:]}>\"'")

def throttle(batch_count: int) -> int:
    if BATCH and batch_count >= BATCH:
        print(f"[rate-limit] {batch_count} processed; sleeping {BATCH_SLEEP}s")
        time.sleep(BATCH_SLEEP)
        return 0
    if PER_SLEEP:
        time.sleep(PER_SLEEP)
    return batch_count

def crawl(limit: int) -> None:
    if not API_TOKEN:
        raise SystemExit("Set API_TOKEN constant in the script.")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {API_TOKEN}", "Accept": "application/json"})
    queue, seen, visited = deque([START_URI]), {START_URI}, 0
    batch = 0

    while queue and visited < limit:
        uri = queue.popleft()
        url = urljoin(BASE_API_URL.rstrip('/') + '/', uri)
        print(f"[GET] {url} ({len(queue)} queued)")
        try:
            resp = session.get(url, timeout=TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
        except (requests.RequestException, ValueError) as e:
            print(f"[skip] {uri} -> {e}")
            batch = throttle(batch)
            continue

        save_json(uri, data)
        visited += 1; batch += 1

        for new in extract_api_uris(data):
            if new.startswith("/api/") and new not in seen:
                seen.add(new); queue.append(new)
                print(f"[+] {new} (queue {len(queue)})")

        batch = throttle(batch)

    print(f"Done. Visited={visited}, Discovered={len(seen)-1}, OutputDir={OUT_DIR.resolve()}")

def parse_args():
    p = argparse.ArgumentParser(description="Minimal API spider.")
    p.add_argument("--test", type=int, choices=[1, 2, 3], help="Cap the crawl to N requests.")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    crawl(args.test or MAX_PAGES)
