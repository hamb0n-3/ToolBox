#!/usr/bin/env python3
import argparse, json, re, time, os
from collections import deque
from pathlib import Path
from urllib.parse import urljoin, urlparse, quote
import urllib3
import requests

BASE_API_URL = "https://example.com/api/"
START_URI = "/api/"
API_TOKEN = os.environ.get("API-CRAWLER_TOKEN", "")
OUT_DIR = Path("API-crawler_output")
MAX_PAGES = 200
PER_SLEEP = 0.2
BATCH = 3
BATCH_SLEEP = 10.0
MAX_SERVER_ERRORS_PER_BASE = 3
TIMEOUT = 20.0
STATE_PATH = OUT_DIR / "_state.json"

URI_RE = re.compile(r"(/api/[^\s\"'<>]+)")
NUMERIC_BASE_RE = re.compile(r"^(/api/(?:[^/]+/)*\d+)(?=/|$)")

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

def base_numeric_segment(uri: str):
    path = urlparse(uri).path
    match = NUMERIC_BASE_RE.match(path)
    if match:
        return match.group(1).rstrip("/")
    return None

def save_state(path: Path, queue, seen, visited, server_errors, blocked_bases):
    data = {
        "queue": list(queue),
        "seen": sorted(seen),
        "visited": visited,
        "server_errors": {k: int(v) for k, v in server_errors.items()},
        "blocked_bases": sorted(blocked_bases),
        "timestamp": time.time(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")

def load_state(path: Path):
    raw = json.loads(path.read_text(encoding="utf-8"))
    queue = deque(raw.get("queue", []))
    seen = set(raw.get("seen", []))
    visited = int(raw.get("visited", 0))
    server_errors = {k: int(v) for k, v in raw.get("server_errors", {}).items()}
    blocked_bases = set(raw.get("blocked_bases", []))
    return queue, seen, visited, server_errors, blocked_bases

def throttle(batch_count: int) -> int:
    if BATCH and batch_count >= BATCH:
        print(f"[rate-limit] {batch_count} processed; sleeping {BATCH_SLEEP}s")
        time.sleep(BATCH_SLEEP)
        return 0
    if PER_SLEEP:
        time.sleep(PER_SLEEP)
    return batch_count

def crawl(limit: int, resume: bool = False) -> None:
    if not API_TOKEN:
        raise SystemExit("Set API_TOKEN constant in the script.")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
session = requests.Session()
session.verify = False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session.headers.update({"Authorization": f"Bearer {API_TOKEN}", "Accept": "application/json"})
    if resume:
        try:
            queue, seen, visited, server_errors, blocked_bases = load_state(STATE_PATH)
            print(f"[resume] loaded state from {STATE_PATH.resolve()} (visited={visited}, queue={len(queue)})")
        except FileNotFoundError:
            print(f"[resume] no state file at {STATE_PATH}; starting fresh")
            queue, seen, visited = deque([START_URI]), {START_URI}, 0
            server_errors, blocked_bases = {}, set()
        except (ValueError, json.JSONDecodeError) as e:
            print(f"[resume] failed to read state ({e}); starting fresh")
            queue, seen, visited = deque([START_URI]), {START_URI}, 0
            server_errors, blocked_bases = {}, set()
    else:
        if STATE_PATH.exists():
            STATE_PATH.unlink()
        queue, seen, visited = deque([START_URI]), {START_URI}, 0
        server_errors, blocked_bases = {}, set()

    batch = 0

    try:
        while queue and visited < limit:
            uri = queue.popleft()
            base_key = base_numeric_segment(uri)

            if base_key and base_key in blocked_bases:
                print(f"[skip-base] {uri} blocked after {MAX_SERVER_ERRORS_PER_BASE} server errors for {base_key}")
                continue

            url = urljoin(BASE_API_URL.rstrip('/') + '/', uri)
            print(f"[GET] {url} ({len(queue)} queued)")
            try:
                resp = session.get(url, timeout=TIMEOUT)
                status = getattr(resp, "status_code", None)

                if status and 500 <= status < 600 and base_key:
                    count = server_errors.get(base_key, 0) + 1
                    server_errors[base_key] = count
                    if count > MAX_SERVER_ERRORS_PER_BASE:
                        blocked_bases.add(base_key)
                        print(f"[block] {base_key} exceeded {MAX_SERVER_ERRORS_PER_BASE} server errors; future descendants will be skipped")

                resp.raise_for_status()
                data = resp.json()
            except (requests.RequestException, ValueError) as e:
                print(f"[skip] {uri} -> {e}")
                batch += 1
                batch = throttle(batch)
                continue

            save_json(uri, data)
            visited += 1; batch += 1

            for new in extract_api_uris(data):
                if new.startswith("/api/") and new not in seen:
                    new_base = base_numeric_segment(new)
                    if new_base and new_base in blocked_bases:
                        print(f"[suppress] {new} (blocked base {new_base})")
                        continue
                    seen.add(new); queue.append(new)
                    print(f"[+] {new} (queue {len(queue)})")

            batch = throttle(batch)
    except KeyboardInterrupt:
        save_state(STATE_PATH, queue, seen, visited, server_errors, blocked_bases)
        print(f"[saved] interrupted; state written to {STATE_PATH.resolve()} (visited={visited}, queue={len(queue)})")
        return

    if STATE_PATH.exists():
        STATE_PATH.unlink()
    print(f"Done. Visited={visited}, Discovered={len(seen)-1}, OutputDir={OUT_DIR.resolve()}")

def parse_args():
    p = argparse.ArgumentParser(description="Minimal API spider.")
    p.add_argument("--test", type=int, choices=[1, 2, 3, 4], help="Cap the crawl to N requests.")
    p.add_argument("--resume", action="store_true", help="Resume from saved state file.")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    crawl(args.test or MAX_PAGES, resume=args.resume)
