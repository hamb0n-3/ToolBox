# crt.sh Enum

crt.sh Enum is a small command-line helper for pulling DNS names out of Certificate Transparency logs via crt.sh. It ships with practical presets, AND/OR targeting, concurrent fetching with optional progress, and tidy CSV/JSON reporting.

## Features
- Built-in lists of common subdomain patterns and environment keywords.
- Target logic that treats commas as OR within a group while multiple `-t` flags behave like AND.
- Direct crt.sh queries with SQL-like wildcards (`%`, `*`).
- Concurrent requests that include retries, backoff, and an optional progress bar.
- CSV and JSON reports that share the same deterministic naming scheme and metadata.
- Uses `requests` when installed and falls back to the Python standard library (`tqdm` is optional).

## Requirements
- Python 3.8 or newer.
- Optional: `requests`, `tqdm` (install with `pip install requests tqdm`).

The script falls back to `urllib` when `requests` is not installed and shows a lightweight progress indicator when `tqdm` is missing.

## Quick Start
```bash
cd src/OSINT/crt.sh-enum
python3 crt.sh-enum.py -e -t example.com
```

This runs the preset enum against `example.com` using the built-in patterns and writes reports under `reports/`.

## Usage
```
python3 crt.sh-enum.py [options]
```

Key options:

| Flag | Description |
| --- | --- |
| `-e`, `--enum` | Enable preset OSINT enumeration (comprehensive patterns). |
| `-q`, `--query` | Direct crt.sh LIKE query (accepts `%` and `*`). Repeatable. |
| `-t`, `--target` | Targets; commas = OR inside a group; multiple `-t` = AND across groups. Repeatable. |
| `--out-dir` | Output directory (default `reports`). |
| `--basename` | Base filename for outputs (timestamp is appended). |
| `--timeout` | Per‑request timeout in seconds (default 30). |
| `--retries` | Retry count on request failures (default 3). |
| `--workers` | Concurrent worker threads (default 4). |
| `--no-json` | Skip JSON report. |
| `--no-csv` | Skip CSV report. |
| `--no-expired` | Exclude expired certificates. |
| `--no-dedupe` | Do not ask server to deduplicate by certificate. |
| `--no-progress` | Disable progress bar/ETA during enum. |
| `--log-level` | `DEBUG`, `INFO`, `WARNING`, or `ERROR` (default `INFO`). |

Notes:
- `*` is automatically converted to `%` and queries are wrapped with `%` if needed.
- When using multiple `-t` groups, results are intersected by DNS name across groups (strict AND).

## Examples
- Comprehensive enum for one domain with progress and JSON only:
  ```bash
  python3 crt.sh-enum.py -e -t example.com --no-csv --log-level INFO
  ```
- AND across groups (names that match both a domain and an environment):
  ```bash
  # OR within group 2 (prod or admin), AND across the two -t groups
  python3 crt.sh-enum.py -e -t example.com -t "prod,admin"
  ```
- Direct hand‑crafted LIKE queries:
  ```bash
  python3 crt.sh-enum.py -q "%.admin.example.com%" -q "%api%.example.com%"
  ```
- Faster runs with more workers and longer timeouts:
  ```bash
  python3 crt.sh-enum.py -e -t example.com --workers 8 --timeout 45 --retries 5
  ```
- Custom output location and basename:
  ```bash
  python3 crt.sh-enum.py -e -t example.com --out-dir out --basename example-enum
  ```

## Output
- Files are written to `reports/` by default with a timestamp suffix, for example:
  - `reports/enum-YYYYMMDD-HHMMSS.json`
  - `reports/enum-YYYYMMDD-HHMMSS.csv`
- CSV columns:
  - `name`, `common_name`, `issuer_name`, `crtsh_id`, `not_before`, `not_after`, `logged_at`, `is_expired`, `source_query`, `input_group`, `input_term`
- JSON report includes:
  - `meta` (inputs, settings, log path)
  - `summary` (unique DNS count, unique cert IDs, date bounds)
  - `items` (the same fields as the CSV rows)

## Tips
- Start with `-e -t yourdomain.com` for broad coverage, then refine with additional `-t` groups to enforce intersections (e.g., environments like `prod`, `stage`, `admin`).
- Use `--no-expired` to focus on active certificates; keep in mind historical logs can be valuable for discovery.
- If you see intermittent network errors, lower `--workers` or raise `--timeout`; the tool already retries with backoff.
- `--no-dedupe` may return more raw rows; final dedupe is still applied by the tool.

## Ethics & Rate Limits
Use responsibly and in accordance with crt.sh usage policies and applicable laws. Keep concurrency reasonable (`--workers`) to avoid stressing remote services.
