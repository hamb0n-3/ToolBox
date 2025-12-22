# GitHub Scraper

GitHub Scraper is a command-line helper for looking through GitHub code, issues, pull requests, and commits for patterns or keywords. It pairs the GitHub Search API with local regex or literal matching so the output stays focused and easy to skim.

## Features
- Queries `code`, `issues`, `prs`, and `commits` in one run.
- Handles literal keywords or full regular expressions with optional case sensitivity.
- Adds local context around each hit while respecting API rate limits.
- Can write raw results to JSON for later review or automation.
- Retries failed requests with backoff and can optionally include forks in code search.

## Requirements
- Python 3.8 or newer.
- `requests` Python package (`pip install requests`).
- Personal access token with `repo` and `read:org` scopes (set `GITHUB_TOKEN` or pass `--token`).

## Quick Start
```bash
cd src/OSINT/github-scraper
python github-scraper.py -k "api key" --organization my-org --language python
```

Typical output groups results by category, prints compact summaries, and keeps the terminal noise down by limiting top matches per category. Use `--save-json result.json` to keep the raw match data.

## Usage
```
python github-scraper.py [options] -k KEYWORD [KEYWORD ...]
```

Key options:

| Flag | Description |
| --- | --- |
| `-k`, `--keywords` | One or more literal keywords; combined with `--regex` to interpret as patterns. |
| `-o`, `--organization` | Restrict search to a specific GitHub organization. |
| `-l`, `--language` | Limit code search to a language (e.g., `python`, `go`). |
| `-t`, `--token` | GitHub token (defaults to `GITHUB_TOKEN` environment variable). |
| `-r`, `--regex` | Interpret keywords as regular expressions. |
| `--case-sensitive` | Make local matching case-sensitive. |
| `--context-lines` | Number of lines to show above and below each match (default 5). |
| `--categories` | One or more categories (`code`, `issues`, `prs`, `commits`). |
| `--max-per-category` | Cap total API results fetched per category (default 120). |
| `--wildcard` | Append `*` to each literal keyword for broader remote search. |
| `--include-forks` | Include forked repositories in code search. |
| `--save-json PATH` | Write raw result payloads to a JSON file. |

## Examples
- Regex search for loose credential references while limiting categories:
  ```bash
  python github-scraper.py -k "(?i)api[_-]?key" -r --categories code prs
  ```
- Case-sensitive literal search with extra context and JSON export:
  ```bash
  python github-scraper.py -k "Authorization: Bearer" --case-sensitive --context-lines 8 --save-json bearer.json
  ```
- Broader hunt inside an organization’s Python repositories:
  ```bash
  python github-scraper.py -k secret token --organization my-org --language python --wildcard
  ```

## Tips
- Set `GITHUB_TOKEN` in your shell profile to avoid passing `--token` for every run.
- GitHub enforces rate limits. The script automatically waits and retries, but consider scoping queries with `--organization`, `--language`, or narrower keywords.
- For regex mode the script derives seed terms to drive the remote API and then applies your full patterns locally; ensure your regex includes some literal tokens for efficient narrowing.
