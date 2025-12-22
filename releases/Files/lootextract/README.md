# LootExtract

LootExtract scans code for hardcoded secrets or endpoints and writes a tidy JSON report for review. It leans on `grep` for speed and adds light parsing so you spend less time sifting through noise.

## Highlights
- Two modes: `secrets` (keys/tokens) and `endpoints` (URLs, DB strings, IPs).
- Recursive scanning with ignore lists and line numbers.
- Parsed, deduplicated output in `clean_output.json`.
- Substring blacklist support plus filtering for version-like IP matches.
- Simple CLI flags that fit into scripts, CI, or quick spot checks.

Note: LootExtract uses `grep` under the hood and expects it to be available on your system.

## Quick Start
```bash
./lootextract -m secrets --dir .
```
- Raw matches are written to `raw_output.txt`.
- Parsed results are saved to `clean_output.json` with file path, line number, and value.

Hunting endpoints instead?
```bash
./lootextract -m endpoints --dir ./src
```

## Common Flows
- Raw only: `./lootextract -m secrets --dir . --raw`
- Parse an existing raw file: `./lootextract --clean -i raw_output.txt -o clean.json`
- Limit by extension: `./lootextract -m secrets --include-ext .py .env .yml`
- Add a blacklist (applies to both modes): `./lootextract -m endpoints --blacklist staging.example.com dummy`

## Endpoint Filtering
To keep results actionable, LootExtract:
- Applies a built-in blacklist and any substrings you pass via `--blacklist`.
- Uses IPv4/IPv6 checks with an allow-all default policy.
- Suppresses bare IP tokens that look like version numbers when `FILTER_VERSION_LIKE` is enabled.
- Deduplicates endpoint values to avoid repeated hits.

## Tips
- Use `jq` for quick review: `jq '.[] | {secret: .secret, file: .file, line: .line}' clean_output.json`
- Point `--dir` at a diff or checkout to scan only recent changes.
- Share `raw_output.txt` with teammates who prefer classic grep output.

Happy hunting.
