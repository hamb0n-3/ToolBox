# URL Verifyer

URL Verifyer is a small multi-threaded status checker for red teamers, penetration testers, and OSINT work. It rotates user agents, supports optional proxy chains, slips in short delays, and can respect API rate limits when you need to stay quiet.

## Features
- Multi-threaded scanning so longer lists finish quickly
- User-agent rotation to look more like regular browsing
- Optional proxy chaining
- Toggle SSL verification per run
- Verbose progress reporting when you want to see the details
- Randomized delays between requests
- Optional rate-limit handling for APIs that publish headers
- CSV output with timestamps, status, proxy info, and errors

## Usage

```sh
python3 URL-verifyer.py -i urls.txt [options]
```

### Required Arguments
- `-i, --input`   Input file containing URLs (one per line)

### Optional Arguments
- `-o, --output`      Output CSV file (default: `results.csv`)
- `-t, --threads`     Number of concurrent threads (default: 1)
- `-p, --proxies`     File containing proxy servers (default: `proxies.txt`)
- `-d, --delay`       Delay range between requests in seconds (default: 1 4)
- `--verify-ssl`      Enable SSL certificate verification
- `-v, --verbose`     Enable verbose output
- `--rate-limit`      Respect X-RateLimit headers if present (for APIs)

## Example Commands

Basic scan:
```sh
python3 URL-verifyer.py -i urls.txt
```

Verbose, multi-threaded scan with 10 threads:
```sh
python3 URL-verifyer.py -i urls.txt -t 10 -v
```

Scan using proxies and respect API rate limits:
```sh
python3 URL-verifyer.py -i urls.txt -p myproxies.txt --rate-limit
```

## Proxy Support
- Store proxies (one per line) in a file (default: `proxies.txt`).
- Formats such as `http://host:port` or `socks5://host:port` work.

## Rate Limiting (APIs)
- With `--rate-limit`, the tool pays attention to `X-RateLimit-Remaining` and `X-RateLimit-Reset` headers (if present) and sleeps as needed.
- Handy for APIs such as GitHub or Twitter where patience avoids bans.

## Output
- Results are saved in CSV format with columns: timestamp, url, status, error, ip, attempts, proxy, user_agent.

## Red Team Notes
- Randomized user agents and delays keep noisy patterns down.
- Proxy support makes it easy to rotate egress points.
- Respecting rate limits helps avoid getting blocked mid-run.
- Only run the tool against targets where you have permission.

## Requirements
- Python 3.x
- `requests`, `urllib3` (install via `pip install -r requirements.txt` if needed)

---

*For educational and authorized testing only.* 
