# nmap_scanner.py

An nmap wrapper with per-host logging, batched scanning, pause/resume, a
scheduled start/daily window, and a time limit. State lives in a per-engagement
SQLite database, so a scan can be stopped and resumed and the results of many
scans accumulate in one queryable place.

## Requirements

- `nmap` on your `PATH`, Python 3 (SQLite is built in).
- `apscheduler` — only needed for `--window` (`pip install apscheduler`).

## How it works

By default each batch of hosts gets one full-port discovery scan (`-p-`), and
every host with open ports then gets a service/script scan (`-sV -sC`) on just
those ports. Use `--custom` to replace both stages with your own nmap command.

Each run is an **engagement** backed by a SQLite DB (default `./engagement.db`).
The DB tracks every target host (pending/completed) and every open port found.
`--resume <db>` continues an engagement, scanning only the hosts it hasn't
completed yet. nmap output files are still written under the output dir.

## Usage

```bash
./nmap_scanner.py 10.0.0.1 example.com            # targets on the CLI
./nmap_scanner.py 192.168.1.0/24                  # CIDR
./nmap_scanner.py 10.0.0.1-10.0.0.50              # full IP-IP range
./nmap_scanner.py -iL targets.txt                 # targets from a file
./nmap_scanner.py 10.0.0.0/24 --db ./             # new engagement DB in ./
./nmap_scanner.py 10.0.0.0/24 --db ops/acme.db    # new engagement at a path
./nmap_scanner.py --resume ops/acme.db            # continue, scan only pending hosts
./nmap_scanner.py 10.0.0.0/24 --custom '-sU -p 53,161 -T4'   # custom scan instead
./nmap_scanner.py 10.0.0.0/24 --batch-size 32     # 32 hosts per nmap invocation
./nmap_scanner.py 10.0.0.0/24 -o /data/scans      # custom output directory
./nmap_scanner.py 10.0.0.0/24 --time 8h           # run 8h, then auto-pause
./nmap_scanner.py 10.0.0.0/24 --start 14:46       # wait until 14:46 to begin
./nmap_scanner.py 10.0.0.0/24 --window 17:00-07:00  # only scan 5pm-7am daily
```

## Options

| Flag | Purpose |
|------|---------|
| `-iL FILE` | Read targets from a file (one per line, `#` comments ok). |
| `--db PATH` | Start a **new** engagement DB. A directory (or `.`) creates `engagement.db` inside it; a file path is used as-is. Default: `./engagement.db`. Errors if it already exists (use `--resume`). |
| `--resume DB` | Continue an existing engagement, scanning only its not-yet-completed hosts. Output dir and scan mode are restored from the DB. |
| `-o, --output-dir DIR` | Where to write nmap output files (default `./NMAP_scans`). |
| `--batch-size N` | Hosts per nmap invocation (default 16). Applies to discovery and `--custom`; service scans stay per host. |
| `--custom 'ARGS'` | Skip discovery/service; run nmap with these args, batched. Add `-Pn` to scan hosts that don't answer ping discovery. |
| `--time DUR` | Run for `30s`/`8m`/`8h`/`2d`, then auto-pause. |
| `--start HH:MM` | Wait until this wall-clock time before starting. |
| `--window HH:MM-HH:MM` | Only scan inside this daily window (may wrap midnight); requires apscheduler. |

## Engagement database

One DB file == one engagement. Tables:

- `hosts(ip, status, added_at, completed_at)` — every target; `status` is
  `pending` or `completed`. Resume scans the pending ones.
- `open_ports(ip, port, proto, service, source, seen_at)` — every open port,
  with `source` of `discovery`, `custom`, or `import:<file>`.
- `meta(key, value)` — engagement config (output dir, custom-scan mode, times).

It's plain SQLite — query it with `sqlite3 engagement.db` (e.g.
`SELECT ip, port, service FROM open_ports ORDER BY ip`).

## Importing other nmap output — `nmap_import.py`

Fold existing nmap `.gnmap` / `.nmap` files into an engagement DB so scans run
elsewhere land in the same database:

```bash
./nmap_import.py --db engagement.db scan.gnmap other.nmap
./nmap_import.py --db ./ --status pending results/*.gnmap
```

Imported hosts are marked `completed` by default (so a resumed scan skips them);
`--status pending` records their ports without claiming they're scanned. Re-
importing merges: ports dedupe on `(ip, port, proto)` and `.nmap` files fill in
service names.

## Output layout

```
NMAP_scans/
├── OpenPorts/<port>/hosts.md            # hosts found with that port open
├── OpenPorts/<port>/service_scans.*     # service-scan output per port
├── ServiceScans/all_hosts.*             # combined service scans
└── CustomScans/                         # --custom mode output
    ├── all_hosts.*                       # combined custom scans
    └── OpenPorts/<port>/hosts.md
```

## Pause / resume

Press `Ctrl-C` for a menu: kill, pause, or continue. `--time` and `--window`
auto-pause too. Progress is checkpointed to the DB after every host (WAL +
`synchronous=NORMAL`, so a kill never corrupts it), so resuming with
`--resume <db>` only scans hosts that weren't completed. Live nmap progress
(`Stats:` / `% done; ETC`) streams during long scans.
