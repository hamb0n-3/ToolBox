# nmap_scanner.py

An nmap wrapper with per-host logging, pause/resume, batched scanning, a
scheduled start/daily window, and a time limit.

> Only run this against hosts you are authorized to scan.

## Requirements

- `nmap` on your `PATH`
- Python 3
- `apscheduler` — only needed for `--window` (`pip install apscheduler`)

## How it works

By default each batch of hosts gets one full-port discovery scan (`-p-`), and
every host with open ports then gets a service/script scan (`-sV -sC`) on just
those ports. Use `--custom` to replace both stages with your own nmap command.

## Usage

```bash
./nmap_scanner.py 10.0.0.1 example.com            # targets on the CLI
./nmap_scanner.py 192.168.1.0/24                  # CIDR
./nmap_scanner.py 10.0.0.1-10.0.0.50              # full IP-IP range
./nmap_scanner.py -iL targets.txt                 # targets from a file
./nmap_scanner.py 10.0.0.0/24 --custom '-sU -p 53,161 -T4'   # custom scan instead
./nmap_scanner.py 10.0.0.0/24 --batch-size 32     # 32 hosts per nmap invocation
./nmap_scanner.py 10.0.0.0/24 -o /data/scans      # custom output directory
./nmap_scanner.py 10.0.0.0/24 --time 8h           # run 8h, then auto-pause
./nmap_scanner.py 10.0.0.0/24 --start 14:46       # wait until 14:46 to begin
./nmap_scanner.py 10.0.0.0/24 --window 17:00-07:00  # only scan 5pm-7am daily
./nmap_scanner.py --resume 12345                  # resume a paused scan by PID
```

## Options

| Flag | Purpose |
|------|---------|
| `-iL FILE` | Read targets from a file (one per line, `#` comments ok). |
| `-o, --output-dir DIR` | Where to write output (default `./NMAP_scans`). |
| `--batch-size N` | Hosts per nmap invocation (default 16). Applies to discovery and `--custom`; service scans stay per host. |
| `--custom 'ARGS'` | Skip discovery/service; run nmap with these args, batched. Include `-Pn` to keep down hosts in the batch. |
| `--time DUR` | Run for `30s`/`8m`/`8h`/`2d`, then auto-pause. |
| `--start HH:MM` | Wait until this wall-clock time before starting. |
| `--window HH:MM-HH:MM` | Only scan inside this daily window (may wrap midnight); requires apscheduler. |
| `--resume PID\|FILE` | Resume a paused scan by its original PID or state-file path. |

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

Press `Ctrl-C` for a menu: kill, pause (save state), or continue. A paused scan
writes `nmap_wrapper_state_<PID>.json` (+ a `.done` log) in the launch
directory. Resume from that **same directory** with `--resume <PID>`. Progress
is checkpointed after every host, so resume only redoes unfinished hosts.
