# beanshooter-batch

A Python wrapper around the [beanshooter](https://github.com/qtc-de/beanshooter)
JMX testing tool (`ghcr.io/qtc-de/beanshooter/beanshooter:4.1.0`) for batch
testing multiple JMX endpoints.

> **Use only against systems you own or have written permission to test.**

## What it does

For every `host:port` in your input file the wrapper runs up to three phases
inside the beanshooter Docker container:

1. **Enumeration (`enum`)** — always. Section-aware parser turns beanshooter's
   output into structured findings: anonymous access, pre-auth deserialization,
   JEP290 bypass, JMXMP without SASL, MBean count, RMI bound names.
2. **Credential brute-force (`brute`)** — only when `--brute` is set *and*
   authentication is required. **Off by default** because beanshooter's brute
   action can lock accounts on JDK 11+.
3. **MBean listing (`list`)** — only when access is obtained (anonymous, weak
   creds discovered, or user-supplied `--username`/`--password`). Flags
   dangerous beans present in the inventory: MLet, DiagnosticCommand,
   HotSpotDiagnostic, TonkaBean.

Outputs:

| File                | Purpose                              |
|---------------------|--------------------------------------|
| `jmx_findings.md`   | Human-readable Markdown report       |
| `jmx_findings.json` | Machine-readable raw results         |
| `jmx_batch.log`     | Full DEBUG log (with secret redaction) |

## Requirements

- Python 3.9+
- Docker available to the current user
- Network reachability to the target JMX endpoints

## Usage

```bash
# Default: anonymous + enumeration + RCE-vector detection
python beanshooter_batch.py -i hosts.txt -o report.md

# Add credential brute-force (account-lockout risk on JDK 11+)
python beanshooter_batch.py -i hosts.txt --brute

# Use known credentials to enable deeper enumeration on auth-required hosts
python beanshooter_batch.py -i hosts.txt --username admin --password 's3cret!'

# TLS-protected endpoints
python beanshooter_batch.py -i hosts.txt --ssl

# More concurrency, longer timeout, verbose console
python beanshooter_batch.py -i hosts.txt -t 8 --timeout 300 -v

# Targets only reachable from the host LAN (Linux only)
python beanshooter_batch.py -i hosts.txt --host-net

# Skip the docker pull (use locally cached image)
python beanshooter_batch.py -i hosts.txt --skip-pull

# Forward arbitrary extra args to every beanshooter invocation
python beanshooter_batch.py -i hosts.txt --extra --stack-trace --jmxmp
```

## Input format (`hosts.txt`)

```
10.0.0.10:9010
10.0.0.11:1099
jmx.internal.example.com:11099
# blank lines and # comments are ignored
# missing port defaults to 9010
192.168.50.5
```

## Findings severity

| Badge       | Used for                                                  |
|-------------|-----------------------------------------------------------|
| 🟥 Critical | Anonymous access, JMXMP no-SASL, pre-auth deserialization accepted, JEP290 bypass, weak creds, TonkaBean already deployed |
| 🟧 High     | MLet MBean deployed (RCE primitive)                       |
| 🟨 Medium   | Full MBean enumeration, DiagnosticCommand / HotSpotDiagnostic exposed |
| 🟦 Low      | (reserved)                                                |
| ⬜ Info     | (reserved)                                                |

## Tests

Parsers are covered by a `unittest` suite that asserts against captured
beanshooter output fixtures:

```bash
python -m unittest tests/test_parsers.py -v
```

The suite includes explicit regression tests for the four parsing bugs found
in the first iteration of this script:

- `test_anonymous_access_detected_on_real_output` — `does not require
  authentication` no longer slips past the parser.
- `test_preauth_deser_detected_on_real_output` — `accepted the payload class`
  + `Configuration Status: Non Default` now correctly fires the RCE finding.
- `test_negation_does_not_flip_*` — `does not require / not enabled` no longer
  trigger sign-flipped false positives.
- `test_quoted_values_accepted` — MBean ObjectNames containing `/` inside
  quoted values are no longer dropped from the inventory.

## Security / operational notes

- **Credentials.** `--password` values are redacted in the log and inside the
  raw-output blobs of the Markdown report. They are *not* redacted in the JSON
  file beyond what beanshooter itself prints (the password is never echoed by
  beanshooter, but be aware of the file's sensitivity).
- **Brute-forcing** can lock accounts. Only use `--brute` against systems
  where this is acceptable, and prefer to scope wordlists / accounts first.
- **No exploitation.** This wrapper only *detects* RCE vectors — it does not
  deploy payloads, deserialize gadgets, or run commands. To exploit, use
  beanshooter directly (`serial`, `mlet`, `tonka`).
- **Cold-start cost.** Each phase spawns a fresh docker container, so figure
  ~2 s of JVM cold-start per beanshooter invocation. For 100 hosts at 3 phases
  each, that's measurable but tolerable. Bump `-t` to parallelize.
- **Parser drift.** Beanshooter's exact output strings can change between
  releases. The full raw output of every phase is preserved in the JSON and
  in `<details>` blocks of the Markdown report so any finding can be verified
  by eye, and the fixture-based tests will fail noisily if parsing breaks
  against a new release.

## Files

```
beanshooter_batch/
├── beanshooter_batch.py        # main script
├── README.md                   # this file
├── hosts.example.txt           # sample input
└── tests/
    ├── test_parsers.py         # unittest suite
    └── fixtures/
        ├── enum_anonymous_vulnerable.txt
        ├── enum_authrequired_preauth_deser.txt
        ├── enum_authrequired_nonvuln.txt
        ├── enum_jmxmp_no_sasl.txt
        ├── brute_with_hits.txt
        └── list_mbeans.txt
```