# VirusTotal Report — github-scraper

**Verdict:** **UNKNOWN** (risk score 0.0/100)

## Summary
- **Generated:** 2025-10-09T17:59:13Z
- **File size:** 6.7 MB
- **Type:** ELF (elf)
- **Magic:** ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), BuildID[sha1]=63aad61591e8504764fb74812d20351dc9bdcae4, for GNU/Linux 3.2.0, statically linked, no section header
- **Reputation:** 0
- **AV engines evaluated:** 76
- **Community votes:** harmless 0, malicious 0

## Hashes
- SHA-256: `dcd949aa33c9021cda213690598d88e1302a7e5147516c84950362060b5d3917`
- SHA-1: `b9bb1ecafba06005bdd6b15dad2d0342a37a96fc`
- MD5: `5b167d60661c87f3b701071d8fb8a8a8`
- TLSH: `T1E96633A5179B895758043F8BB4FA20B00E512A71A2CA3B863563C7F275B471F063DDEB`
- VHASH: `0fec2f15a58d332f651106aa3ddf26c2`
- Authentihash: `—`

## Timestamps
- First seen: 2025-10-03T19:42:56Z
- Last analysis: 2025-10-03T19:42:56Z
- Last modified: 2025-10-03T21:43:40Z

## TRiD (top 5)
- ELF Executable and Linkable format (Linux) — 50.10%
- ELF Executable and Linkable format (generic) — 49.80%

## Known Filenames
- github-scraper
- cqrcl0wfz.exe

**Tags:** 64bits, elf, shared-lib, upx

## Engine Statistics
- malicious: 0
- suspicious: 0
- harmless: 0
- undetected: 65
- timeout: 0
- type-unsupported: 11
- failure: 0
- confirmed-timeout: 0

## Sandbox Verdicts
| Category | Count |
| --- | ---: |
| malicious | 0 |
| suspicious | 0 |
| harmless | 0 |
| undetected | 0 |

## Threat Intelligence

## Behaviour Summary (aggregated)
### Processes tree
- xterm -hold -e sh -c /tmp/github-scraper
- /tmp/github-scraper

### Files written
- /dev/tty
- /dev/ptmx
- /dev/pts/0

### Highlighted text
- 
- /tmp/github-scraper: /lib/x86_64-linux-gnu/libm.so.6: version `GLIBC_2.38' not found (required by /tmp/github-scraper)
- /tmp/github-scraper: /lib/x86_64-linux-gnu/libm.so.6: version `GLIBC_2.35' not found (required by /tmp/github-scraper)
- /tmp/github-scraper: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.38' not found (required by /tmp/github-scraper)
- /tmp/github-scraper: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.33' not found (required by /tmp/github-scraper)
- /tmp/github-scraper: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.32' not found (required by /tmp/github-scraper)
- /tmp/github-scraper: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by /tmp/github-scraper)

### Memory pattern domains
- upx.sf.net

### Memory pattern URLs
- http://upx.sf.net

### MITRE ATT&CK techniques
- T1027.002 (severity=IMPACT_SEVERITY_INFO)
- T1070 (severity=IMPACT_SEVERITY_MEDIUM)
- T1070.004 (severity=IMPACT_SEVERITY_MEDIUM)
- T1027 (severity=IMPACT_SEVERITY_INFO)
- T1027 (severity=IMPACT_SEVERITY_LOW)

### Signature matches
- reference analysis tools strings (id=0; description=anti-analysis)
- packed with UPX (id=1; description=anti-analysis/packer/upx)
- drops_files (severity=IMPACT_SEVERITY_LOW; description=Drops files onto disk)
- deletes_files (severity=IMPACT_SEVERITY_MEDIUM; description=Deletes files from disk)
- 4012 (severity=IMPACT_SEVERITY_INFO; description=Sample contains only a LOAD segment without any section mappings)
- 2163 (severity=IMPACT_SEVERITY_LOW; description=Sample is packed with UPX)
- 715 (severity=IMPACT_SEVERITY_INFO; description=Classification label)
- 5000 (severity=IMPACT_SEVERITY_INFO; description=Non-zero exit code suggests an error during the execution. Lookup the error code for hints.)
- 238 (severity=IMPACT_SEVERITY_INFO; description=URLs found in memory or binary data)
- 4092 (severity=IMPACT_SEVERITY_INFO; description=ELF contains segments with high entropy indicating compressed/encrypted content)

### Attack techniques
```json
{
  "T1027.002": [
    {
      "severity": "INFO",
      "description": "packed with UPX",
      "refs": [
        {
          "ref": "#signature_matches",
          "value": "1"
        }
      ]
    }
  ],
  "T1070": [
    {
      "severity": "MEDIUM",
      "description": "Deletes files from disk",
      "refs": [
        {
          "ref": "#signature_matches",
          "value": "deletes_files"
        }
      ]
    }
  ],
  "T1070.004": [
    {
      "severity": "MEDIUM",
      "description": "Deletes files from disk",
      "refs": [
        {
          "ref": "#signature_matches",
          "value": "deletes_files"
        }
      ]
    }
  ],
  "T1027": [
    {
      "severity": "INFO",
      "description": "ELF contains segments with high entropy indicating compressed/encrypted content",
      "refs": [
        {
          "ref": "#signature_matches",
          "value": "4092"
        }
      ]
    },
    {
      "severity": "LOW",
      "description": "Sample is packed with UPX",
      "refs": [
        {
          "ref": "#signature_matches",
          "value": "2163"
        }
      ]
    }
  ]
}
```

### Dns lookups
- {"hostname": "api.snapcraft.io", "resolved_ips": ["185.125.188.57", "185.125.188.54", "185.125.188.58", "185.125.188.59"]}

### Files opened
- /root/.Xdefaults-laptop
- /etc/X11/app-defaults/XTerm
- /dev/tty
- /dev/ptmx
- /usr/share/fonts
- /usr/local/share/fonts/.uuid
- /usr/local/share/fonts
- /root/.local/share/fonts/.uuid
- /root/.fonts/.uuid
- /root/.XCompose
- /lib/terminfo/x/xterm
- /dev/pts/0
- … (+28 more)

### Ids alerts
- {"rule_msg": "(tcp) experimental TCP options found", "rule_category": "protocol-command-decode", "rule_id": "116:58", "alert_severity": "low"}

### Ip traffic
- {"destination_ip": "185.125.188.59", "destination_port": 443, "transport_layer_protocol": "TCP"}
- {"destination_ip": "185.125.188.54", "destination_port": 443, "transport_layer_protocol": "TCP"}

### Ja3 digests
- 473cd7cb9faa642487833865d516e578

### Mbc
- B0013.001
- F0001.008
- OC0006
- C0002
- OB0006
- F0007
- OC0001
- C0047

### Memory dumps
- /tmp/github-scraper
- /tmp/github-scraper
- /tmp/github-scraper
- /tmp/github-scraper
- /tmp/github-scraper
- /tmp/github-scraper
- /tmp/github-scraper

### Processes created
- xterm -hold -e sh -c /tmp/github-scraper
- sh -c /tmp/github-scraper
- /tmp/github-scraper

### Tags
- SELF_DELETE


## Per-sandbox Behaviour
| Sandbox | Verdict | Confidence | Highlighted calls | Files written | Registry keys | Mutexes |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| CAPA | — | — | 0 | 0 | 0 | 0 |
| CAPE Linux | — | — | 0 | 3 | 0 | 0 |
| Zenbox Linux | — | — | 0 | 0 | 0 | 0 |

## MITRE ATT&CK Mapping
| Sandbox | Tactic | Technique | Technique ID | Severities observed |
| --- | --- | --- | --- | --- |
| CAPA | Defense Evasion (TA0005) | Obfuscated Files or Information | T1027 | — |
| CAPA | Defense Evasion (TA0005) | Software Packing | T1027.002 | INFO |
| CAPE Linux | Defense Evasion (TA0005) | Indicator Removal | T1070 | MEDIUM |
| CAPE Linux | Defense Evasion (TA0005) | File Deletion | T1070.004 | MEDIUM |
| Zenbox Linux | Defense Evasion (TA0005) | Obfuscated Files or Information | T1027 | INFO, LOW |

## Network Indicators
### Contacted Domains
| Indicator | Malicious | Suspicious | Harmless | Undetected | Total |
| --- | ---: | ---: | ---: | ---: | ---: |
| `api.snapcraft.io` | 0 | 0 | 62 | 33 | 95 |

### Contacted IPs
| Indicator | Malicious | Suspicious | Harmless | Undetected | Total |
| --- | ---: | ---: | ---: | ---: | ---: |
| `185.125.188.57` | 1 | 0 | 61 | 33 | 95 |
| `185.125.188.54` | 0 | 0 | 62 | 33 | 95 |
| `185.125.188.59` | 0 | 0 | 62 | 33 | 95 |
| `185.125.188.58` | 0 | 0 | 63 | 32 | 95 |

_Report generated via VirusTotal v3 API. Treat detections as one signal—false positives are possible._