# VirusTotal Report — lootextract

**Verdict:** **UNKNOWN** (risk score 0.0/100)

## Summary
- **Generated:** 2025-10-09T17:37:06Z
- **File size:** 3.4 MB
- **Type:** ELF (elf)
- **Magic:** ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), BuildID[sha1]=86132447bd10d45196a2038b6ed6aa9ac3f1e37f, for GNU/Linux 3.2.0, statically linked, no section header
- **Reputation:** 0
- **AV engines evaluated:** 76
- **Community votes:** harmless 0, malicious 0

## Hashes
- SHA-256: `0f6b9b73ba169cc4187e77adc0078ed358bd3afb75fa1293d66c0ab17b8b3a03`
- SHA-1: `fbdaee2da5019b307002f911f5e705c85908fa8c`
- MD5: `ac58b8c94ceb4fbb4aeb2ae78ec7a78a`
- TLSH: `T17BF533163D106022AE970639E6385776CF0C352DED3BBCA7E798540168C677DB2A0DFA`
- VHASH: `0fec2f15a58d332f651106aa3ddf26c2`
- Authentihash: `—`

## Timestamps
- First seen: 2025-10-09T17:18:27Z
- Last analysis: 2025-10-09T17:18:27Z
- Last modified: 2025-10-09T17:25:57Z

## TRiD (top 5)
- ELF Executable and Linkable format (Linux) — 50.10%
- ELF Executable and Linkable format (generic) — 49.80%

## Known Filenames
- lootextract

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
- /bin/sh sh -c /usr/lib/rsyslog/rsyslog-rotate logrotate_script /var/log/syslog
- /tmp/lootextract

### Highlighted text
- 
- /tmp/lootextract: /lib/x86_64-linux-gnu/libm.so.6: version `GLIBC_2.38' not found (required by /tmp/lootextract)
- /tmp/lootextract: /lib/x86_64-linux-gnu/libm.so.6: version `GLIBC_2.35' not found (required by /tmp/lootextract)
- /tmp/lootextract: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.38' not found (required by /tmp/lootextract)
- /tmp/lootextract: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.33' not found (required by /tmp/lootextract)
- /tmp/lootextract: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.32' not found (required by /tmp/lootextract)
- /tmp/lootextract: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by /tmp/lootextract)

### Memory pattern domains
- upx.sf.net

### Memory pattern URLs
- http://upx.sf.net

### MITRE ATT&CK techniques
- T1027.002 (severity=IMPACT_SEVERITY_INFO)
- T1497.001 (severity=IMPACT_SEVERITY_INFO)
- T1064 (severity=IMPACT_SEVERITY_INFO)
- T1543.002 (severity=IMPACT_SEVERITY_INFO)
- T1027 (severity=IMPACT_SEVERITY_LOW)
- T1027 (severity=IMPACT_SEVERITY_INFO)

### Signature matches
- packed with UPX (id=2; description=anti-analysis/packer/upx)
- reference anti-VM strings targeting Xen (id=3; description=anti-analysis/anti-vm/vm-detection)
- 4012 (severity=IMPACT_SEVERITY_INFO; description=Sample contains only a LOAD segment without any section mappings)
- 2075 (severity=IMPACT_SEVERITY_INFO; description=Executes commands using a shell command-line interpreter)
- 4032 (severity=IMPACT_SEVERITY_INFO; description=Executes the "systemctl" command used for controlling the systemd system and service manager)
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
          "value": "2"
        }
      ]
    }
  ],
  "T1497.001": [
    {
      "severity": "INFO",
      "description": "reference anti-VM strings targeting Xen",
      "refs": [
        {
          "ref": "#signature_matches",
          "value": "3"
        }
      ]
    }
  ],
  "T1064": [
    {
      "severity": "INFO",
      "description": "Executes commands using a shell command-line interpreter",
      "refs": [
        {
          "ref": "#signature_matches",
          "value": "2075"
        }
      ]
    }
  ],
  "T1543.002": [
    {
      "severity": "INFO",
      "description": "Executes the \"systemctl\" command used for controlling the systemd system and service manager",
      "refs": [
        {
          "ref": "#signature_matches",
          "value": "4032"
        }
      ]
    }
  ],
  "T1027": [
    {
      "severity": "LOW",
      "description": "Sample is packed with UPX",
      "refs": [
        {
          "ref": "#signature_matches",
          "value": "2163"
        }
      ]
    },
    {
      "severity": "INFO",
      "description": "ELF contains segments with high entropy indicating compressed/encrypted content",
      "refs": [
        {
          "ref": "#signature_matches",
          "value": "4092"
        }
      ]
    }
  ]
}
```

### Command executions
- sh -c /usr/lib/rsyslog/rsyslog-rotate logrotate_script /var/log/syslog
- /usr/lib/rsyslog/rsyslog-rotate
- systemctl kill -s HUP rsyslog.service

### Files opened
- /lib/systemd/tls/avx512_1/libc.so.6
- /lib/systemd/tls/avx512_1/x86_64/libc.so.6
- /lib/systemd/tls/haswell/avx512_1/libc.so.6
- /lib/systemd/tls/haswell/avx512_1/x86_64/libc.so.6
- /lib/systemd/tls/haswell/libc.so.6
- /lib/systemd/tls/haswell/x86_64/libc.so.6
- /lib64/ld-linux-x86-64.so.2
- /proc/1/environ
- /proc/1/sched
- /proc/4952/stat
- /proc/cmdline
- /proc/filesystems
- … (+25 more)

### Mbc
- F0001.008
- B0009

### Memory dumps
- /tmp/lootextract
- /tmp/lootextract
- /tmp/lootextract
- /tmp/lootextract
- /tmp/lootextract
- /tmp/lootextract
- /tmp/lootextract

### Processes created
- /bin/sh sh -c /usr/lib/rsyslog/rsyslog-rotate logrotate_script /var/log/syslog
- /usr/lib/rsyslog/rsyslog-rotate
- /usr/bin/systemctl systemctl kill -s HUP rsyslog.service
- /tmp/lootextract


## Per-sandbox Behaviour
| Sandbox | Verdict | Confidence | Highlighted calls | Files written | Registry keys | Mutexes |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| CAPA | — | — | 0 | 0 | 0 | 0 |
| Zenbox Linux | — | — | 0 | 0 | 0 | 0 |

## MITRE ATT&CK Mapping
| Sandbox | Tactic | Technique | Technique ID | Severities observed |
| --- | --- | --- | --- | --- |
| CAPA | Defense Evasion (TA0005) | Obfuscated Files or Information | T1027 | — |
| CAPA | Defense Evasion (TA0005) | Software Packing | T1027.002 | INFO |
| CAPA | Defense Evasion (TA0005) | Virtualization/Sandbox Evasion | T1497 | — |
| CAPA | Defense Evasion (TA0005) | System Checks | T1497.001 | INFO |
| CAPA | Discovery (TA0007) | Virtualization/Sandbox Evasion | T1497 | — |
| CAPA | Discovery (TA0007) | System Checks | T1497.001 | INFO |
| Zenbox Linux | Execution (TA0002) | Scripting | T1064 | INFO |
| Zenbox Linux | Defense Evasion (TA0005) | Scripting | T1064 | INFO |
| Zenbox Linux | Defense Evasion (TA0005) | Obfuscated Files or Information | T1027 | INFO, LOW |
| Zenbox Linux | Persistence (TA0003) | Create or Modify System Process | T1543 | — |
| Zenbox Linux | Persistence (TA0003) | Systemd Service | T1543.002 | INFO |
| Zenbox Linux | Privilege Escalation (TA0004) | Create or Modify System Process | T1543 | — |
| Zenbox Linux | Privilege Escalation (TA0004) | Systemd Service | T1543.002 | INFO |

## Network Indicators
_Report generated via VirusTotal v3 API. Treat detections as one signal—false positives are possible._