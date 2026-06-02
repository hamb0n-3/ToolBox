## INJ-CMD — OS Command Injection

## OWASP
[API10 - Unsafe Consumption of APIs]

## Finding Title
Operating System Command Injection in Filter Parameter

## Finding Description
Submitting OS command injection payloads (e.g. `;id`, `$(id)`) in an API filter parameter caused the server to return output consistent with command execution (e.g. `uid=`, `gid=`). This indicates the parameter value is being passed to a system shell or process execution function without sanitisation.

## Risk Level
Critical

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
Remote code execution on the hosting infrastructure. An attacker can execute arbitrary commands as the application service account, exfiltrate environment variables and secrets, establish persistence, pivot to internal network resources, or cause a full system compromise.

## Steps to Reproduce Finding
```bash
for p in ";id" "|id" '$(id)' '`id`' "&& whoami"; do
  result=$(curl -s -G -H "apikey: $API_KEY" "$BASE_URL/facilities" \
    --data-urlencode "state=$p")
  echo "$result" | grep -iE "uid=|gid=|root:" && echo "!! Possible RCE: $p"
done
```
Observed: response body contained `[COMMAND OUTPUT]` for payload `[PAYLOAD]`.
