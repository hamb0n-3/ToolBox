## SSRF-01 — Server-Side Request Forgery (SSRF)

## OWASP
[API7 - Server Side Request Forgery]

## Finding Title
Server-Side Request Forgery via Geo or Address Parameters

## Finding Description
Submitting an internal IP address (e.g. the cloud metadata endpoint `169.254.169.254`) or a URL as a coordinate or address parameter caused the server to issue an outbound request to that address and return content from it in the response. The server is making backend HTTP requests based on user-supplied input without validating that the destination is an allowlisted external address.

## Risk Level
High

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
SSRF can be used to reach internal services not exposed to the internet (databases, admin panels, internal APIs), read cloud metadata credentials (AWS IMDSv1, GCP metadata), scan internal network topology, and pivot to further attacks within the hosting environment. On cloud infrastructure, metadata SSRF is commonly used to obtain IAM credentials for full cloud account compromise.

## Steps to Reproduce Finding
```bash
curl -s -G -H "apikey: $API_KEY" "$BASE_URL/nearby" \
  --data-urlencode "lat=169.254.169.254" \
  --data-urlencode "lng=0.0" \
  --data-urlencode "drive_time=10"

curl -s -G -H "apikey: $API_KEY" "$BASE_URL/nearby" \
  --data-urlencode "street_address=http://169.254.169.254/latest/meta-data/" \
  --data-urlencode "city=x" --data-urlencode "state=VA" --data-urlencode "zip=00000"
```
Observed: `[METADATA CONTENT / INTERNAL RESPONSE]` returned in the response body.
