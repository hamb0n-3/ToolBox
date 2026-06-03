## PROP-01 — Sensitive Property Exposure

## OWASP
[API3 - Broken Object Property Level Authorization]

## Finding Title
API Response Exposes Sensitive or Internal Object Properties

## Finding Description
The response body for a valid facility object contains fields that are not documented in the public API specification and appear sensitive or internal in nature. These may include fields such as `[OBSERVED FIELD NAMES]`. Returning internal data to API consumers violates the principle of least privilege at the data layer.

## Risk Level
High

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
Sensitive field exposure can reveal internal system architecture, personally identifiable information, authentication material, or business-sensitive data to any party with API access. This data can be used to facilitate further attacks or harvested at scale.

## Steps to Reproduce Finding
```bash
FID=$(curl -s -H "apikey: $API_KEY" "$BASE_URL/facilities?per_page=1" \
  | jq -r '.data[0].id')
curl -s -H "apikey: $API_KEY" "$BASE_URL/facilities/$FID" \
  | jq 'paths(scalars) | join(".")'
```
Observed: response contains `[FIELD NAME]` which is not documented in the public API schema.
