## INJ-NOSQL — NoSQL Injection

## OWASP
[API10 - Unsafe Consumption of APIs]

## Finding Title
NoSQL Injection in Filter Parameter

## Finding Description
Submitting NoSQL operator payloads (e.g. `{"$gt":""}`, `{"$ne":null}`) in an API filter parameter produced a different response than a benign value — either returning a `200` when `401`/`404` was expected, or returning a `5xx` indicating the operator was partially interpreted. This suggests the input is being parsed as a query object rather than a scalar string.

## Risk Level
High

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
Depending on the NoSQL database in use, injected operators can bypass authentication, return all documents in a collection, or manipulate query logic to expose records the caller should not be able to access.

## Steps to Reproduce Finding
```bash
for p in '{"$gt":""}' '{"$ne":null}' '[$ne]=1'; do
  printf "[%s] " "$p"
  curl -s -G -H "apikey: $API_KEY" "$BASE_URL/facilities" \
    --data-urlencode "state=$p" -o /dev/null -w "%{http_code}\n"
done
```
Observed: `[UNEXPECTED STATUS OR BEHAVIOUR]` for payload `[PAYLOAD]` — expected `400` or normal baseline response with no operator evaluation.

## Remediation Steps
- Validate and type-assert all query parameters before passing them to the database layer. A `state` filter should be a plain string, never an object; reject non-string types with `400`.
- Use the database driver's safe query construction methods (e.g. MongoDB query builders with typed filter objects) rather than deserialising user input directly into a query document.
- Reject input containing NoSQL operator keys (`$`, `{`, `}`) at the input-validation layer.
