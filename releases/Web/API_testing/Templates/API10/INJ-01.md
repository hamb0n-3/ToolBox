## INJ-01 — SQL Injection

## OWASP
[API10 - Unsafe Consumption of APIs]

## Finding Title
SQL Injection in Filter Parameter

## Finding Description
Submitting SQL metacharacters or injection payloads in the `state` filter parameter caused the server to return a response containing database error messages or behave differently from a baseline request. This indicates the parameter value is being interpolated into a SQL query without parameterisation.

## Risk Level
Critical

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
SQL injection can allow an attacker to extract the full contents of the underlying database, bypass authentication, modify or delete records, and in some configurations execute operating system commands. This represents one of the most severe vulnerability classes in web applications.

## Steps to Reproduce Finding
```bash
curl -s -G -H "apikey: $API_KEY" "$BASE_URL/facilities" \
  --data-urlencode "state='" | grep -iE "sql|syntax|pg::|ora-|mysql|odbc"

curl -s -G -H "apikey: $API_KEY" "$BASE_URL/facilities" \
  --data-urlencode "state=' OR '1'='1" -o /dev/null -w "%{http_code}\n"
```
Observed: `[DATABASE ERROR TEXT]` or `200` for a tautological payload — expected `400` with a generic validation error.

> **Note:** This test checks for error-based SQL injection only. A clean result does not rule out blind or time-based SQL injection.
