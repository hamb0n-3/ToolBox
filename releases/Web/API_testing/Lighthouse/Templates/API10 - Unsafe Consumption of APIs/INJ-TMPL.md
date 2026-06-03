## INJ-TMPL — Server-Side Template Injection (SSTI)

## OWASP
[API10 - Unsafe Consumption of APIs]

## Finding Title
Server-Side Template Injection in Filter Parameter

## Finding Description
Submitting a template expression payload (e.g. `{{7*7}}`, `${7*7}`) in an API filter parameter caused the server to return the evaluated result (`49`) in its response. This confirms the input is being rendered through a server-side templating engine without sanitisation.

## Risk Level
Critical

## Tools Used
- `curl`
- VA Facilities Security Test Suite (`va_facilities_security_test.py`)

## Impact
SSTI is typically escalatable to remote code execution depending on the template engine in use (e.g. Jinja2, Twig, Freemarker). At minimum, sensitive server-side variables and configuration can be read. Full RCE allows the same impact as OS command injection.

## Steps to Reproduce Finding
```bash
for p in '${7*7}' '{{7*7}}' '#{7*7}' '<%= 7*7 %>'; do
  result=$(curl -s -G -H "apikey: $API_KEY" "$BASE_URL/facilities" \
    --data-urlencode "state=$p")
  echo "$result" | grep -q "49" && echo "!! Template evaluated: $p -> 49"
done
```
Observed: `49` in the response body for payload `[PAYLOAD]`, confirming arithmetic evaluation by a template engine.

## Remediation Steps
- Never pass user-supplied input to a template rendering function. Use static templates with data binding — pass user data as variables into the template context, not as part of the template string itself.
- Disable or sandbox the template engine in production if it is not required for the API response path.
- If a template engine is genuinely required, enable the sandbox/escape mode (e.g. Jinja2's `SandboxedEnvironment`) and treat any template expression evaluation as a critical finding requiring immediate investigation.
