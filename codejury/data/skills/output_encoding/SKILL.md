# Output Encoding

The outbound trust boundary. Untrusted data must be encoded for the context it is rendered into.

Bring this skill into scope when you see:
- HTML sinks like innerHTML, dangerouslySetInnerHTML, |safe, mark_safe, v-html
- templates rendering request data
- response headers or redirect targets built from input

## Dimensions to rule on

Output one verdict per dimension below (SECURE, VULNERABLE, PARTIAL, NOT_PRESENT, or UNKNOWN), even when the code is fine, so the report records what was checked. Use the dimension name as the verdict's `dimension`.

### xss

Secure patterns (support a SECURE verdict):
- Rely on contextual output encoding or framework auto-escaping; render untrusted data as text, not markup. Why it is safe: Data is encoded for its context, so it cannot become executable markup. Look for: `escape(`, `textContent`, `render_template`.

Insecure patterns (support a VULNERABLE verdict):
- [HIGH CWE-79] Render untrusted input into HTML through a raw sink. Why it is a problem: Attacker-supplied markup runs as script in the victim's browser. Look for: `innerHTML`, `dangerouslySetInnerHTML`, `|safe`, `mark_safe(`, `v-html`.

  Example of the bug:

  ```python
  el.innerHTML = "Hello " + username
  ```

  Fixed:

  ```python
  el.textContent = "Hello " + username
  ```
- [HIGH CWE-79] Build HTML by string concatenation of untrusted input. Why it is a problem: Same XSS sink, just assembled by hand.
- [MEDIUM CWE-116] Disable template auto-escaping globally. Why it is a problem: Every template output becomes a potential injection point. Look for: `autoescape=False`, `| safe`.

### header and log

Insecure patterns (support a VULNERABLE verdict):
- [MEDIUM CWE-113] Place untrusted input into a response header or redirect location without sanitizing newlines. Why it is a problem: CR/LF in the value splits the response or injects headers.
- [LOW CWE-117] Write untrusted input to logs without neutralizing newlines or control characters. Why it is a problem: Forged log lines mislead investigators and can poison log processors.

## Judgement notes

- Cite an evidence file and line for every VULNERABLE or PARTIAL verdict; a problem with no location is not reportable.
- Untrusted input must be able to reach the sink for this to be VULNERABLE. A constant, a stored data field, a value from trusted config, or a path or argument the operator supplies (for example a CLI argument) is not attacker-controlled; do not flag it.
