# Data Protection

Protecting sensitive data in transit, at rest, and in use, including PII handling.

Bring this skill into scope when you see:
- outbound requests or URLs carrying user data
- models or tables with PII, token, or financial fields
- TLS or certificate verification configuration

## Dimensions to rule on

Output one verdict per dimension below (SECURE, VULNERABLE, PARTIAL, NOT_PRESENT, or UNKNOWN), even when the code is fine, so the report records what was checked. Use the dimension name as the verdict's `dimension`.

### in transit

Secure patterns (support a SECURE verdict):
- Send sensitive data only over TLS and verify the peer certificate. Why it is safe: Confidentiality and integrity on the wire, with a checked endpoint identity. Look for: `https://`, `verify=True`, `ssl.create_default_context`.

Insecure patterns (support a VULNERABLE verdict):
- [HIGH CWE-319] Transmit sensitive data over plaintext HTTP. Why it is a problem: Anyone on the path can read or alter the data. Look for: `http://`.
- [HIGH CWE-295] Disable TLS certificate verification. Why it is a problem: Removes protection against man-in-the-middle interception. Look for: `verify=False`, `ssl._create_unverified_context`, `CERT_NONE`.

  Example of the bug:

  ```python
  requests.get(url, verify=False)
  ```

  Fixed:

  ```python
  requests.get(url)  # verification on by default
  ```

### at rest

Secure patterns (support a SECURE verdict):
- Encrypt sensitive fields and backups at rest. Why it is safe: A storage or backup leak does not expose plaintext.

Insecure patterns (support a VULNERABLE verdict):
- [MEDIUM CWE-311] Store sensitive data (PII, tokens, financial) unencrypted. Why it is a problem: Any database or disk access reveals it directly.

### pii

Insecure patterns (support a VULNERABLE verdict):
- [MEDIUM CWE-359] Expose PII in URLs, responses, or logs beyond what the operation needs. Why it is a problem: PII spreads into caches, history, and logs, widening breach impact.

## Judgement notes

- Cite an evidence file and line for every VULNERABLE or PARTIAL verdict; a problem with no location is not reportable.
