---
id: information-exposure
title: Information Exposure
impact: MEDIUM
tags: [cwe-200, cwe-532, cwe-209, owasp-a02]
triggers: ["traceback.format_exc", "str(e)", "log.info(token", "logger.debug(secret", "print(password", "DEBUG = True", "jsonify(error="]
---

## Information Exposure

Sensitive data (secrets, tokens, PII) written to logs, or internal detail (stack traces, exception messages, debug output) returned to the client, helps an attacker and widens breach impact. Log only non-secret data, return a generic error to the caller, and keep detail server-side.

### Python
Vulnerable:
```python
logger.info("auth token: %s", token)
return jsonify(error=traceback.format_exc()), 500
```
Secure:
```python
logger.info("auth attempt for user %s", user_id)
app.logger.exception("auth failed"); return jsonify(error="internal error"), 500
```

### Not a finding (do not flag)

This is about leaking secrets/PII or internal detail. It is not a finding to:
- read or serve a file, make a request, or return ordinary application data,
- log non-sensitive identifiers (a user id, a request path, a status).

Reaching a file or returning a record is only information exposure when the data
returned is itself sensitive (a secret, another user's PII) or internal (a stack
trace, a query). A plain `open(...)` or response is not this weakness.

