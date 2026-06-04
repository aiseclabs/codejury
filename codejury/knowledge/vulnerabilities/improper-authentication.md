---
id: improper-authentication
title: Improper Authentication
impact: HIGH
tags: [cwe-287, cwe-306, owasp-a07]
triggers: ["login", "authenticate", "password ==", "== token", "auth", "bypass", "if not user", "verify_password"]
---

## Improper Authentication

Authentication is missing on a protected path, can be bypassed by a logic flaw, or compares credentials unsafely, for example a hardcoded bypass token, a non-constant-time compare, or trusting a client-asserted identity. Verify identity server-side against a trusted store before granting access. Compare secrets in constant time.

### Python
Vulnerable:
```python
if request.headers.get("X-Auth") == "debug-bypass":   # hardcoded bypass
    return admin_dashboard()
if user.token == request.args["token"]:               # non-constant-time, and client-asserted
    login(user)
```
Secure:
```python
import hmac
if user and hmac.compare_digest(user.token, request.args["token"]):
    login(user)
```
