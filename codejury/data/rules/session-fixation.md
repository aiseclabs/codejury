---
id: session-fixation
title: Insecure Session Management
impact: MEDIUM
tags: [cwe-384, cwe-613, cwe-614, owasp-a07]
triggers: ["session", "set_cookie", "httponly", "secure=", "samesite", "session_id", "login", "logout"]
---

## Insecure Session Management

The session id is not rotated at login, also called fixation, the session cookie lacks HttpOnly/Secure/SameSite, or sessions never expire. Regenerate the session id on authentication, set HttpOnly + Secure + SameSite on the session cookie, and enforce idle and absolute timeouts.

### Python, Flask
Vulnerable:
```python
resp.set_cookie("sid", token)        # no HttpOnly/Secure/SameSite
# (and session id reused across login)
```
Secure:
```python
session.regenerate()                 # rotate at login
resp.set_cookie("sid", token, httponly=True, secure=True, samesite="Lax")
```
