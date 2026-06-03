---
id: cross-site-request-forgery
title: Cross-Site Request Forgery
impact: HIGH
tags: [cwe-352, owasp-a01]
triggers: ["@app.route", "methods=[\"POST\"", "csrf", "SameSite", "csrf_exempt", "@csrf", "form"]
---

## Cross-Site Request Forgery

A state-changing request is accepted using only ambient credentials (a session cookie) with no anti-CSRF token or SameSite protection, so a malicious site can make the victim's browser perform the action. Require a CSRF token (or SameSite=strict/lax cookies + origin check) on every state-changing endpoint.

### Python
Vulnerable:
```python
@app.route("/account/email", methods=["POST"])
@csrf.exempt            # disables CSRF protection on a state-changing route
def change_email():
    current_user.email = request.form["email"]; db.commit()
```
Secure: keep CSRF protection on. Validate the token, or set the session cookie `SameSite="Lax"` and check the Origin header.
