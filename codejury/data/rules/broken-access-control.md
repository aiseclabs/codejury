---
title: Broken Access Control (Function-Level Authorization)
impact: HIGH
tags: [access-control, authorization, cwe-862, cwe-285, owasp-a01]
triggers: ["@app.route", "@router", "def ", "is_admin", "role", "permission", "@login_required", "requires_", "admin"]
---

## Broken Access Control

A privileged or state-changing endpoint is reachable without the authorization check its peers enforce, or the role/permission is derived from a client-controlled value. Enforce authorization server-side per request, from a trusted store; never trust a client-supplied role.

### Python
Vulnerable:
```python
@app.route("/admin/users/<uid>", methods=["DELETE"])
def delete_user(uid):            # no auth check, unlike sibling routes
    delete(uid)

is_admin = request.json["is_admin"]   # client-controlled privilege
```
Secure:
```python
@app.route("/admin/users/<uid>", methods=["DELETE"])
@requires_admin
def delete_user(uid):
    delete(uid)
```
