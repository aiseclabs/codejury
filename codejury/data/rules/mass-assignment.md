---
title: Mass Assignment
impact: HIGH
tags: [mass-assignment, overposting, cwe-915, owasp-a08]
triggers: ["(**request", "update(**", "setattr(", "Object.assign", ".save()", "create(**", "request.get_json"]
---

## Mass Assignment

Binding a whole request body into a model or update lets a client set internal fields it was never offered (is_admin, balance, role). Bind only an explicit allowlist of fields.

### Python
Vulnerable:
```python
user = User(**request.get_json())
```
Secure:
```python
body = request.get_json()
user = User(name=body["name"], email=body["email"])
```
