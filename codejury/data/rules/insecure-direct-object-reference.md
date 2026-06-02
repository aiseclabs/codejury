---
id: insecure-direct-object-reference
title: Insecure Direct Object Reference
impact: HIGH
tags: [cwe-639, owasp-a01, access-control]
triggers: ["objects.get(", "findById", "get_object_or_404", "/<id>", "/:id", "request.args", "params[", "pk=", "where id ="]
---

## Insecure Direct Object Reference

A record is fetched or mutated by a user-supplied id without checking the caller owns or may access it, so an authenticated user reaches another user's, tenant's, or service's data by changing the id. Scope every object lookup to the caller's identity or tenant.

### Python (Django)
Vulnerable:
```python
account = Account.objects.get(id=request.GET["account_id"])
```
Secure:
```python
account = get_object_or_404(Account, id=request.GET["account_id"], owner=request.user)
```

### Node.js (Express)
Vulnerable: `const doc = await Document.findById(req.params.id)`
Secure: `const doc = await Document.findOne({ _id: req.params.id, userId: req.user.id })`
