---
title: Insecure Direct Object Reference (IDOR)
impact: HIGH
tags: [access-control, idor, authorization, cwe-639, owasp-a01]
triggers: ["objects.get(", "findById", "get_object_or_404", "/<id>", "/:id", "request.args", "params[", "pk=", "where id ="]
---

## Insecure Direct Object Reference (IDOR)

A resource is fetched or mutated by a user-supplied id without checking the caller owns or may access it. An authenticated user reads or changes another user's, tenant's, or service's data by changing the id. Always scope the lookup to the caller's identity / tenant.

### Python (Django)
Vulnerable:
```python
account = BankAccount.objects.get(id=request.GET["account_id"])
```
Secure:
```python
account = get_object_or_404(BankAccount, id=request.GET["account_id"], org_id=request.user.org_id)
```

### Node.js (Express)
Vulnerable: `const doc = await Document.findById(req.params.id)`
Secure: `const doc = await Document.findOne({ _id: req.params.id, userId: req.user.id })`
