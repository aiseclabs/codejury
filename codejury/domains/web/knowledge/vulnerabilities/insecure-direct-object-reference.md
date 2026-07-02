---
id: insecure-direct-object-reference
title: Insecure Direct Object Reference
lens: authorization
impact: HIGH
tags: [cwe-639, owasp-a01, access-control]
triggers: ["objects.get(", "findById", "get_object_or_404", "/<id>", "/:id", "request.args", "params[", "pk=", "where id ="]
---

## Insecure Direct Object Reference

A record is fetched or mutated by a user-supplied id without checking the caller owns or may access it, so an authenticated user reaches another user's, tenant's, or service's data by changing the id. Scope every object lookup to the caller's identity or tenant.

### Python, Django
Vulnerable:
```python
account = Account.objects.get(id=request.GET["account_id"])
```
Secure:
```python
account = get_object_or_404(Account, id=request.GET["account_id"], owner=request.user)
```

### Node.js, Express
Vulnerable: `const doc = await Document.findById(req.params.id)`
Secure: `const doc = await Document.findOne({ _id: req.params.id, userId: req.user.id })`

### Judge the Effective Scope, Not the Line Shape

A lookup that reads as fetch-by-id may already be scoped to the caller, and one that reads as scoped may not be, so judge the query the code actually runs, not how the line looks. Ownership often comes from the object the query is built on, not a visible `where owner = ?`: an association chain scopes to the caller such as Rails `current_user.posts.find(id)` or Laravel `$user->posts()->find($id)`, a manager or queryset may already be filtered by tenant such as Django `request.user.accounts.get(pk=id)`. Report an IDOR only when the effective query is not scoped to the caller on the reachable path. A bare fetch-by-id with no scoping and no separate authorization check is the real defect.
