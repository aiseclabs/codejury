---
id: race-condition
title: Race Condition / TOCTOU
impact: HIGH
tags: [cwe-362, cwe-367, owasp-a04]
triggers: ["if balance", "balance -=", "select_for_update", "get(...).save", "check", "transaction", "lock", "atomic"]
---

## Race Condition / TOCTOU

A check and the action it guards run on shared state without a lock or atomic update, so two concurrent requests both pass the check, enabling double-spend, double-redeem, or a limit bypass. Use a row lock, an atomic conditional update, or a transaction.

### Python, Django
Vulnerable:
```python
acct = Account.objects.get(pk=pk)
if acct.balance >= amount:
    acct.balance -= amount   # concurrent requests both pass
    acct.save()
```
Secure:
```python
with transaction.atomic():
    acct = Account.objects.select_for_update().get(pk=pk)
    if acct.balance >= amount:
        acct.balance -= amount
        acct.save()
```
