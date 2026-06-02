# Business Logic

Correctness of stateful workflows against abuse, covering ordering, races, replay, and value validation.

Bring this skill into scope when you see:
- multi-step flows such as checkout, transfer, or approval
- balance, amount, price, or quantity arithmetic
- shared-state updates without locking or transactions

## Dimensions to rule on

Output one verdict per dimension below (SECURE, VULNERABLE, PARTIAL, NOT_PRESENT, or UNKNOWN), even when the code is fine, so the report records what was checked. Use the dimension name as the verdict's `dimension`.

### state and sequence

Secure patterns (support a SECURE verdict):
- Enforce the workflow state machine server-side and make sensitive actions idempotent. Why it is safe: Steps cannot be skipped or applied twice regardless of client behavior. Look for: `idempotency_key`, `select_for_update`, `with lock`.

Insecure patterns (support a VULNERABLE verdict):
- [MEDIUM CWE-841] Do not enforce step ordering, so a later step can be invoked without the earlier ones. Why it is a problem: An attacker reaches checkout or fulfillment without payment or validation.
- [HIGH CWE-362] Check-then-act on shared state without a lock or atomic update. Why it is a problem: Concurrent requests both pass the check, enabling double spend. Look for: `if balance >=`, `balance -=`, `.get(...)
    ...save()`.

  Example of the bug:

  ```python
  if account.balance >= amount:
      account.balance -= amount
  ```

  Fixed:

  ```python
  with transaction.atomic():
      acct = Account.objects.select_for_update().get(pk=id)
      if acct.balance >= amount: acct.balance -= amount
  ```

### limits and replay

Secure patterns (support a SECURE verdict):
- Validate amounts, quantities, and ranges server-side and rate-limit sensitive actions. Why it is safe: Client-supplied values cannot drive the outcome.

Insecure patterns (support a VULNERABLE verdict):
- [MEDIUM CWE-840] Trust a client-supplied price, amount, or quantity without server validation. Why it is a problem: A user sets a negative or tiny amount and underpays. Look for: `request.json["price"]`, `total = request`, `quantity = request`.
- [MEDIUM CWE-799] No rate limiting or replay protection on sensitive actions. Why it is a problem: Requests can be replayed or brute-forced without restriction.

## Judgement notes

- Cite an evidence file and line for every VULNERABLE or PARTIAL verdict; a problem with no location is not reportable.
