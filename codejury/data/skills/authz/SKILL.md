# Authorization

Deciding whether an authenticated caller is allowed to perform an action on a resource.

Bring this skill into scope when you see:
- routes with an :id or <pk> path parameter
- admin or privileged endpoints
- role, permission, or is_admin checks

## Dimensions to rule on

Output one verdict per dimension below (SECURE, VULNERABLE, PARTIAL, NOT_PRESENT, or UNKNOWN), even when the code is fine, so the report records what was checked. Use the dimension name as the verdict's `dimension`.

### object level

Secure patterns (support a SECURE verdict):
- Confirm the authenticated user owns or may access the object before acting on it. Why it is safe: Ties every object access to the caller's identity, closing direct-object-reference holes. Look for: `filter(owner=request.user`, `get_object_or_404(..., user=`, `current_user.id ==`.

Insecure patterns (support a VULNERABLE verdict):
- [HIGH CWE-639] Fetch or mutate a record by a user-supplied id with no ownership or access check. Why it is a problem: Any user can read or change another user's data by changing the id (IDOR) Look for: `get(id=request`, `objects.get(pk=`, `WHERE id =`.

  Example of the bug:

  ```python
  account = Account.objects.get(id=request.GET["account_id"])
  ```

  Fixed:

  ```python
  account = Account.objects.get(id=request.GET["account_id"], owner=request.user)
  ```
- [HIGH CWE-862] Missing function or endpoint level authorization, so any authenticated user reaches privileged actions. Why it is a problem: Authentication is checked but authorization is not; non-admins can hit admin routes.

### privilege

Secure patterns (support a SECURE verdict):
- Derive roles and permissions server-side from a trusted store, checked per request. Why it is safe: The client cannot grant itself privileges it was not assigned.

Insecure patterns (support a VULNERABLE verdict):
- [HIGH CWE-269] Derive role or permission from a client-controlled field (request body, query param, client-set claim) Why it is a problem: An attacker sets the field and escalates to admin. Look for: `request.json["role"]`, `is_admin = request`, `request.POST.get("role"`.
- [MEDIUM CWE-602] Enforce authorization only in the client or UI, not on the server. Why it is a problem: The server is the only trust boundary; hidden buttons stop nothing.

## Judgement notes

- Cite an evidence file and line for every VULNERABLE or PARTIAL verdict; a problem with no location is not reportable.
