# Session Management

Establishing, protecting, and ending the context that links requests to an authenticated user.

Bring this skill into scope when you see:
- set_cookie or Set-Cookie on a session token
- login, logout, or session creation handlers
- a session store or framework session configuration

## Dimensions to rule on

Output one verdict per dimension below (SECURE, VULNERABLE, PARTIAL, NOT_PRESENT, or UNKNOWN), even when the code is fine, so the report records what was checked. Use the dimension name as the verdict's `dimension`.

### cookie attributes

Secure patterns (support a SECURE verdict):
- Set HttpOnly, Secure, and an explicit SameSite on session cookies. Why it is safe: Blocks script access, plaintext transmission, and most cross-site sending. Look for: `httponly=True`, `secure=True`, `samesite=`.

Insecure patterns (support a VULNERABLE verdict):
- [MEDIUM CWE-1004] Session cookie set without HttpOnly. Why it is a problem: JavaScript can read the cookie, so an XSS turns into session theft. Look for: `set_cookie(`.

  Example of the bug:

  ```python
  resp.set_cookie("sid", token)
  ```

  Fixed:

  ```python
  resp.set_cookie("sid", token, httponly=True, secure=True, samesite="Lax")
  ```
- [MEDIUM CWE-614] Session cookie set without Secure. Why it is a problem: The cookie is sent over plain HTTP and can be sniffed.
- [LOW CWE-1275] SameSite unset, or None without a documented cross-site need. Why it is a problem: Widens the CSRF surface.

### lifecycle

Secure patterns (support a SECURE verdict):
- Regenerate the session id at login, invalidate it at logout, and enforce idle and absolute timeouts. Why it is safe: Limits the window an stolen or fixated session is useful.

Insecure patterns (support a VULNERABLE verdict):
- [HIGH CWE-384] Do not rotate the session id after authentication (session fixation) Why it is a problem: An attacker who plants a known session id before login rides it afterward.
- [MEDIUM CWE-613] No session expiry or an unbounded lifetime. Why it is a problem: A leaked session stays valid indefinitely.

## Judgement notes

- Cite an evidence file and line for every VULNERABLE or PARTIAL verdict; a problem with no location is not reportable.
