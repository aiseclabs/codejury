---
id: server-side-request-forgery
title: Server-Side Request Forgery
impact: HIGH
tags: [cwe-918, owasp-a10]
triggers: ["requests.get", "requests.post", "urlopen", "httpx", "fetch(", "url =", "request.args", "webhook", "callback"]
---

## Server-Side Request Forgery

A server fetches a URL taken from untrusted input without restricting the destination, so an attacker reaches internal targets such as cloud metadata at 169.254.169.254, localhost admin ports, or internal APIs. Validate the host against an allowlist before fetching and reject internal/link-local addresses.

### Python
Vulnerable:
```python
return requests.get(request.args["url"]).text
```
Secure:
```python
if urlparse(url).hostname not in ALLOWED_HOSTS:
    raise ValueError("host not allowed")
return requests.get(url).text
```

A hostname allowlist alone is often not enough. Enforce `https`, reject credentials in the URL, resolve the host and block private, loopback, and link-local ranges, and re-check after each redirect. Prefer an exact destination allowlist.

### Not a Finding

A URL fetched only after an exact allowlist plus internal-IP blocking, with redirects controlled, is not SSRF. A constant or trusted-config URL is not SSRF.
