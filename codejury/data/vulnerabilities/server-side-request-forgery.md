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
