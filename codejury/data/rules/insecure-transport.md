---
id: insecure-transport
title: Insecure Transport
impact: HIGH
tags: [cwe-319, cwe-295, owasp-a02]
triggers: ["http://", "verify=False", "CERT_NONE", "check_hostname", "_create_unverified", "rejectUnauthorized", "InsecureSkipVerify"]
---

## Insecure Transport

Sending sensitive data over cleartext HTTP, or disabling TLS certificate/hostname verification, exposes it to interception and man-in-the-middle. Use HTTPS and leave certificate verification on (the secure default).

### Python
Vulnerable:
```python
requests.get("https://api.example.com/data", verify=False)
requests.post("http://api.example.com/login", data=creds)
```
Secure:
```python
requests.get("https://api.example.com/data")   # verify defaults to True
```
