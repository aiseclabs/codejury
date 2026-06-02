---
title: JWT / Authentication Flaws
impact: HIGH
tags: [authentication, jwt, cwe-347, cwe-287, owasp-a07]
triggers: ["jwt.decode", "verify=False", "verify_signature", "algorithms", "none", "HS256", "decode("]
---

## JWT and Authentication Flaws

Accepting a token without verifying its signature, allowing the "none" algorithm, or trusting claims before verification lets an attacker forge identity. Verify the signature and validate iss/aud/exp before using any claim.

### Python
Vulnerable:
```python
claims = jwt.decode(token, options={"verify_signature": False})
jwt.decode(token, key, algorithms=["none"])
```
Secure:
```python
claims = jwt.decode(token, key, algorithms=["RS256"], audience=AUD, issuer=ISS)
```
