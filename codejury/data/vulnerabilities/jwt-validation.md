---
id: jwt-validation
title: JWT Validation Flaw
impact: HIGH
tags: [cwe-347, cwe-345, owasp-a07]
triggers: ["jwt.decode", "verify=False", "verify_signature", "algorithms", "none", "decode("]
---

## JWT Validation Flaw

Accepting a JWT without verifying its signature, allowing the "none" algorithm, or reading claims before verification lets an attacker forge identity. Verify the signature with a fixed algorithm and validate iss/aud/exp before using any claim.

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
