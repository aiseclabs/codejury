---
title: Hardcoded Secrets
impact: HIGH
tags: [secrets, credentials, cwe-798, owasp-a07]
triggers: ["api_key =", "API_KEY =", "password =", "secret =", "token =", "sk_live", "ghp_", "aws_secret"]
---

## Hardcoded Secrets

A literal credential, key, or token written in source leaks with the code and cannot be rotated easily. Load secrets from environment variables or a secret manager; a variable that reads from env or is passed in as a parameter is fine, only a literal value is a finding.

### Python
Vulnerable:
```python
API_KEY = "sk_live_51HxQ...actual-secret"
```
Secure:
```python
api_key = os.environ["API_KEY"]
```
