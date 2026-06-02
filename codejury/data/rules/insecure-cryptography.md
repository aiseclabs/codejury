---
id: insecure-cryptography
title: Insecure Cryptography
impact: HIGH
tags: [cwe-327, cwe-916, owasp-a02]
triggers: ["hashlib.md5", "hashlib.sha1", "DES", "ECB", "MODE_ECB", "random.random", "random.randint", "md5(", "sha1("]
---

## Insecure Cryptography

Weak algorithms (MD5, SHA-1, DES, RC4), ECB mode, fast hashes for passwords, static or reused IVs, and non-cryptographic randomness for security values are exploitable. Use AES-GCM or ChaCha20-Poly1305, bcrypt/scrypt/argon2 for passwords, a fresh random nonce per message, and a CSPRNG (secrets / os.urandom).

### Python
Vulnerable:
```python
hashlib.md5(password.encode()).hexdigest()
token = str(random.randint(0, 999999))
```
Secure:
```python
bcrypt.hashpw(password.encode(), bcrypt.gensalt())
token = secrets.token_urlsafe(32)
```
