# Authentication

Mechanisms that verify a caller's claimed identity.

Bring this skill into scope when you see:
- routes matching /login, /register, /auth, or /token appear
- imports of jwt, pyjwt, python-jose, or authlib
- a user model with a password or password_hash field

## Dimensions to rule on

Output one verdict per dimension below (SECURE, VULNERABLE, PARTIAL, NOT_PRESENT, or UNKNOWN), even when the code is fine, so the report records what was checked. Use the dimension name as the verdict's `dimension`.

### password storage

Secure patterns (support a SECURE verdict):
- Hash passwords with bcrypt, scrypt, or Argon2id at an OWASP-recommended cost. Why it is safe: Slow, salted, memory-hard hashing resists GPU brute force and rainbow tables. Look for: `bcrypt.hashpw`, `argon2.PasswordHasher`, `hashlib.scrypt`, `passlib`.

Insecure patterns (support a VULNERABLE verdict):
- [HIGH CWE-916] Hash passwords with a fast general-purpose digest such as MD5, SHA-1, or SHA-256. Why it is a problem: Unsalted fast hashes are brute-forced at billions of guesses per second on commodity GPUs. Look for: `hashlib.md5(`, `hashlib.sha1(`, `hashlib.sha256(`.

  Example of the bug:

  ```python
  hashlib.sha256(password.encode()).hexdigest()
  ```

  Fixed:

  ```python
  bcrypt.hashpw(password.encode(), bcrypt.gensalt())
  ```
- [HIGH CWE-256] Store passwords in plaintext or with reversible encryption. Why it is a problem: A single database leak exposes every credential directly.
- [MEDIUM CWE-759] Hash without a per-user salt, using a global salt or no salt. Why it is a problem: Identical passwords produce identical hashes, so precomputed tables apply across users.

### jwt verification

Secure patterns (support a SECURE verdict):
- Verify the signature and validate iss, aud, exp, and nbf before trusting any claim. Why it is safe: Rejects forged, expired, and misrouted tokens before their claims are used. Look for: `algorithms=`, `audience=`, `issuer=`.

Insecure patterns (support a VULNERABLE verdict):
- [HIGH CWE-347] Accept the "none" algorithm, or sign with a weak or hardcoded HS256 secret. Why it is a problem: An attacker can forge tokens that the server accepts as authentic. Look for: `algorithms=["none"]`, `algorithms=["HS256"]`.
- [HIGH CWE-345] Read claims before verifying the signature, or skip verification entirely. Why it is a problem: Attacker-controlled claims drive trust and authorization decisions. Look for: `verify_signature": False`, `verify=False`.

  Example of the bug:

  ```python
  claims = jwt.decode(token, options={"verify_signature": False})
  ```

  Fixed:

  ```python
  claims = jwt.decode(token, key, algorithms=["RS256"], audience=AUD, issuer=ISS)
  ```

## Judgement notes

- Cite an evidence file and line for every VULNERABLE or PARTIAL verdict; a problem with no location is not reportable.
