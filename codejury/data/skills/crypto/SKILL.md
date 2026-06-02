# Cryptography

Correct choice and use of cryptographic primitives for confidentiality and integrity.

Bring this skill into scope when you see:
- imports of hashlib, Crypto, cryptography, or ssl
- encrypt, decrypt, sign, or token generation
- key, iv, nonce, or salt literals

## Dimensions to rule on

Output one verdict per dimension below (SECURE, VULNERABLE, PARTIAL, NOT_PRESENT, or UNKNOWN), even when the code is fine, so the report records what was checked. Use the dimension name as the verdict's `dimension`.

### algorithm

Secure patterns (support a SECURE verdict):
- Use vetted authenticated encryption such as AES-GCM or ChaCha20-Poly1305. Why it is safe: Modern AEAD provides confidentiality and integrity with no mode pitfalls. Look for: `AESGCM`, `ChaCha20Poly1305`, `AES.MODE_GCM`.

Insecure patterns (support a VULNERABLE verdict):
- [HIGH CWE-327] Use a broken or obsolete cipher or hash for security (DES, 3DES, RC4, MD5, SHA-1) Why it is a problem: These are practically attackable and unfit for protecting data. Look for: `DES.new`, `ARC4`, `Crypto.Cipher.DES`, `hashlib.md5`, `hashlib.sha1`.

  Example of the bug:

  ```python
  cipher = DES.new(key, DES.MODE_ECB)
  ```

  Fixed:

  ```python
  cipher = AESGCM(key); ct = cipher.encrypt(nonce, data, None)
  ```
- [HIGH CWE-327] Use ECB mode for a block cipher. Why it is a problem: ECB leaks plaintext structure because identical blocks encrypt identically. Look for: `MODE_ECB`.
- [MEDIUM CWE-326] Use an inadequate key size (e.g. RSA shorter than 2048 bits) Why it is a problem: Undersized keys are within reach of feasible attacks.

### key and nonce

Secure patterns (support a SECURE verdict):
- Load keys from a KMS or secret store and rotate them; derive a fresh random nonce per message. Why it is safe: Keys are not exposed in code and nonces stay unique.

Insecure patterns (support a VULNERABLE verdict):
- [HIGH CWE-321] Hardcode a cryptographic key in source. Why it is a problem: Anyone with the source can decrypt everything. Look for: `key = b"`, `SECRET_KEY = "`, `AES_KEY =`.
- [HIGH CWE-329] Use a static or reused IV/nonce. Why it is a problem: Nonce reuse breaks GCM and reveals patterns under CBC. Look for: `iv = b"\x00`, `nonce = b"`, `IV = bytes(16)`.

### randomness

Secure patterns (support a SECURE verdict):
- Use a CSPRNG (secrets, os.urandom) for tokens, keys, and salts. Why it is safe: Cryptographically strong randomness is unpredictable. Look for: `secrets.token_`, `os.urandom(`.

Insecure patterns (support a VULNERABLE verdict):
- [MEDIUM CWE-338] Use a non-cryptographic PRNG for security-sensitive values. Why it is a problem: Mersenne Twister output is predictable from a few samples. Look for: `random.random(`, `random.randint(`, `random.choice(`.

## Judgement notes

- Cite an evidence file and line for every VULNERABLE or PARTIAL verdict; a problem with no location is not reportable.
