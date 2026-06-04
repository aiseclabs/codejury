---
id: replay-attack
title: Replay Attack
impact: HIGH
tags: [cwe-294, owasp-a04]
triggers: ["nonce", "timestamp", "signature", "verify_sig", "idempotency", "webhook", "callback", "X-Signature"]
---

## Replay Attack

A signed or privileged request such as a payment, signature, webhook, or login is accepted again because it carries no nonce, no timestamp window, and no single-use check, so an attacker who captures one replays it. Bind each sensitive request to a one-time nonce or a short timestamp window, and reject reuse.

### Python
Vulnerable:
```python
if verify_signature(body, sig):       # no nonce / timestamp -> replayable
    process_payment(body)
```
Secure:
```python
if verify_signature(body, sig) and within_window(body["ts"]) and consume_nonce(body["nonce"]):
    process_payment(body)
```
