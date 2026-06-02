---
title: Insecure Deserialization
impact: CRITICAL
tags: [deserialization, rce, cwe-502, owasp-a08]
triggers: ["pickle.loads", "pickle.load", "yaml.load", "marshal.loads", "jsonpickle", "ObjectInputStream", "torch.load"]
---

## Insecure Deserialization

Deserializing untrusted bytes with an object-constructing deserializer (pickle, yaml.load, marshal, Java ObjectInputStream) reconstructs arbitrary objects and can run code. Use a data-only parser (json.loads, yaml.safe_load) for untrusted input.

### Python
Vulnerable:
```python
data = pickle.loads(base64.b64decode(request.data))
config = yaml.load(untrusted)
```
Secure:
```python
data = json.loads(request.data)
config = yaml.safe_load(untrusted)
```
