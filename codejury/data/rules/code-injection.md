---
id: code-injection
title: Code Injection
impact: CRITICAL
tags: [cwe-94, owasp-a03, injection, rce]
triggers: ["eval(", "exec(", "compile(", "pickle.loads", "new Function", "setTimeout(\"", "vm.runInContext"]
---

## Code Injection

Passing untrusted input to a language evaluation primitive (eval, exec, compile, dynamic import, JS Function) lets an attacker execute arbitrary code. Never evaluate untrusted input; parse it with a data-only parser or dispatch through an allowlist.

### Python
Vulnerable:
```python
result = eval(request.args["expr"])
exec(user_supplied_code)
```
Secure:
```python
import ast
result = ast.literal_eval(request.args["expr"])   # data only, no code
```
