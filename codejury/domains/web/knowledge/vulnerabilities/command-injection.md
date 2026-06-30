---
id: command-injection
title: Command Injection
lens: injection
impact: CRITICAL
tags: [cwe-78, owasp-a03, injection]
triggers: ["os.system", "os.popen", "subprocess", "shell=True", "Runtime.getRuntime", "child_process", "popen", "exec("]
---

## Command Injection

Passing untrusted input to a shell lets an attacker run arbitrary commands. Never build a shell string from input. Pass an argument list with the shell disabled.

### Python
Vulnerable:
```python
os.system("ping " + host)
subprocess.run(f"convert {name}", shell=True)
```
Secure:
```python
subprocess.run(["ping", "-c", "1", host], shell=False)
```

### Node.js
Vulnerable: `child_process.exec(`ping ${host}`)`
Secure: `child_process.execFile("ping", ["-c", "1", host])`
