---
title: Path Traversal
impact: HIGH
tags: [path-traversal, cwe-22, owasp-a01]
triggers: ["open(", "os.path.join", "sendfile", "send_file", "readFile", "filename", "../", "upload"]
---

## Path Traversal

Building a filesystem path from untrusted input without containing it lets `../` escape the intended directory. Resolve the path and confirm it stays within an allowed base, or use the basename only.

### Python
Vulnerable:
```python
open(os.path.join(UPLOAD_DIR, request.args["filename"]))
```
Secure:
```python
target = (UPLOAD_DIR / filename).resolve()
if not target.is_relative_to(UPLOAD_DIR):
    raise ValueError("path escapes base dir")
```
