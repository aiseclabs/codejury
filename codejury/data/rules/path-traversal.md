---
id: path-traversal
title: Path Traversal
impact: HIGH
tags: [cwe-22, owasp-a01]
triggers: ["open(", "os.path.join", "send_file", "sendfile", "readFile", "filename", "../", "upload"]
---

## Path Traversal

A filesystem path built from untrusted input without containment lets `../` escape the intended directory. Resolve the path and confirm it stays within an allowed base, or use only the basename.

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
