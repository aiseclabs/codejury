---
id: path-traversal
title: Path Traversal
lens: path-traversal
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
base = UPLOAD_DIR.resolve()
target = (base / filename).resolve()
if not target.is_relative_to(base):
    raise ValueError("path escapes base dir")
```

### Not a Finding

If the input is neutralized before the file operation there is no traversal:
- `os.path.basename(name)` is applied and strips `../` and any directory parts,
- the resolved path is confirmed within a base using `is_relative_to` or `realpath` under base,
- the value is from an allowlist, or is a constant / trusted-config path.

`open(os.path.join(BASE, os.path.basename(name)))` is safe: basename removes the
traversal. Do not report it.

