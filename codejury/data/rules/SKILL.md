---
name: code-security-review
description: "Application security rules for reviewing code for exploitable vulnerabilities. Use when reviewing a diff or a codebase for security issues, or when writing code that handles untrusted input, authentication, authorization, file paths, database queries, network requests, deserialization, or cryptography. Consult the relevant rule file before judging whether code is vulnerable."
---

# Code Security Review Rules

Generic application-security rules, one file per vulnerability class under `rules/`.
Each rule states the impact, the patterns to hunt, and vulnerable-vs-secure code
examples. Used both by the diff-audit engine (the relevant rules are injected into
the prompt) and by the full-review agent (read the rules for the target's stack).

## How to use

1. Identify what the code does: handle input, query a DB, read files, fetch URLs,
   authenticate, authorize, deserialize, render output?
2. Read the matching rule files below, Critical and High first.
3. Apply the secure pattern when writing; flag the vulnerable pattern when reviewing.
4. Report only real, exploitable, high-confidence issues with a concrete exploit
   path. Do not report dependency CVEs, style, speculation, or config-leak-only risks.

## Rules

### Critical
- SQL Injection — `rules/sql-injection.md`
- Command Injection — `rules/command-injection.md`
- Insecure Deserialization — `rules/insecure-deserialization.md`

### High
- IDOR / object-level access — `rules/idor.md`
- Broken Access Control / function-level authz — `rules/broken-access-control.md`
- JWT / Authentication — `rules/authentication-jwt.md`
- SSRF — `rules/ssrf.md`
- Path Traversal — `rules/path-traversal.md`
- XSS — `rules/xss.md`
- Mass Assignment — `rules/mass-assignment.md`
- Insecure Cryptography — `rules/insecure-crypto.md`
- Hardcoded Secrets — `rules/secrets.md`

The set is data: add a rule by dropping a new `rules/<class>.md` with the same
frontmatter (title, impact, tags, triggers) and vulnerable/secure examples.
