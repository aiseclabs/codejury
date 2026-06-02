---
name: code-security-review
description: "Application security rules for reviewing code for exploitable vulnerabilities. Use when reviewing a diff or a codebase for security issues, or when writing code that handles untrusted input, authentication, authorization, file paths, database queries, network requests, deserialization, or cryptography. Read the matching rule before judging whether code is vulnerable."
---

# Code Security Review Rules

Application-security rules, one file per weakness class under `rules/`, named by
the specific weakness (CWE-style). Each rule states impact, the markers to hunt
(`triggers`), and vulnerable-vs-secure examples. The diff-audit engine injects the
rules relevant to a change into the prompt; the full-review agent reads them for
the target's stack. A finding's `category` is one of these ids.

## Rules by OWASP category

### A01 Broken Access Control
- `missing-authorization` (CWE-862)
- `insecure-direct-object-reference` (CWE-639)
- `cross-site-request-forgery` (CWE-352)
- `path-traversal` (CWE-22)
- `open-redirect` (CWE-601)

### A02 Cryptographic Failures
- `insecure-cryptography` (CWE-327)
- `insecure-transport` (CWE-319)
- `hardcoded-secrets` (CWE-798)
- `information-exposure` (CWE-200/532)

### A03 Injection
- `sql-injection` (CWE-89)
- `command-injection` (CWE-78)
- `code-injection` (CWE-94)
- `cross-site-scripting` (CWE-79)
- `xml-external-entity` (CWE-611)
- `server-side-template-injection` (CWE-1336)
- `http-response-splitting` (CWE-113)

### A04 Insecure Design / Business Logic
- `business-logic` (CWE-840)
- `replay-attack` (CWE-294)
- `race-condition` (CWE-362)
- `mass-assignment` (CWE-915)

### A07 Identification and Authentication
- `improper-authentication` (CWE-287)
- `jwt-validation` (CWE-347)
- `session-fixation` (CWE-384)

### A08 Software and Data Integrity
- `insecure-deserialization` (CWE-502)

### A10 Server-Side Request Forgery
- `server-side-request-forgery` (CWE-918)

Report only real, exploitable, high-confidence issues with a concrete exploit
path. Do not report dependency CVEs, style, speculation, or config-leak-only
risks. The set is data: add a class by dropping a new `rules/<id>.md` with the
same frontmatter (id, title, impact, tags, triggers) and examples.
