# Dependencies and Configuration

Software supply chain and deployment configuration, covering known-vulnerable components and unsafe defaults.

Bring this skill into scope when you see:
- dependency manifests and lock files
- install or bootstrap scripts fetching remote code
- file permission, bucket ACL, or default credential settings
- TLS client calls that set verify or build a custom SSL context

## Dimensions to rule on

Output one verdict per dimension below (SECURE, VULNERABLE, PARTIAL, NOT_PRESENT, or UNKNOWN), even when the code is fine, so the report records what was checked. Use the dimension name as the verdict's `dimension`.

### dependencies

Secure patterns (support a SECURE verdict):
- Pin dependency versions and scan them for known vulnerabilities. Why it is safe: Builds are reproducible and known-vulnerable versions are caught. Look for: `==`, `requirements.txt`, `poetry.lock`, `pip-audit`.

Insecure patterns (support a VULNERABLE verdict):
- [MEDIUM CWE-1104] Depend on unmaintained or known-vulnerable components. Why it is a problem: Public CVEs in shipped dependencies are directly exploitable.
- [MEDIUM CWE-494] Download or install code at runtime without an integrity or signature check. Why it is a problem: A tampered or hijacked source injects code into the build or host. Look for: `curl | sh`, `pip install http`, `urlretrieve`.

### configuration

Secure patterns (support a SECURE verdict):
- Ship secure defaults with least privilege and a minimal exposed surface. Why it is safe: Misconfiguration is the default-off state, not something to remember.

Insecure patterns (support a VULNERABLE verdict):
- [MEDIUM CWE-732] Grant overly permissive permissions (world-writable files, public storage buckets) Why it is a problem: Anyone can read or modify resources that should be restricted. Look for: `chmod 0777`, `0o777`, `ACL: public-read`, `AllUsers`.
- [HIGH CWE-1392] Ship default or sample credentials. Why it is a problem: Default credentials are public knowledge and trivially abused. Look for: `admin:admin`, `password=admin`, `changeme`.

### transport security

Secure patterns (support a SECURE verdict):
- Leave TLS certificate verification at its secure default: verify omitted or verify=True, the default SSL context, hostname checking on. Why it is safe: The secure default validates the certificate chain and hostname. An https:// call that does not disable verification is fine; do not flag it just for making a request or for omitting verify. Look for: `verify=True`, `create_default_context`, `requests.get(`, `requests.post(`.

Insecure patterns (support a VULNERABLE verdict):
- [HIGH CWE-295] Disable TLS certificate or hostname verification: verify=False, CERT_NONE, check_hostname=False, or an unverified SSL context. Why it is a problem: An unverified TLS connection is open to a man-in-the-middle despite https://. Look for: `verify=False`, `CERT_NONE`, `check_hostname = False`, `_create_unverified_context`.

  Example of the bug:

  ```python
  requests.get("https://api.partner.com/data", verify=False)
  ```

  Fixed:

  ```python
  requests.get("https://api.partner.com/data")  # verify defaults to True
  ```

## Judgement notes

- Cite an evidence file and line for every VULNERABLE or PARTIAL verdict; a problem with no location is not reportable.
