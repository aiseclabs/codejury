# Input Validation

The inbound trust boundary. Untrusted input must be parameterized, validated against an allowlist, or escaped before it reaches an interpreter (SQL, shell, filesystem, template, LDAP, ...).

Bring this skill into scope when you see:
- raw SQL strings or cursor.execute calls appear
- imports of os, subprocess, or shlex with process execution
- file paths built from request, form, or query parameters
- outbound HTTP fetches (requests, urllib, httpx) to a non-constant URL
- deserialization calls (pickle, yaml.load, marshal) on external input

## Dimensions to rule on

Output one verdict per dimension below (SECURE, VULNERABLE, PARTIAL, NOT_PRESENT, or UNKNOWN), even when the code is fine, so the report records what was checked. Use the dimension name as the verdict's `dimension`.

### sql injection

Secure patterns (support a SECURE verdict):
- Use parameterized queries or ORM-bound parameters; never build SQL from input. Why it is safe: The driver sends data separately from the statement, so input cannot alter the query. Look for: `cursor.execute(`, `execute(query, params`, `session.query(`, `text(:param)`.

Insecure patterns (support a VULNERABLE verdict):
- [CRITICAL CWE-89] Build SQL by string concatenation or f-string interpolation of input. Why it is a problem: Input becomes part of the statement and can change its meaning entirely. Look for: `execute(f"`, `execute("SELECT`, `" + `, `% (`, `.format(`.

  Example of the bug:

  ```python
  cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
  ```

  Fixed:

  ```python
  cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
  ```
- [HIGH CWE-89] Interpolate a table or column name from input without an allowlist. Why it is a problem: Identifiers cannot be parameterized, so unchecked input still injects.
- [HIGH CWE-89] Pass a pre-built SQL string to an ORM raw or text escape hatch. Why it is a problem: Raw escape hatches bypass the ORM's parameter binding. Look for: `.raw(`, `text(`, `execute_sql(`.

### command injection

Secure patterns (support a SECURE verdict):
- Run subprocesses with an argument list and shell=False. Why it is safe: Arguments are passed directly to execve, so the shell never parses input. This only applies to code that actually spawns a process; an ordinary function, method, or library/API call (e.g. provider.complete) is not command execution. Look for: `subprocess.run([`, `subprocess.Popen([`.

Insecure patterns (support a VULNERABLE verdict):
- [CRITICAL CWE-78] Pass interpolated input to an OS shell or subprocess: os.system, os.popen, subprocess(..., shell=True), or eval/exec. A normal function, method, or library/API call is NOT this; flag only an actual shell or process invocation. Why it is a problem: Shell metacharacters in input let an attacker run arbitrary commands. Look for: `os.system(`, `shell=True`, `os.popen(`.

  Example of the bug:

  ```python
  os.system("ping " + host)
  ```

  Fixed:

  ```python
  subprocess.run(["ping", "-c", "1", host], shell=False)
  ```
- [HIGH CWE-78] Build the argument list itself from an unvalidated, shell-parsed string. Why it is a problem: Splitting an untrusted string can still smuggle extra arguments or commands. Look for: `shlex.split(`, `shell=True`.

### path traversal

Secure patterns (support a SECURE verdict):
- Resolve the path and confirm it stays within an allowed base directory. Why it is safe: A resolved path outside the base is rejected before any file access. Look for: `os.path.realpath`, `Path(...).resolve()`, `is_relative_to(`.
- Use a path that is not attacker-controlled: a data field, a directory read from trusted config, or a path the operator passes on the command line. Why it is safe: Traversal needs an external attacker to control the path. A path stored as a field, a trusted/configured directory, or an operator-supplied CLI argument is not a finding; neither is merely declaring a `path` attribute.

Insecure patterns (support a VULNERABLE verdict):
- [HIGH CWE-22] Take an externally controlled value (HTTP request, upload, form, query, or message field) and use it in a filesystem open/read/write without resolving it and confirming it stays in an allowed base. NOT this: a path kept as a data field, a directory from trusted config, or a path the operator passes on the CLI. Why it is a problem: Sequences like ../ let attacker input escape the intended directory. Look for: `request.`, `upload`, `filename`, `os.path.join(`.

  Example of the bug:

  ```python
  open(os.path.join(UPLOAD_DIR, request.args["filename"]))
  ```

  Fixed:

  ```python
  target = (UPLOAD_DIR / filename).resolve()
  if not target.is_relative_to(UPLOAD_DIR):
      raise ValueError("path escapes upload dir")
  ```

### ssrf

Secure patterns (support a SECURE verdict):
- Validate the request URL's host against an allowlist before fetching it. Why it is safe: An attacker cannot redirect the fetch to an internal target the list omits. Look for: `urlparse(`, `.hostname`, `ALLOWED`, `allowlist`.
- Fetch a URL that is not attacker-controlled: a constant, a value from trusted config, or an operator-supplied argument. Why it is safe: SSRF needs an external attacker to control the destination. A constant URL or one from trusted config is not a finding, even though it goes through a fetch call.

Insecure patterns (support a VULNERABLE verdict):
- [HIGH CWE-918] Fetch a URL taken from externally controlled input (HTTP request, form, query, or message field) without validating its host against an allowlist. NOT this: a constant URL, one from trusted config, or an operator-supplied argument. Why it is a problem: The server makes the request, so attacker input reaches internal-only targets: cloud metadata, localhost admin ports, internal APIs behind the firewall. Look for: `requests.get(`, `urllib.request.urlopen(`, `httpx.`, `request.args`, `request.json`.

  Example of the bug:

  ```python
  requests.get(request.args["url"]).text
  ```

  Fixed:

  ```python
  if urlparse(url).hostname not in ALLOWED_HOSTS:
      raise ValueError("host not allowed")
  requests.get(url).text
  ```

### insecure deserialization

Secure patterns (support a SECURE verdict):
- Parse untrusted input with a data-only parser, json.loads or yaml.safe_load, that cannot instantiate arbitrary objects. Why it is safe: A data-only parser builds plain structures and has no code-execution path. Look for: `json.loads`, `yaml.safe_load`.

Insecure patterns (support a VULNERABLE verdict):
- [CRITICAL CWE-502] Deserialize externally controlled bytes with an object-constructing deserializer: pickle, marshal, yaml.load (unsafe Loader), or jsonpickle. NOT this: a data-only parser like json.loads or yaml.safe_load. Why it is a problem: These reconstruct arbitrary objects, so crafted input runs code on unpickle. Look for: `pickle.loads`, `pickle.load(`, `yaml.load(`, `marshal.loads`, `jsonpickle.decode`.

  Example of the bug:

  ```python
  pickle.loads(base64.b64decode(request.data))
  ```

  Fixed:

  ```python
  json.loads(request.data)
  ```

## Judgement notes

- Cite an evidence file and line for every VULNERABLE or PARTIAL verdict; a problem with no location is not reportable.
- Untrusted input must be able to reach the sink for this to be VULNERABLE. A constant, a stored data field, a value from trusted config, or a path or argument the operator supplies (for example a CLI argument) is not attacker-controlled; do not flag it.
