# Secrets Management

How credentials and keys are stored, supplied, and kept out of code, logs, and version control.

Bring this skill into scope when you see:
- a literal string assigned to a key, token, password, secret, or credential name
- imports of a secret manager or vault client
- .env or config files with credential-looking values

## Dimensions to rule on

Output one verdict per dimension below (SECURE, VULNERABLE, PARTIAL, NOT_PRESENT, or UNKNOWN), even when the code is fine, so the report records what was checked. Use the dimension name as the verdict's `dimension`.

### storage

Secure patterns (support a SECURE verdict):
- Load secrets at runtime from environment variables or a secret manager. Why it is safe: A variable that reads its value from the environment or a secret manager is the correct pattern, not a violation; nothing secret is written in the source. Look for: `os.environ[`, `os.getenv(`, `secretsmanager`, `vault`.
- Receive a secret as a function or constructor parameter (dependency injection) Why it is safe: Accepting or forwarding a key through a parameter or variable is correct; the value comes from the caller or the environment, not a literal in the source. Only an actual key string written in the code is a finding. Look for: `def __init__(self, *, api_key`, `api_key: str | None = None`, `api_key=api_key`.

Insecure patterns (support a VULNERABLE verdict):
- [HIGH CWE-798] Assign a literal credential string: an actual key/token value written in the source. A variable, parameter, env lookup, or a non-credential string (e.g. a model name or URL) that merely holds or forwards a value is NOT this. Why it is a problem: The credential leaks with the source and cannot be rotated easily. Look for: `api_key = "sk`, `token = "ghp_`, `aws_secret_access_key = "`.

  Example of the bug:

  ```python
  API_KEY = "sk_live_51HxQ....actual-secret-value"   # literal secret in source
  ```

  Fixed:

  ```python
  api_key = os.environ["API_KEY"]                    # read from env, fine
  client = Client(api_key=api_key)                   # passed as a parameter, fine
  ```
- [HIGH CWE-259] Assign a literal password string in source. Why it is a problem: A fixed password in code is shared, discoverable, and unchangeable. Look for: `password = "`, `passwd = "`.

### exposure

Secure patterns (support a SECURE verdict):
- Log or render only non-credential data, or redact secrets before logging. Why it is safe: Emitting analysis results, status, or non-secret fields is fine. The risk is logging the value of a credential, not handling data in general.

Insecure patterns (support a VULNERABLE verdict):
- [MEDIUM CWE-532] Write the value of a secret, token, or password to logs or output. Why it is a problem: Logs are widely accessible and long-lived, so a logged secret value spreads. Look for: `log.info(token`, `print(password`, `logger.debug(secret`, `log.info(api_key`.
- [MEDIUM CWE-540] Commit secrets in config files or a tracked .env. Why it is a problem: Version history keeps the secret even after it is removed.

## Judgement notes

- Cite an evidence file and line for every VULNERABLE or PARTIAL verdict; a problem with no location is not reportable.
