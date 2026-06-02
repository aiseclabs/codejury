# Error Handling and Logging

Failing without leaking information, and recording enough to investigate incidents.

Bring this skill into scope when you see:
- exception handlers and error responses
- logging configuration and DEBUG flags
- authentication, authorization, or admin actions

## Dimensions to rule on

Output one verdict per dimension below (SECURE, VULNERABLE, PARTIAL, NOT_PRESENT, or UNKNOWN), even when the code is fine, so the report records what was checked. Use the dimension name as the verdict's `dimension`.

### information leakage

Secure patterns (support a SECURE verdict):
- Return a generic error to the client and log the detail server-side. Why it is safe: The caller learns nothing exploitable while operators keep the detail. Look for: `except Exception`, `return 500`, `abort(500)`.

Insecure patterns (support a VULNERABLE verdict):
- [MEDIUM CWE-209] Return a stack trace or exception detail to the client. Why it is a problem: Internal paths, queries, and versions help an attacker map the system. Look for: `traceback.format_exc()`, `str(e)`, `return jsonify(error=str`.

  Example of the bug:

  ```python
  return jsonify(error=traceback.format_exc()), 500
  ```

  Fixed:

  ```python
  app.logger.exception("checkout failed"); return jsonify(error="internal error"), 500
  ```
- [LOW CWE-489] Leave a debug feature or verbose mode enabled in production. Why it is a problem: Debug pages expose internals and sometimes allow code execution. Look for: `DEBUG = True`, `app.run(debug=True`, `FLASK_DEBUG=1`.

### audit trail

Secure patterns (support a SECURE verdict):
- Log security-relevant events (auth attempts, access denials, admin actions) with timestamp and actor. Why it is safe: Gives a forensic trail to detect and reconstruct abuse.

Insecure patterns (support a VULNERABLE verdict):
- [MEDIUM CWE-778] Do not log security-relevant events. Why it is a problem: Without an audit trail, intrusions go unnoticed and uninvestigable.

## Judgement notes

- Cite an evidence file and line for every VULNERABLE or PARTIAL verdict; a problem with no location is not reportable.
