# Excessive Agency

An LLM-driven agent acts on the world from model output. The risk is too much autonomy or privilege: a completion (which an attacker can steer via prompt injection) triggers a high-impact or irreversible action, such as delete, transfer, send, or run, with no allowlist of permitted tools, no human confirmation, and no least-privilege scoping. The fix is to gate actions: allowlist low-impact tools, require human approval for high-impact ones, and scope each tool's authority narrowly. This is about the action and its authority, not about encoding (output_to_markup) or interpreters (output_to_interpreter).

Bring this skill into scope when you see:
- a model completion selects a tool/function that is then invoked
- getattr/eval/dict dispatch of a tool name from model output
- high-impact actions (delete, transfer, send, deploy) reached from model output

## Dimensions to rule on

Output one verdict per dimension below (SECURE, VULNERABLE, PARTIAL, NOT_PRESENT, or UNKNOWN), even when the code is fine, so the report records what was checked. Use the dimension name as the verdict's `dimension`.

### unconstrained action

Secure patterns (support a SECURE verdict):
- Dispatch only through an allowlist of low-impact tools; require explicit human approval before any high-impact or irreversible action. Why it is safe: A steered completion can only reach pre-approved, low-impact actions. Look for: `ALLOWED`, `in TOOLS`, `require_approval`, `confirm`, `human`.

Insecure patterns (support a VULNERABLE verdict):
- [HIGH CWE-862] Dispatch a tool or action chosen by the model with no allowlist (getattr/eval of a tool name, or a free function table) so any tool, including destructive ones, can be invoked. Why it is a problem: A manipulated completion can invoke any tool the process exposes. Look for: `getattr(`, `TOOLS[`, `globals()[`, `tool_name`, `call["name"]`.

  Example of the bug:

  ```python
  call = json.loads(client.complete(messages=[{"role": "user", "content": msg}]).text)
  getattr(tools, call["name"])(**call["args"])
  ```

  Fixed:

  ```python
  ALLOWED = {"search": search, "summarize": summarize}
  if call["name"] not in ALLOWED:
      raise ValueError("tool not permitted")
  ALLOWED[call["name"]](**call["args"])
  ```
- [HIGH CWE-862] Perform a high-impact or irreversible operation (delete, transfer, send, deploy) directly on the model's decision, with no human in the loop. Why it is a problem: An autonomous, unconfirmed action turns a wrong/steered output into damage. Look for: `drop_all`, `transfer(`, `delete(`, `send(`, `deploy(`.

  Example of the bug:

  ```python
  decision = client.complete(messages=[{"role": "user", "content": req}]).text
  if decision.strip() == "DELETE":
      db.drop_all()
  ```

  Fixed:

  ```python
  decision = client.complete(messages=[{"role": "user", "content": req}]).text
  if decision.strip() == "DELETE":
      queue_for_human_approval("DELETE", req)
  ```

## Judgement notes

- Cite an evidence file and line for every VULNERABLE or PARTIAL verdict; a problem with no location is not reportable.
- Untrusted input must be able to reach the sink for this to be VULNERABLE. A constant, a stored data field, a value from trusted config, or a path or argument the operator supplies (for example a CLI argument) is not attacker-controlled; do not flag it.
