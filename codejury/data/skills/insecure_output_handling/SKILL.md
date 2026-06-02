# Insecure Output Handling

Model output is untrusted. When a completion is passed to a downstream interpreter (eval/exec, a shell, SQL) or rendered as markup without validation or encoding, the model, or an attacker who steered it via prompt injection, can reach code execution or XSS. Constrain and validate model output before use; encode it before rendering.

Bring this skill into scope when you see:
- a model completion (.text / .content / choices) flows into exec, eval, a shell, or SQL
- a model completion rendered as HTML or into a template
- model output used without schema validation or encoding

## Dimensions to rule on

Output one verdict per dimension below (SECURE, VULNERABLE, PARTIAL, NOT_PRESENT, or UNKNOWN), even when the code is fine, so the report records what was checked. Use the dimension name as the verdict's `dimension`.

### output to interpreter

Secure patterns (support a SECURE verdict):
- Constrain model output to a validated schema / allowlisted action before acting on it; never eval/exec or shell it. Why it is safe: The output can only select among safe, predefined actions. Look for: `model_validate`, `json.loads`, `schema`, `in ALLOWED`.

Insecure patterns (support a VULNERABLE verdict):
- [CRITICAL CWE-94] Pass a model completion to eval/exec, a shell (os.system, subprocess shell=True), or a raw SQL string. Why it is a problem: A completion (attacker-steerable) becomes code or commands that run. Look for: `exec(`, `eval(`, `os.system(`, `shell=True`, `.execute(`.

  Example of the bug:

  ```python
  code = client.complete(messages=[{"role": "user", "content": prompt}]).text
  exec(code)
  ```

  Fixed:

  ```python
  raw = client.complete(messages=[{"role": "user", "content": prompt}]).text
  action = ActionModel.model_validate_json(raw)  # schema-constrained
  dispatch(action.name)
  ```

### output to markup

Secure patterns (support a SECURE verdict):
- Encode model output before placing it in HTML or a template. Why it is safe: The completion renders as inert text, not markup. Look for: `html.escape`, `markupsafe`, `|e`, `autoescape`.

Insecure patterns (support a VULNERABLE verdict):
- [HIGH CWE-79] Render a model completion as HTML / into a template without encoding (innerHTML, string-built HTML, render_template_string) Why it is a problem: A completion containing markup or script executes in the browser. Look for: `innerHTML`, `render_template_string`, `|safe`, `Markup(`.

  Example of the bug:

  ```python
  answer = client.complete(messages=[{"role": "user", "content": q}]).text
  return "<div>" + answer + "</div>"
  ```

  Fixed:

  ```python
  answer = client.complete(messages=[{"role": "user", "content": q}]).text
  return "<div>" + html.escape(answer) + "</div>"
  ```

## Judgement notes

- Cite an evidence file and line for every VULNERABLE or PARTIAL verdict; a problem with no location is not reportable.
- Untrusted input must be able to reach the sink for this to be VULNERABLE. A constant, a stored data field, a value from trusted config, or a path or argument the operator supplies (for example a CLI argument) is not attacker-controlled; do not flag it.
