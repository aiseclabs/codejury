# API Design

Architectural consistency across an HTTP API's endpoints, not single-line bugs. It judges the surface as a whole: whether sibling routes enforce authorization the same way, whether request bodies are bound by an explicit field allowlist, whether responses and CORS expose more than intended. Point vulnerabilities stay with their own capability (an IDOR is authz, an injection is input_validation); api_design fires when an endpoint is inconsistent with its peers or binds and exposes data wholesale at the boundary.

Bring this skill into scope when you see:
- more than one HTTP route on the same app or router
- authorization decorators present on some routes but not others
- request bodies bound directly into models
- responses built from whole ORM objects

## Dimensions to rule on

Output one verdict per dimension below (SECURE, VULNERABLE, PARTIAL, NOT_PRESENT, or UNKNOWN), even when the code is fine, so the report records what was checked. Use the dimension name as the verdict's `dimension`.

### endpoint authz

Secure patterns (support a SECURE verdict):
- Every state-changing route enforces the same authorization gate its peers use, or is an explicitly intended public route. Why it is safe: A uniform gate removes the gap an attacker reaches by picking the one unguarded sibling. Look for: `@login_required`, `@requires_auth`, `permission_classes`, `Depends(require_user)`.

Insecure patterns (support a VULNERABLE verdict):
- [HIGH CWE-862] A mutating or privileged route omits the authorization decorator or check that sibling routes on the same surface apply. Why it is a problem: The inconsistency is the hole; the unguarded endpoint reaches the same actions without the check.

  Example of the bug:

  ```python
  @app.route("/admin/users", methods=["GET"])
  @requires_admin
  def list_users(): ...
  
  @app.route("/admin/users/<id>", methods=["DELETE"])
  def delete_user(id): ...   # sibling drops @requires_admin
  ```

  Fixed:

  ```python
  @app.route("/admin/users/<id>", methods=["DELETE"])
  @requires_admin
  def delete_user(id): ...
  ```

### cors

Secure patterns (support a SECURE verdict):
- Cross-origin access is limited to an explicit origin allowlist, and credentials are not combined with a wildcard origin. Why it is safe: Only named origins can read authenticated responses. Look for: `allow_origins=[`, `CORS_ALLOWED_ORIGINS`, `origins=[`.

Insecure patterns (support a VULNERABLE verdict):
- [HIGH CWE-942] Allow any origin with credentials, or reflect the request Origin into Access-Control-Allow-Origin while allowing credentials. Why it is a problem: Any site can make credentialed requests and read the authenticated response. Look for: `allow_origins=["*"]`, `Access-Control-Allow-Origin", "*"`, `allow_credentials=True`.

### mass assignment

Secure patterns (support a SECURE verdict):
- Bind only an explicit allowlist of fields from the request body into the model or update. Why it is safe: Client-controlled fields cannot reach attributes the API did not intend to expose. Look for: `schema.load`, `pick(`, `only=(`, `fields = [`.

Insecure patterns (support a VULNERABLE verdict):
- [HIGH CWE-915] Spread the whole request body into a model constructor or update, e.g. Model(**request.json) or obj.update(**data) Why it is a problem: A client can set internal fields it was never offered, such as is_admin or balance. Look for: `(**request.json`, `(**request.get_json`, `update(**data`, `setattr(obj`.

  Example of the bug:

  ```python
  user = User(**request.get_json())
  ```

  Fixed:

  ```python
  body = request.get_json()
  user = User(name=body["name"], email=body["email"])
  ```

### boundary validation

Secure patterns (support a SECURE verdict):
- Validate request inputs against a schema or explicit bounds at the API boundary, consistently across endpoints. Why it is safe: Malformed or out-of-range input is rejected before it reaches business logic. Look for: `pydantic`, `marshmallow`, `request_schema`, `validate(`.

Insecure patterns (support a VULNERABLE verdict):
- [MEDIUM CWE-20] An endpoint consumes client-supplied limits, offsets, or sizes with no bounds while sibling endpoints validate, or accepts the raw body with no schema. Why it is a problem: Unbounded client input drives resource exhaustion or skips invariants the validated siblings enforce.

### response exposure

Secure patterns (support a SECURE verdict):
- Serialize responses through an explicit field allowlist or response schema. Why it is safe: New internal fields do not leak into responses by default. Look for: `response_model=`, `ResponseSchema`, `only=(`, `serializer`.

Insecure patterns (support a VULNERABLE verdict):
- [MEDIUM CWE-213] Return a whole ORM row or internal object to the client, e.g. jsonify(user.__dict__) or returning the model directly, exposing fields like password_hash. Why it is a problem: Internal and sensitive fields ship to the client whenever the model grows. Look for: `jsonify(user.__dict__`, `return user.__dict__`, `to_dict()`, `model_dump()`.

## Judgement notes

- Cite an evidence file and line for every VULNERABLE or PARTIAL verdict; a problem with no location is not reportable.
