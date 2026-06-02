# API Design

API-surface problems that only the whole set of endpoints reveals, and that no
single-endpoint skill owns. You are given one HTTP handler plus an inventory of
every endpoint on the surface (method, route, handler, decorators). Judge the
surface, not the line.

Strict scope. This skill covers exactly three things: authorization that is
inconsistent across sibling routes, CORS misconfiguration, and whole-body mass
assignment. Everything that a single endpoint can be judged on in isolation
belongs to another skill, and you must not report it here:

- A single endpoint simply missing an authorization check, with no guarded
  sibling to compare against, is authz, not api_design.
- Input validation, injection, and bounds are input_validation.
- Leaking sensitive fields or PII in a response is data_protection.

## Dimensions to rule on

Output one verdict per dimension below (SECURE, VULNERABLE, PARTIAL,
NOT_PRESENT, or UNKNOWN). Use the dimension name as the verdict's `dimension`.
Cite an evidence file and line for any VULNERABLE or PARTIAL verdict.

### endpoint_authz

This dimension is about consistency across the surface, never a lone endpoint.

Secure (support a SECURE verdict):
- Every state-changing route (POST, PUT, PATCH, DELETE) on the surface enforces
  the same authorization gate, or is an explicitly intended public route. Why it
  is safe: there is no unguarded sibling for an attacker to pick.

Vulnerable (support a VULNERABLE verdict):
- [HIGH CWE-862] A mutating or privileged route omits the authorization
  decorator or check that its sibling routes on the same surface apply. Why it is
  a problem: the inconsistency is the hole; the unguarded endpoint reaches the
  same class of action without the check its peers require.
  Only flag this when the inventory shows a guarded sibling to compare against. A
  surface where no route is guarded is an authz question, not an api_design one.

  Inconsistent (flag here):

  ```python
  @app.route("/admin/users", methods=["GET"])
  @requires_admin
  def list_users(): ...

  @app.route("/admin/users/<id>", methods=["DELETE"])   # sibling dropped @requires_admin
  def delete_user(id): ...
  ```

  Consistent (fine):

  ```python
  @app.route("/admin/users/<id>", methods=["DELETE"])
  @requires_admin
  def delete_user(id): ...
  ```

### cors

Secure (support a SECURE verdict):
- Cross-origin access is limited to an explicit origin allowlist, and credentials
  are not combined with a wildcard or reflected origin. Why it is safe: only named
  origins can read authenticated responses.

Vulnerable (support a VULNERABLE verdict):
- [HIGH CWE-942] Allow any origin together with credentials, or reflect the
  request Origin into Access-Control-Allow-Origin while allowing credentials. Why
  it is a problem: any website can then make credentialed requests and read the
  authenticated response.

  Bad:

  ```python
  CORSMiddleware(allow_origins=["*"], allow_credentials=True)
  ```

  Good:

  ```python
  CORSMiddleware(allow_origins=["https://app.example.com"], allow_credentials=True)
  ```

### mass_assignment

Secure (support a SECURE verdict):
- The handler binds only an explicit allowlist of fields from the request body
  into the model or update. Why it is safe: client-controlled fields cannot reach
  attributes the API never offered.

Vulnerable (support a VULNERABLE verdict):
- [HIGH CWE-915] The handler spreads the whole request body into a model
  constructor or update, e.g. Model(**request.json) or obj.update(**body). Why it
  is a problem: a client can set internal fields it was never offered, such as
  is_admin or balance.

  Bad:

  ```python
  user = User(**request.get_json())
  ```

  Good:

  ```python
  body = request.get_json()
  user = User(name=body["name"], email=body["email"])
  ```

## Judgement notes

- Use the endpoint inventory to reason about the surface; a verdict that needs a
  guarded sibling must point to one.
- Cite an evidence file and line for every VULNERABLE or PARTIAL verdict; a
  problem with no location is not reportable.
