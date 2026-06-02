# Attack Surface

Whole-repository design review of the attack surface. You are given an inventory
of the repository: its files and its entrypoints (the HTTP routes and CLI
commands where external input enters), not the line-by-line code. Judge whether
the surface exposes things it should not.

Strict scope. This skill judges only what should or should not be an entrypoint
at all. It does not judge how an endpoint is implemented:

- Whether sibling routes enforce authorization consistently is api_design.
- A single endpoint missing an authorization check is authz.
- How an endpoint handles its input is input_validation, and what it returns is
  data_protection.

A legitimate application route (an admin route that the app is meant to expose,
a normal CRUD route) is not a finding here. The finding is an entrypoint that
should not be reachable from the outside at all.

## Dimensions to rule on

Output one verdict for the dimension below (SECURE, VULNERABLE, PARTIAL,
NOT_PRESENT, or UNKNOWN). Use the dimension name as the verdict's `dimension`.
Cite the offending route or file as evidence for any VULNERABLE or PARTIAL
verdict.

### attack_surface

Secure (support a SECURE verdict):
- The exposed entrypoints all match what the application is for: documented
  product routes, with no debug, test, or internal-only routes reachable from the
  edge. Why it is safe: a minimal, intentional surface is less to defend and gives
  an attacker no unintended door.

Vulnerable (support a VULNERABLE verdict):
- [HIGH CWE-668] An entrypoint is exposed that should not be externally reachable:
  a debug, test, diagnostic, internal, or maintenance route (for example
  `/debug/...`, `/__debug`, `/internal/...`, `/test/...`, a route that dumps
  config or runs arbitrary input). Why it is a problem: these routes routinely
  skip the controls the product surface enforces, and often expose internals or
  dangerous operations directly.
- [MEDIUM CWE-668] The surface is far larger or more privileged than the stated
  purpose warrants, suggesting routes were exposed by accident. Why it is a
  problem: each unintended entrypoint is attackable.

## Judgement notes

- Decide from the inventory: is each route something the product is meant to
  expose, or something that leaked out (debug/internal/test)?
- A normal admin or product route is in scope by design; do not flag it here.
  Flag only entrypoints that should not exist on the public surface.
- Cite the route or file as the evidence location for any problem.
