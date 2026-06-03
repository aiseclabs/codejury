---
id: oauth
title: OAuth and OIDC
kind: topic
detect:
  files: []
  manifest: ["authlib", "oauthlib", "oauth2", "django-oauth", "django-allauth", "oic", "openid", "oidc"]
  imports: ["import authlib", "from authlib", "import oauthlib", "from oauthlib", "import jwt"]
---
# OAuth and OIDC Review Notes

An OAuth or OIDC server holds protocol state, so the high-value bugs are logic,
authorization, and replay flaws rather than injection. Trace each grant and token
flow end to end and check the points below. These are where real audits find
issues that a surface read misses.

## Authorization Code
- Single use: the code must be redeemed once. Redeem it inside a row lock or an
  atomic conditional update so two concurrent requests cannot both succeed. A
  read then update without a lock is a double-redeem.
- Bound to the client: the code issued to client A must be rejected when client B
  presents it. Check that the token endpoint compares the code's client to the
  authenticated client.
- Bound to the redirect_uri and PKCE: the redirect_uri and the PKCE verifier at
  the token endpoint must match what was used at authorize. A missing PKCE check
  on a public client is exploitable.
- Expiry enforced: an expired code must be rejected. Confirm the expiry is read
  and compared, not just stored.

## redirect_uri and State
- redirect_uri is validated against a registered allowlist with exact match, not
  a prefix or substring, so an open redirect or code leak is not possible.
- The state parameter is present and checked to stop login CSRF.

## Tokens and Sessions
- Access and refresh tokens are random and high entropy, scoped, and expire.
- Refresh rotates and the old token is revoked, so a captured refresh cannot be
  replayed.
- JWT access tokens verify the signature, the algorithm, the issuer, the
  audience, and expiry. A `verify=False` or an unconstrained algorithm is a flaw.
  See the jwt-validation rule.

## Replay and Signatures
- A signed or one-time request such as an MFA binding, a webhook, or a privileged
  action carries a nonce or a short timestamp window and a single-use check, so a
  captured request cannot be replayed. See the replay-attack rule.

## Authorization per Endpoint
- Every token, introspection, revocation, and management endpoint authenticates
  the caller and authorizes the specific resource. Watch for an endpoint that
  fetches by a client supplied id with no owner or tenant check, the IDOR shape,
  and for a privileged endpoint left unauthenticated. See the
  insecure-direct-object-reference and missing-authorization rules.
