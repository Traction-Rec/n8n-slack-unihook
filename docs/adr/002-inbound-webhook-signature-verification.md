# ADR-002: Inbound Webhook Signature Verification

## Status

Accepted

## Date

2026-02-19

## Context

External webhook providers (GitHub, Jira/Atlassian) support signing outbound
payloads with a shared secret so that receivers can verify authenticity. Without
verification, any party that knows the Unihook endpoint URL can inject fake
events that will be routed to n8n workflows.

ADR-001 addressed the *outbound* side of GitHub's HMAC verification — re-signing
payloads with n8n's per-workflow secret so that n8n accepts them. This ADR
addresses the *inbound* side — verifying that events arriving at Unihook's
`/github/events` and `/jira/events` endpoints actually originate from the
expected provider.

### Signing standards

Both GitHub and Atlassian (Jira, Bitbucket Cloud) use the same HMAC-SHA256
pattern:

- **GitHub**: `X-Hub-Signature-256: sha256=<hex_digest>` — HMAC-SHA256 of the
  raw request body, keyed with the webhook's shared secret.
- **Atlassian**: `X-Hub-Signature: sha256=<hex_digest>` — identical algorithm,
  different header name. Documented in the
  [Bitbucket Cloud webhook docs](https://support.atlassian.com/bitbucket-cloud/docs/manage-webhooks/#Secure-webhooks).

### Why Slack is not included

n8n's Slack Trigger node does not enforce HMAC verification on incoming
webhooks. The middleware already forwards `X-Slack-Signature` and
`X-Slack-Request-Timestamp` headers as-is. Slack signature verification could
be added as a future enhancement but is not required for n8n compatibility.

## Decision

Inbound signature verification is **opt-in via environment variables**:

| Env Var | Header Verified | Service |
|---------|----------------|---------|
| `GITHUB_WEBHOOK_SECRET` | `X-Hub-Signature-256` | GitHub |
| `JIRA_WEBHOOK_SECRET` | `X-Hub-Signature` | Jira / Atlassian |

When the env var is **set**:

1. The route handler extracts the corresponding header.
2. If the header is missing, return `401 Unauthorized`.
3. Parse the `sha256=<hex>` value and compute HMAC-SHA256 of the raw body
   using the env var as the key.
4. Compare using constant-time equality (via the `hmac` crate's
   `verify_slice`).
5. If the comparison fails, return `401 Unauthorized`.
6. If valid, proceed with normal routing.

When the env var is **unset**, verification is skipped entirely and the
endpoint behaves as before — any request with a valid payload structure is
accepted. This maintains backward compatibility.

### Shared utility

Both services use identical HMAC-SHA256 verification logic (only the header
name differs). A shared `verify_hmac_sha256` function in `src/crypto.rs`
handles parsing, computation, and constant-time comparison for both.

### Relationship to outbound re-signing (GitHub only)

Inbound verification and outbound re-signing are independent concerns:

```
GitHub ──(GITHUB_WEBHOOK_SECRET)──▶ Unihook ──(per-trigger staticData secret)──▶ n8n
         ^^^^^^^^^^^^^^^^^^^^^^^^             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
         Inbound: ADR-002                     Outbound: ADR-001
```

The inbound secret is the one configured on the GitHub webhook pointing at
Unihook. The outbound secret is the one n8n generated internally when the
workflow was activated. These are always different values.

For Jira, there is no outbound re-signing — n8n's Jira Trigger does not
perform body-dependent HMAC verification (see ADR-001 for details).

## Consequences

### Positive

- Events arriving at Unihook can be verified as genuinely originating from
  the expected provider, preventing injection attacks.
- Opt-in design: no breaking change for existing deployments.
- Shared `src/crypto.rs` module is reusable for any future HMAC-based
  verification.

### Negative

- Operators must configure the same shared secret in both the external
  provider (GitHub webhook settings, Jira webhook settings) and in Unihook's
  environment.
- If the secret is rotated in the provider but not in Unihook (or vice
  versa), all events will be rejected with 401 until both sides match.

### Known Limitation: Jira `authenticateWebhook` / `httpQueryAuth`

n8n's Jira Trigger node has an optional `authenticateWebhook` parameter that,
when enabled, validates incoming requests using an `httpQueryAuth` credential
(query parameters appended to the webhook URL). Unihook does not currently
support this feature because n8n's public API does not expose decrypted
credential data — the `httpQueryAuth` name/value cannot be read at runtime.

Users with `authenticateWebhook: true` on Jira Trigger nodes should disable it.
Unihook provides its own inbound verification via `JIRA_WEBHOOK_SECRET`, which
is a stronger security mechanism (HMAC-SHA256 over the full body vs. a static
query parameter).
