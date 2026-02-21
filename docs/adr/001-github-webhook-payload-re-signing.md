# ADR-001: GitHub Webhook Payload Re-signing

## Status

Accepted

## Date

2026-02-19

## Context

n8n's GitHub Trigger node has a built-in webhook lifecycle that differs from
Slack and Jira triggers. When a GitHub Trigger workflow is activated, n8n:

1. Generates a random 32-byte hex secret locally (`randomBytes(32).toString('hex')`)
2. Calls `POST /repos/{owner}/{repo}/hooks` on the GitHub API, passing that
   secret in the webhook configuration
3. Stores the secret in the workflow's `staticData` under
   `"node:{NodeName}".webhookSecret`
4. On every incoming webhook delivery, verifies the `X-Hub-Signature-256`
   header — an HMAC-SHA256 of the raw request body using that stored secret

This verification **cannot be disabled**. If the signature is missing or
invalid, n8n returns `401 Unauthorized` and the workflow does not execute.

In our middleware architecture, the event delivery path is:

```
GitHub  ──(secret A)──▶  Middleware  ──(???)──▶  n8n webhook endpoint
```

- **Secret A** is whatever the user configured on the GitHub webhook that
  points to the middleware's `/github/events` endpoint.
- **n8n's secret** is a different, randomly-generated value stored in
  `staticData`.

These are fundamentally different secrets. The `X-Hub-Signature-256` header
that arrives from GitHub was computed with Secret A, but n8n expects one
computed with its own secret. Forwarding the original signature as-is will
always fail verification.

This is further complicated in multi-workflow scenarios: if a single `push`
event matches three n8n workflows, each workflow has its own unique
`webhookSecret`. No single signature can satisfy all three.

### Why this differs from Slack and Jira

The core issue is not whether signature verification is body-dependent —
both Slack and GitHub use body-dependent HMAC signatures. The issue is
**who controls the signing secret**.

- **Slack**: The signing secret is defined in the Slack API **credential**,
  which the user configures in both the Slack app and n8n. Because the same
  secret is used on both sides, the middleware can forward the raw body with
  the original `X-Slack-Signature` and `X-Slack-Request-Timestamp` headers
  as-is, and n8n validates the signature correctly. The secret is
  user-controlled and consistent across all Slack trigger nodes that share
  the credential.
- **Jira**: n8n's Jira Trigger uses URL-embedded authentication (query
  parameters on the webhook URL). Since the auth token is part of the URL
  itself — not derived from the body — the middleware just forwards to the
  correct URL and the authentication passes through transparently.

GitHub is different because n8n **auto-generates a unique random secret per
trigger node** and stores it in `staticData`. The user has no control over
this secret and cannot configure it to match. When the middleware receives
events signed with the user's GitHub webhook secret, it cannot forward that
signature as-is because n8n expects one computed with its own internally
generated secret. This is further complicated in multi-workflow scenarios:
if a single event matches three n8n workflows, each has its own unique
`webhookSecret`, so a different signature is needed for each.

## Decision

The middleware **re-signs each forwarded payload per-trigger** using the
webhook secret from n8n's workflow `staticData`.

The implementation:

1. **During trigger refresh** (`fetch_github_triggers`): the `staticData`
   field is read from the n8n workflow API response. For each GitHub Trigger
   node, the secret is extracted from `staticData["node:{NodeName}"].webhookSecret`
   and stored in `GitHubTriggerConfig.webhook_secret`.

2. **During event forwarding** (`route_event`): for each matching trigger,
   `build_signed_headers()` computes `HMAC-SHA256(body, webhook_secret)` and
   sets `X-Hub-Signature-256: sha256={hex_digest}` on the forwarded request.
   This replaces any original signature from GitHub.

3. **If no secret is available** (e.g. workflow was never activated, or
   `staticData` is empty): the event is forwarded without re-signing and n8n
   will reject it. This is logged as a warning.

## Consequences

### Positive

- GitHub Trigger workflows execute correctly when events are routed through
  the middleware, matching the same behaviour as if GitHub delivered directly
  to n8n.
- Multiple workflows with different secrets can all receive the same event,
  each with a correctly signed payload.
- The periodic trigger refresh picks up secret rotations automatically (e.g.
  when a workflow is deactivated and reactivated, generating a new secret).

### Negative

- The middleware must have read access to workflow `staticData` via the n8n
  API, which contains sensitive cryptographic material.
- There is a brief window after workflow activation (before the next trigger
  refresh) where the middleware may not have the latest secret. Events
  forwarded during this window will be rejected by n8n.

### Neutral

- The original `X-Hub-Signature-256` from GitHub is discarded. Inbound
  signature verification (validating that events actually originate from
  GitHub) is handled separately via the `GITHUB_WEBHOOK_SECRET` env var.
  See [ADR-002](002-inbound-webhook-signature-verification.md).
