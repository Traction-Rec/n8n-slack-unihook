# ADR-003: Provider API Interception and DB-Backed Trigger Storage

## Status

Accepted

## Date

2026-02-22

## Context

### The `staticData` problem

ADR-001 described how Unihook re-signs GitHub webhook payloads using the HMAC
secret that n8n auto-generates during workflow activation. The secret was
originally retrieved from the workflow's `staticData` via the n8n API during
periodic trigger refreshes.

This approach has a critical limitation: **`staticData` is not populated until
a workflow has been activated at least once**, and even then, the field is only
written after n8n's webhook lifecycle hooks complete. During "test" event
delivery (the "Listen for Test Event" flow in the n8n editor), n8n uses a
separate test webhook registration that generates a *new* ephemeral secret, but
this secret is never written to `staticData`. As a result, Unihook cannot
re-sign payloads for test event deliveries, causing them to fail with
`401 Unauthorized`.

### The external mock problem

To allow n8n trigger nodes (GitHub Trigger, Jira Trigger) to activate in a
test environment without real external accounts, a separate nginx container
(`mock-apis`) served static responses to the webhook registration API calls
that n8n makes during activation. While this worked, the static responses
discarded all request data — notably the HMAC secret that n8n sends in the
GitHub `POST /repos/{owner}/{repo}/hooks` body. This meant the mock could
not capture or forward the secret to Unihook.

### Combining the solutions

Rather than maintaining a separate mock server and relying on `staticData`
for secrets, Unihook can **serve the provider API endpoints itself**,
intercepting the webhook registration requests that n8n makes. This lets
Unihook capture secrets at registration time — before and independently of
`staticData` — and store them in a local database for immediate use during
event routing.

Moving trigger metadata to the same database creates a single source of
truth and eliminates the in-memory `Vec<TriggerConfig>` that was previously
rebuilt from scratch on every refresh cycle.

## Decision

### 1. Built-in provider API mock endpoints

Unihook serves the API endpoints that n8n's trigger nodes call during their
webhook lifecycle. These routes are mounted at the top level of the HTTP
router alongside the existing event ingestion routes:

| Provider | Endpoints | Source |
|----------|-----------|--------|
| GitHub | `GET/POST /repos/{owner}/{repo}/hooks`, `DELETE /repos/{owner}/{repo}/hooks/{id}`, `GET /user` | `src/routes/provider_github.rs` |
| Jira | `GET/POST /rest/webhooks/1.0/webhook`, `DELETE /rest/webhooks/1.0/webhook/{id}`, `GET /rest/api/2/myself` | `src/routes/provider_jira.rs` |

The GitHub `POST` handler extracts the `webhook_id` from the `config.url`
path (the second-to-last URL segment) and the HMAC `secret` from
`config.secret`, storing both in the database. This captures secrets from
both production activations and test-mode registrations.

Jira does not use HMAC secrets, so its mock simply returns valid responses.

### 2. SQLite database for persistent state

A SQLite database (via `rusqlite` with the `bundled` feature) stores:

- **`webhook_secrets`** — maps `(webhook_id, provider)` to an HMAC `secret`
  and a database-generated `id` (used as the `hook_id` returned in API
  responses). Keyed by the n8n webhook ID extracted from the registration URL.

- **`github_triggers`**, **`jira_triggers`**, **`slack_triggers`** — trigger
  metadata previously held in memory. Each row stores the webhook ID, workflow
  ID, and provider-specific fields (owner/repo, event types, webhook URLs,
  etc.). Written during the periodic trigger sync and read during event
  routing.

The database path is configurable via the `DATABASE_PATH` environment
variable (default: `unihook.db`). Setting it to `:memory:` creates an
in-memory database for unit tests.

### 3. Correlation via `webhook_id`

The `webhook_id` (the unique identifier n8n assigns to each trigger node's
webhook) is the correlation key between:

- The webhook secret captured at registration time
- The trigger metadata discovered via the n8n workflow API

Full webhook URLs are **not** stored in the secrets table. Instead, they are
reconstructed at routing time from the `webhook_id` and the
`N8N_ENDPOINT_WEBHOOK` / `N8N_ENDPOINT_WEBHOOK_TEST` environment variables.

### 4. Trigger sync writes to DB, routing reads from DB

The periodic trigger refresh task (`refresh_triggers`) now calls
`db.sync_{provider}_triggers()`, which replaces all rows for the provider in
a single transaction. The event routing code reads triggers from the database
via `db.query_{provider}_triggers()`. For GitHub, this query joins with the
`webhook_secrets` table to attach the HMAC secret inline, avoiding a separate
lookup.

### 5. Credential configuration

Users (and the integration test script) create n8n credentials with their
API endpoint pointing at Unihook instead of the real external service:

| Credential | Field | Value |
|------------|-------|-------|
| GitHub API | Server | `http://<unihook-host>:3000` |
| Jira Software Cloud API | Domain | `http://<unihook-host>:3000` |

This directs n8n's webhook lifecycle calls to Unihook's mock endpoints.

## Consequences

### Positive

- **Secrets captured at registration time** — eliminates the dependency on
  `staticData` and the timing gap described in ADR-001. Test-mode secrets are
  captured the moment n8n registers the test webhook.
- **Single container** — no separate nginx mock is needed, simplifying
  deployment and the integration test environment.
- **Persistent state** — trigger metadata and secrets survive process
  restarts. The periodic sync updates them, but routing is not blocked by a
  refresh cycle.
- **Single source of truth** — trigger configs and secrets live in one
  database, joinable for efficient lookups.

### Negative

- **SQLite dependency** — adds `rusqlite` (with `bundled` feature, which
  compiles SQLite from source) to the build. This increases compile time
  slightly but avoids requiring a system SQLite library.
- **Credential reconfiguration** — existing users who previously pointed
  credentials at an external mock must update them to point at Unihook.
  New users benefit from a simpler setup.

### Neutral

- **`staticData` still works as a fallback** — the trigger sync continues
  to extract secrets from `staticData` when available (via
  `upsert_webhook_secret_fallback`), so workflows activated before this
  change continue to work without re-activation.
- **Event types not stored in `webhook_secrets`** — event filtering metadata
  is pulled from the trigger sync, keeping the secrets table minimal.
