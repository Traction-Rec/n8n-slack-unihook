# Unihook

A lightweight Rust service that enables multiple n8n workflows to share a single inbound webhook for Slack, Jira, and GitHub. It receives all events at one endpoint per service and intelligently routes them to matching n8n workflows based on their trigger configurations.

## The Problem

n8n's built-in trigger nodes (Slack Trigger, Jira Trigger, GitHub Trigger) create unique webhooks for each workflow. External services like Slack, Jira, and GitHub only support a single event subscription URL per app/instance, which forces organizations to:

- **Slack**: Create separate Slack apps for each workflow, manage multiple OAuth credentials, and deal with complex app approval processes
- **Jira**: Register separate webhooks in Jira for each workflow, leading to webhook sprawl and management overhead
- **GitHub**: Register separate webhooks per repository per workflow, causing webhook sprawl across repositories

This is administratively unworkable for organizations with multiple event-triggered workflows.

## The Solution

Unihook acts as a router between external services and n8n:

1. **Single Webhook**: Register one URL per service (Slack, Jira, GitHub)
2. **Dynamic Discovery**: Automatically discovers n8n workflows with matching triggers via the n8n API
3. **Smart Routing**: Forwards events only to workflows whose trigger configuration matches the event
4. **Zero Execution Waste**: Events that don't match any trigger never reach n8n

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Slack Events   │────▶│                  │────▶│  n8n Workflow A │
│      API        │     │                  │────▶│  n8n Workflow B │
└─────────────────┘     │                  │     └─────────────────┘
                        │                  │
┌─────────────────┐     │     Unihook      │     ┌─────────────────┐
│  Jira Webhooks  │────▶│     Router       │────▶│  n8n Workflow C │
│                 │     │                  │────▶│  n8n Workflow D │
└─────────────────┘     │                  │     └─────────────────┘
                        │                  │
┌─────────────────┐     │                  │     ┌─────────────────┐
│ GitHub Webhooks │────▶│                  │────▶│  n8n Workflow E │
│                 │     │                  │────▶│  n8n Workflow F │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                              │
                              ▼
                        ┌──────────────────┐
                        │   n8n API        │
                        │ (discover        │
                        │  triggers)       │
                        └──────────────────┘
```

## Quick Start

### Prerequisites

- Docker and Docker Compose (recommended)
- OR Rust 1.86+ for local development
- n8n instance with API access enabled
- n8n API key

### Using Docker Compose

1. Clone the repository:

```bash
git clone https://github.com/your-org/n8n-unihook.git
cd n8n-unihook
```

2. Create a `.env` file:

```bash
# Required
N8N_API_KEY=your-n8n-api-key

# Optional (defaults shown)
N8N_API_URL=http://n8n:5678
REFRESH_INTERVAL_SECS=60
RUST_LOG=n8n_unihook=info

# Path to the SQLite database used for webhook secrets & trigger metadata
# DATABASE_PATH=unihook.db

# Inbound webhook signature verification (optional but recommended for GitHub)
# Set this to the shared secret configured in your GitHub webhook settings
# GITHUB_WEBHOOK_SECRET=your-github-webhook-secret
```

3. Start the service:

```bash
docker-compose up -d
```

### Using Docker

```bash
docker build -t n8n-unihook .

docker run -d \
  --name n8n-unihook \
  -p 3000:3000 \
  -e N8N_API_KEY=your-n8n-api-key \
  -e N8N_API_URL=http://your-n8n-host:5678 \
  n8n-unihook
```

### Local Development

```bash
# Set environment variables
export N8N_API_KEY=your-n8n-api-key
export N8N_API_URL=http://localhost:5678

# Build and run
cargo run
```

## Configuration

| Environment Variable | Required | Default | Description |
|---------------------|----------|---------|-------------|
| `N8N_API_KEY` | Yes | - | Your n8n API key |
| `N8N_API_URL` | No | `http://localhost:5678` | n8n instance URL |
| `LISTEN_ADDR` | No | `0.0.0.0:3000` | Address to bind the HTTP server |
| `REFRESH_INTERVAL_SECS` | No | `60` | How often to refresh trigger configs |
| `N8N_ENDPOINT_WEBHOOK` | No | `webhook` | n8n production webhook path segment |
| `N8N_ENDPOINT_WEBHOOK_TEST` | No | `webhook-test` | n8n test webhook path segment |
| `GITHUB_WEBHOOK_SECRET` | No | - | Shared secret for verifying inbound GitHub webhooks (HMAC-SHA256 via `X-Hub-Signature-256`) |
| `DATABASE_PATH` | No | `unihook.db` | Path to SQLite database for webhook secrets & trigger metadata (use `:memory:` for in-memory) |
| `RUST_LOG` | No | `n8n_unihook=info` | Log level |

## Setting Up Slack

1. **Create or configure your Slack App** at [api.slack.com/apps](https://api.slack.com/apps)

2. **Enable Event Subscriptions**:
   - Go to "Event Subscriptions"
   - Toggle "Enable Events" to On
   - Set the Request URL to: `https://your-domain.com/slack/events`
   - Slack will send a verification challenge — Unihook handles this automatically

3. **Subscribe to Events**:
   - Add the bot events your workflows need:
     - `message.channels` — New messages in public channels
     - `app_mention` — When your bot is @mentioned
     - `reaction_added` — Reactions added to messages
     - `file_shared` — Files shared in channels
     - `channel_created` — New channels created
     - `team_join` — New users joining the workspace

4. **Install the App** to your workspace

### Slack Routing

Unihook queries the n8n API to discover workflows with Slack Trigger nodes. For each trigger, it extracts:

- **Event type** (message, reaction, mention, etc.)
- **Channel filter** (specific channels or workspace-wide)
- **Watch Whole Workspace** setting

When an event arrives:

1. Extract the event type and channel from the Slack payload
2. Match against all discovered triggers
3. Forward to workflows where:
   - Event type matches, AND
   - Channel matches (or trigger watches whole workspace)

#### Slack Event Type Mapping

| Slack Event | n8n Trigger Setting |
|-------------|---------------------|
| `message` | "New Message Posted to Channel" |
| `app_mention` | "Bot/App Mention" |
| `reaction_added` | "Reaction Added" |
| `file_shared` | "File Shared" |
| `file_public` | "File Made Public" |
| `channel_created` | "New Public Channel Created" |
| `team_join` | "New User Created" |
| `*` | "Any Event" |

## Setting Up Jira

### Important: n8n's Automatic Webhook Registration

> **You need to understand this before setting up Jira workflows.**
>
> n8n's Jira Trigger node unconditionally calls the Jira REST API to register its own webhooks whenever a workflow is activated (and deregister them on deactivation). This is hardcoded in the node's lifecycle hooks ([`JiraTrigger.node.ts`](https://github.com/n8n-io/n8n/blob/master/packages/nodes-base/nodes/Jira/JiraTrigger.node.ts) `webhookMethods.default.checkExists/create/delete`) and there is **no environment variable or configuration option in n8n to disable it**. If these API calls fail, workflow activation fails entirely — n8n does not gracefully degrade.
>
> This creates two problems when using Unihook:
>
> 1. **Duplicate webhooks** — You register a webhook in Jira pointing at Unihook (`/jira/events`), but n8n also registers its own webhooks pointing directly at n8n, bypassing Unihook entirely.
> 2. **Activation failures** — If n8n cannot reach the Jira API (e.g. network restrictions, user permissions), workflows with Jira Trigger nodes cannot be activated at all.
>
> **The workaround** is to configure the Jira credential in n8n with a domain that does _not_ point to your real Jira instance. Instead, point it at a lightweight service that returns the minimal API responses n8n expects. This satisfies n8n's webhook registration calls without creating real webhooks in Jira or causing activation failures. Unihook handles all actual event routing — the credential is only needed to keep n8n happy.
>
> See [Jira Credential Workaround](#jira-credential-workaround) below for the exact setup.
>
> **Note:** The Slack Trigger node does _not_ have this problem — it does not call out to Slack during workflow activation, so no workaround is needed for Slack.

### Steps

1. **Register a webhook** in your Jira instance:
   - Go to **Settings → System → WebHooks** (Jira Server/Data Center) or use the Jira REST API
   - Set the URL to: `https://your-domain.com/jira/events`
   - If you use n8n's `authenticateWebhook` feature, append the same query parameter to this URL (see [Query Parameter Forwarding](#query-parameter-forwarding-jira-authenticatewebhook))
   - Select the events you want to forward (or select all)

2. **Set up the Jira credential workaround** in n8n (see [below](#jira-credential-workaround))

3. **Create n8n workflows** with Jira Trigger nodes:
   - Add a "Jira Trigger" node to your workflow
   - Configure the trigger's **Events** to match the events you want (e.g. `jira:issue_created`, `comment_created`, or `*` for all)
   - Attach the workaround Jira credential (not a real one)
   - Activate the workflow

4. **Unihook routes events** to matching workflows based on the `webhookEvent` field in the Jira payload.

### Jira Credential Workaround

Because n8n's Jira Trigger node unconditionally registers webhooks via the Jira REST API during workflow activation (see [above](#important-n8ns-automatic-webhook-registration)), you need a service that responds to those API calls. **Unihook includes built-in mock endpoints** for this purpose — no separate mock server is required.

**What n8n calls during the Jira Trigger lifecycle:**

| When | Method | Endpoint | Expected Response |
|------|--------|----------|-------------------|
| Credential validation | `GET` | `/rest/api/2/myself` | `200` with a JSON user object |
| Workflow activation | `GET` | `/rest/webhooks/1.0/webhook` | `200` with `[]` (empty array) |
| Workflow activation | `POST` | `/rest/webhooks/1.0/webhook` | `201` with a JSON webhook object containing a `self` URL |
| Workflow deactivation | `DELETE` | `/rest/webhooks/1.0/webhook/{id}` | `204` |

Unihook serves all of these endpoints natively (see [`src/routes/provider_jira.rs`](src/routes/provider_jira.rs)).

**Create the Jira credential in n8n** with its domain pointing at Unihook:

| Field | Value | Notes |
|-------|-------|-------|
| Type | `Jira Software Cloud API` | |
| Domain | `http://your-unihook-host:3000` | Points at Unihook, **not** real Jira |
| Email | `noop@example.com` | Arbitrary — the mock accepts anything |
| API Token | `noop` | Arbitrary — the mock accepts anything |

Attach this credential to your Jira Trigger nodes. When n8n activates the workflow, its webhook registration calls hit Unihook's mock endpoints and succeed silently. Unihook handles all actual event delivery from Jira.

### Jira Routing

Unihook discovers workflows with Jira Trigger nodes via the n8n API. For each trigger, it extracts:

- **Event types** — The list of Jira event types the trigger listens for (e.g. `jira:issue_created`, `comment_updated`, `*`)

When a Jira webhook event arrives at `/jira/events`:

1. Extract the `webhookEvent` field from the payload
2. Match against all discovered Jira triggers
3. Forward to workflows where the event type matches (exact match or wildcard `*`)

#### Supported Jira Event Types

| Category | Events |
|----------|--------|
| Issues | `jira:issue_created`, `jira:issue_updated`, `jira:issue_deleted` |
| Comments | `comment_created`, `comment_updated`, `comment_deleted` |
| Boards | `board_created`, `board_updated`, `board_deleted`, `board_configuration_changed` |
| Sprints | `sprint_created`, `sprint_started`, `sprint_updated`, `sprint_closed`, `sprint_deleted` |
| Projects | `project_created`, `project_updated`, `project_deleted` |
| Versions | `jira:version_created`, `jira:version_updated`, `jira:version_released`, `jira:version_unreleased`, `jira:version_moved`, `jira:version_deleted` |
| Users | `user_created`, `user_updated`, `user_deleted` |
| Worklogs | `worklog_created`, `worklog_updated`, `worklog_deleted` |
| Issue Links | `issuelink_created`, `issuelink_deleted` |
| Options | `option_voting_changed`, `option_watching_changed`, `option_unassigned_issues_changed`, `option_subtasks_changed`, `option_attachments_changed`, `option_issuelinks_changed`, `option_timetracking_changed` |
| Wildcard | `*` (matches all events) |

## Setting Up GitHub

### Important: n8n's Automatic Webhook Registration and Payload Re-signing

> **You need to understand this before setting up GitHub workflows.**
>
> Like Jira, n8n's GitHub Trigger node calls the GitHub REST API to register its own webhooks whenever a workflow is activated. This is hardcoded in the node's lifecycle hooks ([`GithubTrigger.node.ts`](https://github.com/n8n-io/n8n/blob/master/packages/nodes-base/nodes/Github/GithubTrigger.node.ts)). If these API calls fail, workflow activation fails entirely.
>
> Additionally, n8n's GitHub Trigger generates a random HMAC secret during webhook registration and verifies every incoming payload against it using the `X-Hub-Signature-256` header. **This verification cannot be disabled** — if the signature is missing or invalid, n8n returns `401 Unauthorized`.
>
> Since the user's GitHub webhook (pointing at Unihook) uses a different secret than the one n8n generated, the original signature from GitHub won't pass n8n's verification. Unihook solves this by **re-signing each forwarded payload** with n8n's per-workflow secret. When using the [credential workaround](#github-credential-workaround), the secret is captured at webhook registration time and stored in Unihook's SQLite database. Otherwise, it falls back to reading the secret from the workflow's `staticData` via the n8n API.
>
> See [ADR-001: GitHub Webhook Payload Re-signing](docs/adr/001-github-webhook-payload-re-signing.md) for the full technical rationale.
>
> **The workaround** for webhook registration is the same pattern as Jira: point the GitHub credential in n8n at a mock service instead of real GitHub.
>
> **Note:** The Slack Trigger node does _not_ have this problem — it does not call out to Slack during workflow activation, so no workaround is needed for Slack.

### Steps

1. **Create a webhook** on your GitHub repository (or organisation):
   - Go to **Settings → Webhooks → Add webhook**
   - Set the Payload URL to: `https://your-domain.com/github/events`
   - Set Content type to `application/json`
   - **(Recommended)** Set a secret — Unihook can verify inbound signatures when `GITHUB_WEBHOOK_SECRET` is set (see [Inbound Signature Verification](#inbound-signature-verification))
   - Select the events you want to forward (or select "Send me everything")

2. **Set up the GitHub credential workaround** in n8n (see [below](#github-credential-workaround))

3. **Create n8n workflows** with GitHub Trigger nodes:
   - Add a "GitHub Trigger" node to your workflow
   - Configure the **Owner** and **Repository** to match the repository the webhook is on
   - Configure the trigger's **Events** to match the events you want (e.g. `push`, `issues`, or `*` for all)
   - Attach the workaround GitHub credential (not a real one)
   - Activate the workflow

4. **Unihook routes events** to matching workflows based on the `X-GitHub-Event` header and the repository owner/name in the payload.

### GitHub Credential Workaround

Because n8n's GitHub Trigger node registers webhooks via the GitHub REST API during workflow activation (see [above](#important-n8ns-automatic-webhook-registration-and-payload-re-signing)), you need a service that responds to those API calls. **Unihook includes built-in mock endpoints** for this purpose — no separate mock server is required. As a bonus, Unihook's GitHub mock intercepts the HMAC `secret` that n8n generates during webhook creation and stores it in its SQLite database, enabling automatic payload re-signing without relying on n8n's `staticData`.

**What n8n calls during the GitHub Trigger lifecycle:**

| When | Method | Endpoint | Expected Response |
|------|--------|----------|-------------------|
| Credential validation | `GET` | `/user` | `200` with a JSON user object |
| Webhook check | `GET` | `/repos/{owner}/{repo}/hooks` | `200` with `[]` (empty array) |
| Webhook creation | `POST` | `/repos/{owner}/{repo}/hooks` | `201` with a JSON webhook object containing `id` |
| Webhook deletion | `DELETE` | `/repos/{owner}/{repo}/hooks/{id}` | `204` |

Unihook serves all of these endpoints natively (see [`src/routes/provider_github.rs`](src/routes/provider_github.rs)). When `POST /repos/{owner}/{repo}/hooks` is called, Unihook extracts the `webhook_id` from `config.url` and the `secret` from `config.secret`, storing both in the database for later re-signing.

**Create the GitHub credential in n8n** with its server pointing at Unihook:

| Field | Value | Notes |
|-------|-------|-------|
| Type | `GitHub API` | |
| Server | `http://your-unihook-host:3000` | Points at Unihook, **not** real GitHub |
| User | `noop` | Arbitrary — the mock accepts anything |
| Access Token | `noop` | Arbitrary — the mock accepts anything |

Attach this credential to your GitHub Trigger nodes. When n8n activates the workflow, its webhook registration calls hit Unihook's mock endpoints. Unihook captures the HMAC secret and handles all actual event delivery from GitHub, including re-signing payloads for n8n's signature verification.

### GitHub Routing

Unihook discovers workflows with GitHub Trigger nodes via the n8n API. For each trigger, it extracts:

- **Event types** — The list of GitHub event types the trigger listens for (e.g. `push`, `issues`, `*`)
- **Owner** — The repository owner (e.g. `n8n-io`)
- **Repository** — The repository name (e.g. `n8n`)
- **Webhook secret** — The HMAC secret used for re-signing (see [ADR-003](docs/adr/003-provider-api-interception-and-db-backed-triggers.md)). The primary source is Unihook's provider mock endpoint, which captures the secret at webhook registration time and stores it in SQLite. If the mock endpoint was not used (e.g. the workflow was activated before adopting the credential workaround), the secret is read from n8n's `staticData` as a fallback.

When a GitHub webhook event arrives at `/github/events`:

1. Extract the event type from the `X-GitHub-Event` header
2. Extract the owner and repository from the payload
3. Match against all discovered GitHub triggers where:
   - Event type matches (exact match or wildcard `*`), AND
   - Owner matches (case-insensitive), AND
   - Repository matches (case-insensitive)
4. For each matching trigger, re-sign the payload with that workflow's webhook secret and forward

#### Supported GitHub Event Types

| Category | Events |
|----------|--------|
| Code | `push`, `create`, `delete` |
| Pull Requests | `pull_request`, `pull_request_review`, `pull_request_review_comment` |
| Issues | `issues`, `issue_comment` |
| CI/CD | `check_run`, `check_suite`, `deployment`, `deployment_status` |
| Releases | `release` |
| Repository | `repository`, `repository_import`, `repository_vulnerability_alert`, `public`, `fork`, `star`, `watch` |
| Organisation | `organization`, `org_block`, `membership`, `member`, `team`, `team_add` |
| GitHub Apps | `github_app_authorization`, `installation`, `installation_repositories` |
| Other | `commit_comment`, `deploy_key`, `gollum`, `label`, `marketplace_purchase`, `milestone`, `page_build`, `project`, `project_card`, `project_column`, `security_advisory`, `status` |
| Special | `ping` (handled automatically — acknowledged but not routed) |
| Wildcard | `*` (matches all events) |

## Inbound Signature Verification

Unihook supports optional HMAC-SHA256 verification of incoming webhook payloads. When enabled, events that fail verification are rejected with `401 Unauthorized` before any routing occurs.

| Service | Env Var | Header Verified | Signing Standard |
|---------|---------|----------------|-----------------|
| GitHub | `GITHUB_WEBHOOK_SECRET` | `X-Hub-Signature-256` | [GitHub webhook security](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries) |

**How it works**: GitHub computes `HMAC-SHA256(body, secret)` and sends it as `sha256=<hex_digest>` in the `X-Hub-Signature-256` header. Unihook recomputes the HMAC using the configured env var and compares using constant-time equality.

**Opt-in**: If the env var is not set, verification is skipped entirely and the endpoint accepts any well-formed request (backward-compatible with existing deployments).

> **Note**: Inbound verification is independent of GitHub's outbound re-signing (see [ADR-001](docs/adr/001-github-webhook-payload-re-signing.md)). The inbound secret is the one you configure on the webhook pointing at Unihook; the outbound secret is the one n8n generates internally.

See [ADR-002: Inbound Webhook Signature Verification](docs/adr/002-inbound-webhook-signature-verification.md) for the full technical rationale.

### Query Parameter Forwarding (Jira `authenticateWebhook`)

n8n's Jira Trigger node has an optional `authenticateWebhook` parameter that validates incoming requests using an `httpQueryAuth` credential — a query parameter appended to the webhook URL.

Unihook supports this transparently by forwarding any query parameters from the inbound Jira request URL to the n8n webhook URL. To use it:

1. Enable `authenticateWebhook` on your Jira Trigger node in n8n and configure the `httpQueryAuth` credential (e.g. name=`secret`, value=`abc123`).
2. When registering your Jira webhook, append the same query parameter to the Unihook URL:
   `https://your-domain.com/jira/events?secret=abc123`
3. Jira sends events to the URL with the query parameter. Unihook captures it and appends it to the n8n webhook URL when forwarding, so n8n's credential validation passes.

No additional environment variables are required.

## API Endpoints

### Event Ingestion (external services → n8n)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/slack/events` | POST | Receives Slack events (configure in Slack app) |
| `/jira/events` | POST | Receives Jira webhook events (configure in Jira) |
| `/github/events` | POST | Receives GitHub webhook events (configure in GitHub) |
| `/health` | GET | Health check — reports loaded trigger counts |

### Provider API Mock (intercepting n8n → provider calls)

These endpoints are served by Unihook so that n8n's trigger nodes can complete their webhook lifecycle without connecting to real external services. Point n8n credentials at Unihook's host to use them (see [Jira Credential Workaround](#jira-credential-workaround) and [GitHub Credential Workaround](#github-credential-workaround)).

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/user` | GET | GitHub credential validation — returns a mock user |
| `/repos/{owner}/{repo}/hooks` | GET | GitHub webhook check — returns empty array |
| `/repos/{owner}/{repo}/hooks` | POST | GitHub webhook creation — captures HMAC secret in SQLite |
| `/repos/{owner}/{repo}/hooks/{id}` | DELETE | GitHub webhook deletion — removes secret from SQLite |
| `/rest/api/2/myself` | GET | Jira credential validation — returns a mock user |
| `/rest/webhooks/1.0/webhook` | GET | Jira webhook check — returns empty array |
| `/rest/webhooks/1.0/webhook` | POST | Jira webhook creation — returns a valid webhook object |
| `/rest/webhooks/1.0/webhook/{id}` | DELETE | Jira webhook deletion — returns 204 |

## Reverse Proxy Setup (nginx example)

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    # SSL configuration...

    location /slack/events {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /jira/events {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /github/events {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Integration Testing

### Running Tests

```bash
# Full test run (starts Docker, runs tests, stops Docker)
./scripts/run-integration-tests.sh

# Keep Docker running after tests (useful for debugging)
./scripts/run-integration-tests.sh --keep-running

# Skip Docker startup (when containers are already running)
./scripts/run-integration-tests.sh --skip-docker

# Run specific tests
./scripts/run-integration-tests.sh --filter test_jira
```

### Provider API Mock Endpoints

The integration test environment uses Unihook's built-in provider API mock endpoints (the same credential workarounds described above for [Jira](#jira-credential-workaround) and [GitHub](#github-credential-workaround)). The test setup script creates "dud" credentials in n8n with their API endpoints pointing at `http://n8n-unihook:3000` on the Docker test network. When n8n activates trigger workflows, its webhook registration calls are intercepted by Unihook, which stores any secrets (e.g. GitHub HMAC) in its SQLite database. See [`docker-compose.test.yml`](docker-compose.test.yml) and [`scripts/run-integration-tests.sh`](scripts/run-integration-tests.sh) for the implementation.

## Troubleshooting

### Events not being forwarded

1. Check the health endpoint: `curl http://localhost:3000/health`
2. Verify triggers are loaded: The health response shows `slack_triggers_loaded`, `jira_triggers_loaded`, and `github_triggers_loaded` counts
3. Check logs: `docker logs n8n-unihook`
4. Ensure workflows are **active** in n8n (inactive workflows only receive test webhook events)

### Slack verification failing

- Ensure the service is publicly accessible
- Check that `/slack/events` returns 200 for POST requests
- The service handles URL verification automatically

### Jira events not matching

- Verify the `webhookEvent` field is present in the Jira payload
- Check that the workflow's Jira Trigger node is configured for the correct event types
- Use wildcard (`*`) events during debugging to match everything

### GitHub events not matching

- Verify the `X-GitHub-Event` header is present (GitHub always sends this)
- Check that the workflow's GitHub Trigger node is configured for the correct **owner** and **repository** — these must match the repository sending events (case-insensitive)
- Check that the event type matches (e.g. the trigger listens for `push` but GitHub is sending `issues`)
- Use wildcard (`*`) events during debugging to match all event types for a given repo

### GitHub events returning 401 from n8n

- This means the payload re-signing failed or the webhook secret is stale
- If using the [credential workaround](#github-credential-workaround), secrets are captured automatically at webhook registration time — try deactivating and reactivating the workflow so n8n re-registers the webhook and Unihook captures the new secret
- If **not** using the credential workaround, ensure the workflow has been activated at least once (so n8n's `staticData` is populated with the webhook secret) and wait for the next trigger refresh cycle
- Check logs for `"No webhook secret available"` warnings

### n8n API connection issues

- Verify `N8N_API_URL` is correct and accessible from the container
- Check that your `N8N_API_KEY` has read access to workflows

## License

MIT
