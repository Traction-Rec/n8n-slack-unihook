# Unihook

A lightweight Rust service that enables multiple n8n workflows to share a single inbound webhook for Slack and Jira. It receives all events at one endpoint per service and intelligently routes them to matching n8n workflows based on their trigger configurations.

## The Problem

n8n's built-in trigger nodes (Slack Trigger, Jira Trigger) create unique webhooks for each workflow. External services like Slack and Jira only support a single event subscription URL per app/instance, which forces organizations to:

- **Slack**: Create separate Slack apps for each workflow, manage multiple OAuth credentials, and deal with complex app approval processes
- **Jira**: Register separate webhooks in Jira for each workflow, leading to webhook sprawl and management overhead

This is administratively unworkable for organizations with multiple event-triggered workflows.

## The Solution

Unihook acts as a router between external services and n8n:

1. **Single Webhook**: Register one URL per service (Slack, Jira)
2. **Dynamic Discovery**: Automatically discovers n8n workflows with matching triggers via the n8n API
3. **Smart Routing**: Forwards events only to workflows whose trigger configuration matches the event
4. **Zero Execution Waste**: Events that don't match any trigger never reach n8n

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Slack Events   │────▶│                  │────▶│  n8n Workflow A │
│      API        │     │                  │────▶│  n8n Workflow B │
└─────────────────┘     │                  │     └─────────────────┘
                        │     Unihook      │
┌─────────────────┐     │     Router       │     ┌─────────────────┐
│  Jira Webhooks  │────▶│                  │────▶│  n8n Workflow C │
│                 │     │                  │────▶│  n8n Workflow D │
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
git clone https://github.com/your-org/n8n-slack-unihook.git
cd n8n-slack-unihook
```

2. Create a `.env` file:

```bash
# Required
N8N_API_KEY=your-n8n-api-key

# Optional (defaults shown)
N8N_API_URL=http://n8n:5678
REFRESH_INTERVAL_SECS=60
RUST_LOG=n8n_slack_unihook=info
```

3. Start the service:

```bash
docker-compose up -d
```

### Using Docker

```bash
docker build -t n8n-slack-unihook .

docker run -d \
  --name n8n-slack-unihook \
  -p 3000:3000 \
  -e N8N_API_KEY=your-n8n-api-key \
  -e N8N_API_URL=http://your-n8n-host:5678 \
  n8n-slack-unihook
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
| `RUST_LOG` | No | `n8n_slack_unihook=info` | Log level |

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
> 2. **Activation failures** — If n8n cannot reach the Jira API (e.g. network restrictions, no real Jira instance), workflows with Jira Trigger nodes cannot be activated at all.
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
   - Select the events you want to forward (or select all)

2. **Set up the Jira credential workaround** in n8n (see [below](#jira-credential-workaround))

3. **Create n8n workflows** with Jira Trigger nodes:
   - Add a "Jira Trigger" node to your workflow
   - Configure the trigger's **Events** to match the events you want (e.g. `jira:issue_created`, `comment_created`, or `*` for all)
   - Attach the workaround Jira credential (not a real one)
   - Activate the workflow

4. **Unihook routes events** to matching workflows based on the `webhookEvent` field in the Jira payload.

### Jira Credential Workaround

Because n8n's Jira Trigger node unconditionally registers webhooks via the Jira REST API during workflow activation (see [above](#important-n8ns-automatic-webhook-registration)), you need a service that responds to those API calls. This can be any HTTP service that returns the expected responses for four endpoints — a minimal nginx config works well.

**What n8n calls during the Jira Trigger lifecycle:**

| When | Method | Endpoint | Expected Response |
|------|--------|----------|-------------------|
| Credential validation | `GET` | `/rest/api/2/myself` | `200` with a JSON user object |
| Workflow activation | `GET` | `/rest/webhooks/1.0/webhook` | `200` with `[]` (empty array) |
| Workflow activation | `POST` | `/rest/webhooks/1.0/webhook` | `201` with a JSON webhook object containing a `self` URL |
| Workflow deactivation | `DELETE` | `/rest/webhooks/1.0/webhook/{id}` | `204` |

**Example nginx config** (see [`tests/integration/mock-jira/nginx.conf`](tests/integration/mock-jira/nginx.conf) for a complete working example):

```nginx
server {
    listen 8080;

    # Webhook registration (GET = check existing, POST = create)
    location = /rest/webhooks/1.0/webhook {
        default_type application/json;
        if ($request_method = GET)  { return 200 '[]'; }
        if ($request_method = POST) { return 201 '{"name":"n8n-noop","url":"http://noop","events":[],"enabled":true,"self":"http://jira-mock:8080/rest/webhooks/1.0/webhook/1"}'; }
        return 200 '{}';
    }

    # Webhook deletion
    location ~ ^/rest/webhooks/1.0/webhook/.+ {
        return 204;
    }

    # Credential validation
    location = /rest/api/2/myself {
        default_type application/json;
        return 200 '{"accountId":"noop","emailAddress":"noop@example.com","displayName":"Noop","active":true}';
    }

    # Catch-all
    location / {
        default_type application/json;
        return 200 '{}';
    }
}
```

**Then create the Jira credential in n8n** with its domain pointing at this mock service:

| Field | Value | Notes |
|-------|-------|-------|
| Type | `Jira Software Cloud API` | |
| Domain | `http://your-mock-host:8080` | Points at the mock, **not** real Jira |
| Email | `noop@example.com` | Arbitrary — the mock accepts anything |
| API Token | `noop` | Arbitrary — the mock accepts anything |

Attach this credential to your Jira Trigger nodes. When n8n activates the workflow, its webhook registration calls hit the mock and succeed silently. Unihook handles all actual event delivery from Jira.

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

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/slack/events` | POST | Receives Slack events (configure in Slack app) |
| `/jira/events` | POST | Receives Jira webhook events (configure in Jira) |
| `/health` | GET | Health check — reports loaded trigger counts |

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

### Mock Jira API Server

The integration test environment includes the same [Jira credential workaround](#jira-credential-workaround) described above — a `mock-jira` nginx container runs on the Docker test network, and the test setup script creates a credential pointing at `http://mock-jira:8080`. See `tests/integration/mock-jira/nginx.conf`, `docker-compose.test.yml`, and `scripts/run-integration-tests.sh` for the implementation.

## Troubleshooting

### Events not being forwarded

1. Check the health endpoint: `curl http://localhost:3000/health`
2. Verify triggers are loaded: The health response shows `slack_triggers_loaded` and `jira_triggers_loaded` counts
3. Check logs: `docker logs n8n-slack-unihook`
4. Ensure workflows are **active** in n8n (inactive workflows only receive test webhook events)

### Slack verification failing

- Ensure the service is publicly accessible
- Check that `/slack/events` returns 200 for POST requests
- The service handles URL verification automatically

### Jira events not matching

- Verify the `webhookEvent` field is present in the Jira payload
- Check that the workflow's Jira Trigger node is configured for the correct event types
- Use wildcard (`*`) events during debugging to match everything

### n8n API connection issues

- Verify `N8N_API_URL` is correct and accessible from the container
- Check that your `N8N_API_KEY` has read access to workflows

## License

MIT
