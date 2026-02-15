# Slack Unihook

A lightweight Rust service that enables multiple n8n workflows to share a single Slack app webhook. It receives all Slack events at one endpoint and intelligently routes them to matching n8n workflows based on their trigger configurations.

## The Problem

n8n's built-in Slack Trigger node creates unique webhooks for each workflow. Since Slack apps only support a single event subscription URL, this forces organizations to:

- Create separate Slack apps for each workflow
- Manage multiple OAuth credentials
- Deal with complex app approval processes for each workflow

This is administratively unworkable for organizations with multiple Slack-triggered workflows.

## The Solution

Slack Unihook acts as a router between Slack and n8n:

1. **Single Webhook**: Register one URL in your Slack app's event subscriptions
2. **Dynamic Discovery**: Automatically discovers n8n workflows with Slack triggers via the n8n API
3. **Smart Routing**: Forwards events only to workflows that match the event's criteria
4. **Zero Execution Waste**: Events that don't match any trigger never reach n8n

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Slack Events   │────▶│  Slack Unihook   │────▶│  n8n Workflow A │
│      API        │     │     Router       │────▶│  n8n Workflow B │
└─────────────────┘     └──────────────────┘────▶│  n8n Workflow C │
                              │                  └─────────────────┘
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
| `RUST_LOG` | No | `n8n_slack_unihook=info` | Log level |

## Setting Up Your Slack App

1. **Create or configure your Slack App** at [api.slack.com/apps](https://api.slack.com/apps)

2. **Enable Event Subscriptions**:
   - Go to "Event Subscriptions"
   - Toggle "Enable Events" to On
   - Set the Request URL to: `https://your-domain.com/slack/events`
   - Slack will send a verification challenge - Unihook handles this automatically

3. **Subscribe to Events**:
   - Add the bot events your workflows need:
     - `message.channels` - New messages in public channels
     - `app_mention` - When your bot is @mentioned
     - `reaction_added` - Reactions added to messages
     - `file_shared` - Files shared in channels
     - `channel_created` - New channels created
     - `team_join` - New users joining the workspace

4. **Install the App** to your workspace

## How Routing Works

Slack Unihook queries the n8n API to discover workflows with Slack Trigger nodes. For each trigger, it extracts:

- **Event type** (message, reaction, mention, etc.)
- **Channel filter** (specific channels or workspace-wide)
- **Watch Whole Workspace** setting

When an event arrives:

1. Extract the event type and channel from the Slack payload
2. Match against all discovered triggers
3. Forward to workflows where:
   - Event type matches, AND
   - Channel matches (or trigger watches whole workspace)

### Event Type Mapping

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

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/slack/events` | POST | Receives Slack events (configure in Slack app) |
| `/health` | GET | Health check endpoint |

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
}
```

## Troubleshooting

### Events not being forwarded

1. Check the health endpoint: `curl http://localhost:3000/health`
2. Verify triggers are loaded: The health response shows `triggers_loaded` count
3. Check logs: `docker logs n8n-slack-unihook`
4. Ensure workflows are **active** in n8n (inactive workflows are ignored)

### Slack verification failing

- Ensure the service is publicly accessible
- Check that `/slack/events` returns 200 for POST requests
- The service handles URL verification automatically

### n8n API connection issues

- Verify `N8N_API_URL` is correct and accessible from the container
- Check that your `N8N_API_KEY` has read access to workflows

## License

MIT
