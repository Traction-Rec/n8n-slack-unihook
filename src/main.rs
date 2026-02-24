mod config;
mod crypto;
mod db;
mod github;
mod jira;
mod n8n;
mod router;
mod routes;
mod slack;

use axum::{Router as AxumRouter, routing::get, routing::post};
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::Config;
use crate::db::Database;
use crate::n8n::N8nClient;
use crate::router::{GitHubRouter, JiraRouter, SlackRouter};
use crate::routes::{
    AppState, handle_github_event, handle_jira_event, handle_slack_event, health_check,
    provider_github, provider_jira,
};

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "n8n_unihook=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = match Config::from_env() {
        Ok(c) => Arc::new(c),
        Err(e) => {
            error!(error = %e, "Failed to load configuration");
            eprintln!("Error: Failed to load configuration: {}", e);
            eprintln!("\nRequired environment variables:");
            eprintln!("  N8N_API_KEY     - Your n8n API key");
            eprintln!("\nOptional environment variables:");
            eprintln!(
                "  N8N_API_URL              - n8n instance URL (default: http://localhost:5678)"
            );
            eprintln!("  LISTEN_ADDR              - Address to bind (default: 0.0.0.0:3000)");
            eprintln!("  REFRESH_INTERVAL_SECS    - Trigger refresh interval (default: 60)");
            eprintln!("  N8N_ENDPOINT_WEBHOOK     - Production webhook path (default: webhook)");
            eprintln!("  N8N_ENDPOINT_WEBHOOK_TEST - Test webhook path (default: webhook-test)");
            eprintln!(
                "  GITHUB_WEBHOOK_SECRET    - Shared secret for GitHub inbound HMAC verification"
            );
            eprintln!("  DATABASE_PATH            - Path to SQLite database (default: unihook.db)");
            std::process::exit(1);
        }
    };

    info!(
        n8n_api_url = %config.n8n_api_url,
        listen_addr = %config.listen_addr,
        refresh_interval_secs = config.refresh_interval_secs,
        database_path = %config.database_path,
        "Starting Unihook router"
    );

    // Open the SQLite database
    let db = match Database::open(&config.database_path) {
        Ok(db) => Arc::new(db),
        Err(e) => {
            error!(error = %e, path = %config.database_path, "Failed to open database");
            eprintln!(
                "Error: Failed to open database at {}: {}",
                config.database_path, e
            );
            std::process::exit(1);
        }
    };

    // Create shared n8n API client
    let n8n_client = Arc::new(N8nClient::new(config.clone()));

    // Create the Slack router (event routing engine)
    let slack_router = Arc::new(SlackRouter::new(
        config.clone(),
        n8n_client.clone(),
        db.clone(),
    ));

    // Create the Jira router (event routing engine)
    let jira_router = Arc::new(JiraRouter::new(
        config.clone(),
        n8n_client.clone(),
        db.clone(),
    ));

    // Create the GitHub router (event routing engine)
    let github_router = Arc::new(GitHubRouter::new(
        config.clone(),
        n8n_client.clone(),
        db.clone(),
    ));

    // Start background tasks that refresh trigger configurations
    slack_router.clone().start_refresh_task();
    jira_router.clone().start_refresh_task();
    github_router.clone().start_refresh_task();

    // Create application state
    let app_state = Arc::new(AppState {
        slack_router,
        jira_router,
        github_router,
        config: config.clone(),
        db: db.clone(),
    });

    // Build the HTTP router
    let app = AxumRouter::new()
        // ── Inbound event routes (from external providers to n8n) ────────
        .route("/slack/events", post(handle_slack_event))
        .route("/jira/events", post(handle_jira_event))
        .route("/github/events", post(handle_github_event))
        // ── Provider API mock routes (intercepting n8n → provider calls) ─
        // GitHub API mock
        .route(
            "/repos/{owner}/{repo}/hooks",
            get(provider_github::list_hooks).post(provider_github::create_hook),
        )
        .route(
            "/repos/{owner}/{repo}/hooks/{hook_id}",
            axum::routing::delete(provider_github::delete_hook),
        )
        .route("/user", get(provider_github::get_user))
        // Jira API mock
        .route(
            "/rest/webhooks/1.0/webhook",
            get(provider_jira::list_webhooks).post(provider_jira::create_webhook),
        )
        .route(
            "/rest/webhooks/1.0/webhook/{id}",
            axum::routing::delete(provider_jira::delete_webhook),
        )
        .route("/rest/api/2/myself", get(provider_jira::get_myself))
        // ── Health check ─────────────────────────────────────────────────
        .route("/health", get(health_check))
        .with_state(app_state);

    // Start the server
    let listener = tokio::net::TcpListener::bind(&config.listen_addr)
        .await
        .expect("Failed to bind to address");

    info!(address = %config.listen_addr, "Server listening");
    info!("Slack webhook URL: http://<your-host>/slack/events");
    info!("Jira webhook URL: http://<your-host>/jira/events");
    info!("GitHub webhook URL: http://<your-host>/github/events");
    info!("Provider API mock: http://<your-host>/repos/:owner/:repo/hooks (GitHub)");
    info!("Provider API mock: http://<your-host>/rest/webhooks/1.0/webhook (Jira)");

    axum::serve(listener, app)
        .await
        .expect("Server failed to start");
}
