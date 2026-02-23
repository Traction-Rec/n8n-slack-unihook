use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use std::sync::Arc;
use tracing::{debug, info, warn};

use super::AppState;

// ── Jira API mock endpoints ─────────────────────────────────────────────

/// `GET /rest/webhooks/1.0/webhook` — n8n calls this to check for existing hooks.
///
/// We always return an empty array, telling n8n there are no existing Jira
/// webhooks so it proceeds to create one via POST.
pub async fn list_webhooks() -> impl IntoResponse {
    debug!("Jira mock: GET /rest/webhooks/1.0/webhook -> []");
    Json(serde_json::json!([]))
}

/// `POST /rest/webhooks/1.0/webhook` — n8n calls this to register a webhook.
///
/// The request body looks like:
/// ```json
/// {
///   "name": "n8n: <webhook-url>",
///   "url": "http://n8n:5678/webhook/<webhookId>/webhook",
///   "events": ["jira:issue_created"],
///   "filters": {},
///   "excludeBody": false
/// }
/// ```
///
/// Jira doesn't use HMAC secrets — authentication is done via the Jira API
/// credential itself. We simply return a valid webhook object so n8n considers
/// the registration successful. The `self` URL in the response is used by n8n
/// to extract the webhook ID for DELETE operations during deactivation.
pub async fn create_webhook(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let url = body.get("url").and_then(|v| v.as_str()).unwrap_or("");
    let events = body.get("events").cloned().unwrap_or(serde_json::json!([]));
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("n8n-mock");

    info!(
        name = %name,
        url = %url,
        "Jira mock: captured webhook registration"
    );

    // Trigger an immediate sync so the jira_triggers table is populated
    // right away — otherwise events arriving before the next periodic refresh
    // would find no matching trigger rows.
    let jira_router = state.jira_router.clone();
    tokio::spawn(async move {
        if let Err(e) = jira_router.refresh_triggers().await {
            warn!(error = %e, "Jira mock: failed to refresh triggers after webhook registration");
        }
    });

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "name": name,
            "url": url,
            "events": events,
            "enabled": true,
            "self": format!("http://localhost/rest/webhooks/1.0/webhook/1")
        })),
    )
}

/// `DELETE /rest/webhooks/1.0/webhook/:id` — n8n calls this to deregister.
///
/// Returns 204 No Content.
pub async fn delete_webhook(Path(id): Path<String>) -> impl IntoResponse {
    info!(id = %id, "Jira mock: deleted webhook");
    StatusCode::NO_CONTENT
}

/// `GET /rest/api/2/myself` — n8n calls this to validate Jira credentials.
///
/// Returns a minimal mock user object.
pub async fn get_myself() -> impl IntoResponse {
    debug!("Jira mock: GET /rest/api/2/myself -> mock user");
    Json(serde_json::json!({
        "accountId": "unihook-mock",
        "emailAddress": "unihook@example.com",
        "displayName": "Unihook Mock Jira User",
        "active": true
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::db::Database;
    use crate::n8n::N8nClient;
    use crate::router::{GitHubRouter, JiraRouter, SlackRouter};
    use axum::response::IntoResponse;

    /// Build a test `AppState` backed by an in-memory SQLite database.
    fn test_state() -> Arc<AppState> {
        let db = Arc::new(Database::open(":memory:").unwrap());
        let config = Arc::new(Config {
            n8n_api_url: "http://localhost:5678".to_string(),
            n8n_api_key: "test-key".to_string(),
            listen_addr: "0.0.0.0:3000".to_string(),
            refresh_interval_secs: 600,
            n8n_endpoint_webhook: "webhook".to_string(),
            n8n_endpoint_webhook_test: "webhook-test".to_string(),
            github_webhook_secret: None,
            database_path: ":memory:".to_string(),
        });
        let n8n_client = Arc::new(N8nClient::new(config.clone()));
        let slack_router = Arc::new(SlackRouter::new(
            config.clone(),
            n8n_client.clone(),
            db.clone(),
        ));
        let jira_router = Arc::new(JiraRouter::new(
            config.clone(),
            n8n_client.clone(),
            db.clone(),
        ));
        let github_router = Arc::new(GitHubRouter::new(
            config.clone(),
            n8n_client.clone(),
            db.clone(),
        ));

        Arc::new(AppState {
            slack_router,
            jira_router,
            github_router,
            config,
            db,
        })
    }

    // ── create_webhook handler tests ────────────────────────────────────

    #[tokio::test]
    async fn test_create_webhook_returns_201() {
        let state = test_state();

        let body = serde_json::json!({
            "name": "n8n: http://n8n:5678/webhook/jira-wh-1/webhook",
            "url": "http://n8n:5678/webhook/jira-wh-1/webhook",
            "events": ["jira:issue_created"],
            "filters": {},
            "excludeBody": false
        });

        let response = create_webhook(State(state), Json(body))
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_create_webhook_with_minimal_body() {
        let state = test_state();

        // Minimal body — url, name, events all optional
        let body = serde_json::json!({});

        let response = create_webhook(State(state), Json(body))
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::CREATED);
    }

    // ── delete_webhook handler tests ────────────────────────────────────

    #[tokio::test]
    async fn test_delete_webhook_returns_204() {
        let response = delete_webhook(Path("42".to_string())).await.into_response();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_delete_webhook_nonexistent_returns_204() {
        let response = delete_webhook(Path("nonexistent".to_string()))
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    // ── list_webhooks and get_myself handler tests ──────────────────────

    #[tokio::test]
    async fn test_list_webhooks_returns_200() {
        let response = list_webhooks().await.into_response();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_myself_returns_200() {
        let response = get_myself().await.into_response();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
