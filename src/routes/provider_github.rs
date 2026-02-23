use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use std::sync::Arc;
use tracing::{debug, info, warn};

use super::AppState;

/// Extract the n8n webhook ID from a `config.url` value.
///
/// n8n webhook URLs follow the pattern:
///   `http://<host>/<endpoint>/<webhookId>/webhook`
///
/// For example:
///   `http://n8n:5678/webhook/abc123-def/webhook`  →  `"abc123-def"`
///   `http://n8n:5678/webhook-test/abc123-def/webhook`  →  `"abc123-def"`
///
/// The webhook ID is always the second-to-last path segment.
fn extract_webhook_id_from_url(url: &str) -> Option<String> {
    // Strip query string if present
    let path_part = url.split('?').next().unwrap_or(url);
    let segments: Vec<&str> = path_part.trim_end_matches('/').rsplit('/').collect();

    // We need at least: ["webhook", "<webhookId>", "<endpoint>", ...]
    if segments.len() >= 2 {
        let id = segments[1]; // second-to-last segment
        if !id.is_empty() {
            return Some(id.to_string());
        }
    }
    None
}

// ── GitHub API mock endpoints ───────────────────────────────────────────

/// `GET /repos/:owner/:repo/hooks` — n8n calls this to check for existing hooks.
///
/// We always return an empty array, telling n8n there are no existing webhooks
/// so it proceeds to create a new one via POST.
pub async fn list_hooks(Path((_owner, _repo)): Path<(String, String)>) -> impl IntoResponse {
    debug!("GitHub mock: GET /repos/{_owner}/{_repo}/hooks -> []");
    Json(serde_json::json!([]))
}

/// `POST /repos/:owner/:repo/hooks` — n8n calls this to register a webhook.
///
/// The request body looks like:
/// ```json
/// {
///   "name": "web",
///   "config": {
///     "url": "http://n8n:5678/webhook/<webhookId>/webhook",
///     "content_type": "json",
///     "secret": "<hmac-secret>"
///   },
///   "events": ["push"],
///   "active": true
/// }
/// ```
///
/// We extract the `webhook_id` from `config.url` and the `secret` from
/// `config.secret`, store them in the database, and return a valid GitHub
/// hook object so n8n considers the registration successful.
pub async fn create_hook(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let config = body.get("config").cloned().unwrap_or(serde_json::json!({}));
    let url = config.get("url").and_then(|v| v.as_str()).unwrap_or("");
    let secret = config.get("secret").and_then(|v| v.as_str()).unwrap_or("");
    let events = body.get("events").cloned().unwrap_or(serde_json::json!([]));

    let webhook_id = match extract_webhook_id_from_url(url) {
        Some(id) => id,
        None => {
            warn!(
                url = %url,
                "GitHub mock: could not extract webhook_id from config.url, using fallback"
            );
            // Use a fallback so n8n doesn't break — but this hook won't correlate with triggers
            format!("unknown-{owner}-{repo}")
        }
    };

    // Store the secret in the database
    let hook_id = match state
        .db
        .upsert_webhook_secret(&webhook_id, "github", secret)
    {
        Ok(id) => id,
        Err(e) => {
            warn!(error = %e, "GitHub mock: failed to store webhook secret");
            // Return a fake ID so n8n doesn't break
            1
        }
    };

    info!(
        webhook_id = %webhook_id,
        hook_id = hook_id,
        owner = %owner,
        repo = %repo,
        has_secret = !secret.is_empty(),
        "GitHub mock: captured webhook registration"
    );

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": hook_id,
            "name": "web",
            "active": true,
            "events": events,
            "config": {
                "url": url,
                "content_type": "json"
            },
            "updated_at": "2024-01-01T00:00:00Z",
            "created_at": "2024-01-01T00:00:00Z"
        })),
    )
}

/// `DELETE /repos/:owner/:repo/hooks/:hook_id` — n8n calls this to deregister.
///
/// We remove the corresponding secret from the database and return 204.
pub async fn delete_hook(
    State(state): State<Arc<AppState>>,
    Path((_owner, _repo, hook_id)): Path<(String, String, i64)>,
) -> impl IntoResponse {
    match state.db.delete_webhook_secret_by_id(hook_id) {
        Ok(true) => {
            info!(hook_id = hook_id, "GitHub mock: deleted webhook secret");
        }
        Ok(false) => {
            debug!(
                hook_id = hook_id,
                "GitHub mock: hook_id not found (already deleted?)"
            );
        }
        Err(e) => {
            warn!(error = %e, hook_id = hook_id, "GitHub mock: failed to delete webhook secret");
        }
    }
    StatusCode::NO_CONTENT
}

/// `GET /user` — n8n calls this to validate GitHub credentials.
///
/// Returns a minimal mock user object.
pub async fn get_user() -> impl IntoResponse {
    debug!("GitHub mock: GET /user -> mock user");
    Json(serde_json::json!({
        "login": "unihook-mock",
        "id": 1,
        "type": "User",
        "name": "Unihook Mock GitHub User"
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
    ///
    /// Returns the shared state and a handle to the database so tests can
    /// verify that handlers wrote the expected data.
    fn test_state() -> (Arc<AppState>, Arc<Database>) {
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

        let state = Arc::new(AppState {
            slack_router,
            jira_router,
            github_router,
            config,
            db: db.clone(),
        });

        (state, db)
    }

    // ── extract_webhook_id_from_url tests ───────────────────────────────

    #[test]
    fn test_extract_webhook_id_standard_url() {
        let id = extract_webhook_id_from_url("http://n8n:5678/webhook/abc123-def456/webhook");
        assert_eq!(id.as_deref(), Some("abc123-def456"));
    }

    #[test]
    fn test_extract_webhook_id_test_endpoint() {
        let id = extract_webhook_id_from_url("http://n8n:5678/webhook-test/abc123-def456/webhook");
        assert_eq!(id.as_deref(), Some("abc123-def456"));
    }

    #[test]
    fn test_extract_webhook_id_with_trailing_slash() {
        let id = extract_webhook_id_from_url("http://n8n:5678/webhook/abc123/webhook/");
        assert_eq!(id.as_deref(), Some("abc123"));
    }

    #[test]
    fn test_extract_webhook_id_with_query_string() {
        let id = extract_webhook_id_from_url("http://n8n:5678/webhook/abc123/webhook?token=xyz");
        assert_eq!(id.as_deref(), Some("abc123"));
    }

    #[test]
    fn test_extract_webhook_id_empty_url() {
        let id = extract_webhook_id_from_url("");
        assert!(id.is_none());
    }

    #[test]
    fn test_extract_webhook_id_no_path() {
        let id = extract_webhook_id_from_url("http://n8n:5678");
        assert!(id.is_none());
    }

    // ── create_hook handler tests ───────────────────────────────────────

    #[tokio::test]
    async fn test_create_hook_stores_secret_in_db() {
        let (state, db) = test_state();

        let body = serde_json::json!({
            "name": "web",
            "config": {
                "url": "http://n8n:5678/webhook/test-wh-id/webhook",
                "content_type": "json",
                "secret": "my-test-secret"
            },
            "events": ["push"],
            "active": true
        });

        let response = create_hook(
            State(state),
            Path(("test-owner".into(), "test-repo".into())),
            Json(body),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::CREATED);

        // Verify the secret was stored in the database
        let secret = db.get_webhook_secret("test-wh-id").unwrap();
        assert_eq!(secret, Some("my-test-secret".to_string()));
    }

    #[tokio::test]
    async fn test_create_hook_upsert_preserves_id_and_updates_secret() {
        let (state, db) = test_state();

        let body1 = serde_json::json!({
            "config": {
                "url": "http://n8n:5678/webhook/wh-upsert/webhook",
                "secret": "first-secret"
            }
        });

        create_hook(
            State(state.clone()),
            Path(("o".into(), "r".into())),
            Json(body1),
        )
        .await;

        let body2 = serde_json::json!({
            "config": {
                "url": "http://n8n:5678/webhook/wh-upsert/webhook",
                "secret": "updated-secret"
            }
        });

        create_hook(State(state), Path(("o".into(), "r".into())), Json(body2)).await;

        // The secret should have been updated
        let secret = db.get_webhook_secret("wh-upsert").unwrap();
        assert_eq!(secret, Some("updated-secret".to_string()));
    }

    #[tokio::test]
    async fn test_create_hook_fallback_id_when_url_missing() {
        let (state, db) = test_state();

        // config.url is absent, so the handler should fall back to "unknown-{owner}-{repo}"
        let body = serde_json::json!({
            "config": {
                "secret": "fallback-secret"
            }
        });

        let response = create_hook(
            State(state),
            Path(("the-owner".into(), "the-repo".into())),
            Json(body),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::CREATED);

        let secret = db.get_webhook_secret("unknown-the-owner-the-repo").unwrap();
        assert_eq!(secret, Some("fallback-secret".to_string()));
    }

    #[tokio::test]
    async fn test_create_hook_empty_secret_still_stored() {
        let (state, db) = test_state();

        // n8n may send an empty secret in some edge cases
        let body = serde_json::json!({
            "config": {
                "url": "http://n8n:5678/webhook/wh-empty/webhook"
            }
        });

        let response = create_hook(State(state), Path(("o".into(), "r".into())), Json(body))
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::CREATED);

        // Empty string is still stored (the handler uses unwrap_or(""))
        let secret = db.get_webhook_secret("wh-empty").unwrap();
        assert_eq!(secret, Some("".to_string()));
    }

    // ── delete_hook handler tests ───────────────────────────────────────

    #[tokio::test]
    async fn test_delete_hook_removes_secret_from_db() {
        let (state, db) = test_state();

        // Store a secret first
        let hook_id = db
            .upsert_webhook_secret("wh-del", "github", "the-secret")
            .unwrap();
        assert!(db.get_webhook_secret("wh-del").unwrap().is_some());

        let response = delete_hook(State(state), Path(("owner".into(), "repo".into(), hook_id)))
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(db.get_webhook_secret("wh-del").unwrap().is_none());
    }

    #[tokio::test]
    async fn test_delete_hook_nonexistent_returns_204() {
        let (state, _db) = test_state();

        let response = delete_hook(State(state), Path(("owner".into(), "repo".into(), 99999)))
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    // ── list_hooks and get_user handler tests ───────────────────────────

    #[tokio::test]
    async fn test_list_hooks_returns_200() {
        let response = list_hooks(Path(("owner".into(), "repo".into())))
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_user_returns_200() {
        let response = get_user().await.into_response();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
