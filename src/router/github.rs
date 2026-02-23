use crate::config::Config;
use crate::crypto::compute_hmac_sha256;
use crate::db::{Database, GitHubTriggerRow};
use crate::n8n::N8nClient;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use super::forward_to_webhook;

/// The GitHub routing engine that manages trigger configurations and forwards events.
///
/// Trigger metadata and webhook secrets are stored in SQLite. The periodic
/// refresh job writes to the database, and routing reads from it.
pub struct GitHubRouter {
    /// Shared database handle
    db: Arc<Database>,

    /// n8n API client (shared with other routers)
    n8n_client: Arc<N8nClient>,

    /// Configuration
    config: Arc<Config>,
}

impl GitHubRouter {
    /// Create a new GitHub router instance
    pub fn new(config: Arc<Config>, n8n_client: Arc<N8nClient>, db: Arc<Database>) -> Self {
        Self {
            db,
            n8n_client,
            config,
        }
    }

    /// Start the background task that periodically refreshes GitHub trigger configurations
    pub fn start_refresh_task(self: Arc<Self>) {
        let router = self.clone();
        let refresh_interval = self.config.refresh_interval_secs;

        tokio::spawn(async move {
            // Initial load
            if let Err(e) = router.refresh_triggers().await {
                error!(error = %e, "Failed initial GitHub trigger load");
            }

            // Periodic refresh
            let mut ticker = interval(Duration::from_secs(refresh_interval));
            loop {
                ticker.tick().await;
                if let Err(e) = router.refresh_triggers().await {
                    warn!(error = %e, "Failed to refresh GitHub triggers");
                }
            }
        });
    }

    /// Refresh the GitHub trigger configurations from n8n and write to DB.
    ///
    /// Also persists any `webhook_secret` from `staticData` as a fallback
    /// (will not overwrite secrets already captured by the provider mock).
    ///
    /// Called periodically by the background task, and also triggered
    /// immediately when the provider mock intercepts a webhook registration
    /// so that the trigger metadata is available for routing without waiting
    /// for the next periodic sync.
    pub async fn refresh_triggers(&self) -> Result<(), crate::n8n::N8nClientError> {
        info!("Refreshing GitHub trigger configurations from n8n");
        let new_triggers = self.n8n_client.fetch_github_triggers().await?;

        // Persist fallback secrets from staticData before syncing triggers
        for trigger in &new_triggers {
            if let Some(ref secret) = trigger.webhook_secret
                && let Err(e) =
                    self.db
                        .upsert_webhook_secret_fallback(&trigger.webhook_id, "github", secret)
            {
                warn!(
                    error = %e,
                    webhook_id = %trigger.webhook_id,
                    "Failed to persist staticData webhook secret"
                );
            }
        }

        // Sync trigger metadata to the database
        if let Err(e) = self.db.sync_github_triggers(&new_triggers) {
            warn!(error = %e, "Failed to sync GitHub triggers to database");
        }

        Ok(())
    }

    /// Reconstruct the production webhook URL for a trigger row.
    fn build_webhook_url(&self, webhook_id: &str) -> String {
        let base = self.config.n8n_api_url.trim_end_matches('/');
        format!(
            "{}/{}/{}/webhook",
            base, self.config.n8n_endpoint_webhook, webhook_id
        )
    }

    /// Reconstruct the test webhook URL for a trigger row.
    fn build_test_webhook_url(&self, webhook_id: &str) -> String {
        let base = self.config.n8n_api_url.trim_end_matches('/');
        format!(
            "{}/{}/{}/webhook",
            base, self.config.n8n_endpoint_webhook_test, webhook_id
        )
    }

    /// Route a GitHub event to all matching triggers.
    ///
    /// Reads matching triggers from the database (which JOINs webhook_secrets
    /// so the HMAC secret is included). For each matching trigger, re-signs
    /// the payload and forwards to both production and test webhook URLs.
    ///
    /// If any forward returns a 401 or if a trigger's webhook secret was
    /// missing, the router will immediately refresh its trigger cache from
    /// the n8n API and retry those specific deliveries.
    pub async fn route_event(
        &self,
        event_type: &str,
        owner: Option<&str>,
        repository: Option<&str>,
        raw_body: String,
        headers: HeaderMap,
    ) {
        debug!(
            event_type = %event_type,
            owner = ?owner,
            repository = ?repository,
            "Routing GitHub event"
        );

        // Get matching triggers from the database
        let all_rows = match self.db.query_github_triggers(owner, repository) {
            Ok(rows) => rows,
            Err(e) => {
                error!(error = %e, "Failed to query GitHub triggers from database");
                return;
            }
        };

        // Filter by event type (the DB doesn't filter events for us)
        let matching_triggers: Vec<&GitHubTriggerRow> = all_rows
            .iter()
            .filter(|t| t.events.iter().any(|e| e == "*" || e == event_type))
            .collect();

        if matching_triggers.is_empty() {
            debug!(
                event_type = %event_type,
                owner = ?owner,
                repository = ?repository,
                "No matching GitHub triggers found for event"
            );
            return;
        }

        info!(
            event_type = %event_type,
            owner = ?owner,
            repository = ?repository,
            matching_count = matching_triggers.len(),
            "Forwarding GitHub event to matching triggers"
        );

        let raw_body = Arc::new(raw_body);

        // Phase 1: Forward to all matching triggers concurrently and collect results.
        let results = self
            .forward_all(&matching_triggers, &raw_body, &headers)
            .await;

        // Phase 2: Identify forwards that failed with 401 or had no webhook secret.
        let retry_urls: HashSet<String> = results
            .into_iter()
            .filter(|r| r.status == Some(401) || !r.had_secret)
            .map(|r| r.webhook_url)
            .collect();

        if retry_urls.is_empty() {
            return;
        }

        info!(
            retry_count = retry_urls.len(),
            "Got 401 or missing webhook secret; refreshing triggers from n8n API and retrying"
        );

        // Refresh the trigger cache from the n8n API
        if let Err(e) = self.refresh_triggers().await {
            warn!(error = %e, "Failed to refresh triggers for retry — giving up");
            return;
        }

        // Re-query the database for matching triggers (now with fresh data)
        let fresh_rows = match self.db.query_github_triggers(owner, repository) {
            Ok(rows) => rows,
            Err(e) => {
                error!(error = %e, "Failed to re-query GitHub triggers after refresh");
                return;
            }
        };

        let fresh_matching: Vec<&GitHubTriggerRow> = fresh_rows
            .iter()
            .filter(|t| t.events.iter().any(|e| e == "*" || e == event_type))
            .collect();

        // Phase 3: Retry only the specific webhook URLs that failed.
        let mut retry_forwards = Vec::new();
        for trigger in &fresh_matching {
            let signed_headers = Arc::new(Self::build_signed_headers(
                &headers,
                &raw_body,
                trigger.secret.as_deref(),
            ));

            let prod_url = self.build_webhook_url(&trigger.webhook_id);
            let test_url = self.build_test_webhook_url(&trigger.webhook_id);

            if trigger.workflow_active && retry_urls.contains(&prod_url) {
                let client = self.n8n_client.clone();
                let name = trigger.workflow_name.clone();
                let body = raw_body.clone();
                let hdrs = signed_headers.clone();
                retry_forwards.push(tokio::spawn(async move {
                    forward_to_webhook(
                        &client,
                        &prod_url,
                        &name,
                        "production (retry)",
                        &body,
                        &hdrs,
                    )
                    .await
                }));
            }

            if retry_urls.contains(&test_url) {
                let client = self.n8n_client.clone();
                let name = trigger.workflow_name.clone();
                let body = raw_body.clone();
                let hdrs = signed_headers.clone();
                retry_forwards.push(tokio::spawn(async move {
                    forward_to_webhook(&client, &test_url, &name, "test (retry)", &body, &hdrs)
                        .await
                }));
            }
        }

        for handle in retry_forwards {
            let _ = handle.await;
        }
    }

    /// Forward a GitHub event to all matching triggers concurrently.
    async fn forward_all(
        &self,
        triggers: &[&GitHubTriggerRow],
        raw_body: &Arc<String>,
        headers: &HeaderMap,
    ) -> Vec<ForwardResult> {
        let mut jobs: Vec<(tokio::task::JoinHandle<Option<u16>>, ForwardResult)> = Vec::new();

        for trigger in triggers {
            let had_secret = trigger.secret.is_some();
            let signed_headers = Arc::new(Self::build_signed_headers(
                headers,
                raw_body,
                trigger.secret.as_deref(),
            ));

            let prod_url = self.build_webhook_url(&trigger.webhook_id);
            let test_url = self.build_test_webhook_url(&trigger.webhook_id);

            // Production webhook — only for active workflows
            if trigger.workflow_active {
                let client = self.n8n_client.clone();
                let name = trigger.workflow_name.clone();
                let body = raw_body.clone();
                let hdrs = signed_headers.clone();
                let url = prod_url.clone();

                let meta = ForwardResult {
                    webhook_url: prod_url,
                    had_secret,
                    status: None,
                };
                let handle = tokio::spawn(async move {
                    forward_to_webhook(&client, &url, &name, "production", &body, &hdrs).await
                });
                jobs.push((handle, meta));
            } else {
                debug!(
                    workflow_name = %trigger.workflow_name,
                    "Skipping production webhook for inactive GitHub workflow"
                );
            }

            // Test webhook — always forward (for development and testing)
            {
                let client = self.n8n_client.clone();
                let name = trigger.workflow_name.clone();
                let body = raw_body.clone();
                let hdrs = signed_headers.clone();
                let url = test_url.clone();

                let meta = ForwardResult {
                    webhook_url: test_url,
                    had_secret,
                    status: None,
                };
                let handle = tokio::spawn(async move {
                    forward_to_webhook(&client, &url, &name, "test", &body, &hdrs).await
                });
                jobs.push((handle, meta));
            }
        }

        // Collect results
        let mut results = Vec::with_capacity(jobs.len());
        for (handle, mut meta) in jobs {
            meta.status = handle.await.ok().flatten();
            results.push(meta);
        }
        results
    }

    /// Build forwarded headers with a re-computed `X-Hub-Signature-256`.
    fn build_signed_headers(
        original_headers: &HeaderMap,
        body: &str,
        webhook_secret: Option<&str>,
    ) -> HeaderMap {
        let mut headers = original_headers.clone();

        if let Some(secret) = webhook_secret {
            let signature = compute_hmac_sha256(secret, body.as_bytes());

            headers.insert(
                HeaderName::from_static("x-hub-signature-256"),
                HeaderValue::from_str(&signature).expect("signature is valid ASCII"),
            );

            debug!(
                has_secret = true,
                "Re-signed GitHub webhook payload with n8n's webhook secret"
            );
        } else {
            warn!("No webhook secret available for GitHub trigger; forwarding without re-signing");
        }

        headers
    }

    /// Get the current number of loaded GitHub triggers (for health checks)
    pub fn trigger_count(&self) -> usize {
        self.db.count_github_triggers().unwrap_or(0)
    }
}

/// Result of a single webhook forward attempt, used to decide whether a retry
/// is needed after refreshing the trigger cache.
struct ForwardResult {
    webhook_url: String,
    had_secret: bool,
    status: Option<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::db::Database;
    use crate::github::GitHubTriggerConfig;
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Build a minimal `Config` that points at the given mock server URL.
    fn test_config(base_url: &str) -> Arc<Config> {
        Arc::new(Config {
            n8n_api_url: base_url.to_string(),
            n8n_api_key: "test-api-key".to_string(),
            listen_addr: "0.0.0.0:3000".to_string(),
            refresh_interval_secs: 600,
            n8n_endpoint_webhook: "webhook".to_string(),
            n8n_endpoint_webhook_test: "webhook-test".to_string(),
            github_webhook_secret: None,
            database_path: ":memory:".to_string(),
        })
    }

    /// Seed a GitHub trigger into the database, optionally with a webhook secret.
    fn seed_trigger(db: &Arc<Database>, secret: Option<&str>) {
        let triggers = vec![GitHubTriggerConfig {
            webhook_id: "wh1".to_string(),
            workflow_id: "wf1".to_string(),
            workflow_name: "Test Workflow".to_string(),
            workflow_active: true,
            events: vec!["push".to_string()],
            owner: "test-owner".to_string(),
            repository: "test-repo".to_string(),
            webhook_secret: None,
        }];
        db.sync_github_triggers(&triggers).unwrap();

        if let Some(s) = secret {
            db.upsert_webhook_secret("wh1", "github", s).unwrap();
        }
    }

    /// Build a mock n8n API response for `GET /api/v1/workflows` that returns
    /// a single GitHub Trigger workflow with the given webhook secret.
    fn workflows_api_response(secret: &str) -> serde_json::Value {
        serde_json::json!({
            "data": [{
                "id": "wf1",
                "name": "Test Workflow",
                "active": true,
                "nodes": [{
                    "type": "n8n-nodes-base.githubTrigger",
                    "name": "GitHub Trigger",
                    "webhookId": "wh1",
                    "parameters": {
                        "events": ["push"],
                        "owner": "test-owner",
                        "repository": "test-repo"
                    }
                }],
                "staticData": {
                    "node:GitHub Trigger": {
                        "webhookId": 1,
                        "webhookSecret": secret
                    }
                }
            }],
            "nextCursor": null
        })
    }

    // ==================== Happy-path: no retry needed ====================

    #[tokio::test]
    async fn test_no_retry_when_all_forwards_succeed() {
        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        let config = test_config(&base_url);
        let n8n_client = Arc::new(N8nClient::new(config.clone()));
        let db = Arc::new(Database::open(":memory:").unwrap());
        let router = GitHubRouter::new(config, n8n_client, db.clone());

        seed_trigger(&db, Some("good-secret"));

        Mock::given(method("POST"))
            .and(path_regex("/wh1/webhook"))
            .respond_with(ResponseTemplate::new(200))
            .expect(2)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/workflows"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock_server)
            .await;

        router
            .route_event(
                "push",
                Some("test-owner"),
                Some("test-repo"),
                r#"{"ref":"refs/heads/main"}"#.to_string(),
                HeaderMap::new(),
            )
            .await;
    }

    // ==================== Retry on 401 ====================

    #[tokio::test]
    async fn test_retry_on_401_refreshes_triggers_and_retries() {
        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        let config = test_config(&base_url);
        let n8n_client = Arc::new(N8nClient::new(config.clone()));
        let db = Arc::new(Database::open(":memory:").unwrap());
        let router = GitHubRouter::new(config, n8n_client, db.clone());

        seed_trigger(&db, Some("old-secret"));

        Mock::given(method("POST"))
            .and(path_regex("/wh1/webhook"))
            .respond_with(ResponseTemplate::new(401))
            .expect(4) // 2 initial + 2 retry
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/workflows"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(workflows_api_response("new-secret")),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        router
            .route_event(
                "push",
                Some("test-owner"),
                Some("test-repo"),
                r#"{"ref":"refs/heads/main"}"#.to_string(),
                HeaderMap::new(),
            )
            .await;
    }

    // ==================== Retry on missing secret ====================

    #[tokio::test]
    async fn test_retry_on_missing_secret_refreshes_and_retries() {
        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        let config = test_config(&base_url);
        let n8n_client = Arc::new(N8nClient::new(config.clone()));
        let db = Arc::new(Database::open(":memory:").unwrap());
        let router = GitHubRouter::new(config, n8n_client, db.clone());

        // Seed trigger with NO secret
        seed_trigger(&db, None);

        Mock::given(method("POST"))
            .and(path_regex("/wh1/webhook"))
            .respond_with(ResponseTemplate::new(200))
            .expect(4) // 2 initial + 2 retry
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/workflows"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(workflows_api_response("the-secret")),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        router
            .route_event(
                "push",
                Some("test-owner"),
                Some("test-repo"),
                r#"{"ref":"refs/heads/main"}"#.to_string(),
                HeaderMap::new(),
            )
            .await;
    }
}
