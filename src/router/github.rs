use crate::config::Config;
use crate::crypto::compute_hmac_sha256;
use crate::github::GitHubTriggerConfig;
use crate::n8n::N8nClient;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use super::forward_to_webhook;

/// The GitHub routing engine that manages trigger configurations and forwards events
pub struct GitHubRouter {
    /// Cached GitHub trigger configurations
    triggers: Arc<RwLock<Vec<GitHubTriggerConfig>>>,

    /// n8n API client (shared with other routers)
    n8n_client: Arc<N8nClient>,

    /// Configuration
    config: Arc<Config>,
}

impl GitHubRouter {
    /// Create a new GitHub router instance
    pub fn new(config: Arc<Config>, n8n_client: Arc<N8nClient>) -> Self {
        Self {
            triggers: Arc::new(RwLock::new(Vec::new())),
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

    /// Refresh the GitHub trigger configurations from n8n
    async fn refresh_triggers(&self) -> Result<(), crate::n8n::N8nClientError> {
        info!("Refreshing GitHub trigger configurations from n8n");
        let new_triggers = self.n8n_client.fetch_github_triggers().await?;

        let mut triggers = self.triggers.write();
        *triggers = new_triggers;

        Ok(())
    }

    /// Route a GitHub event to all matching triggers
    ///
    /// The `raw_body` parameter is the exact raw request body from GitHub.
    /// This must be forwarded as-is (not re-serialized) to preserve the
    /// payload integrity.
    ///
    /// For each matching trigger, the middleware re-signs the body with n8n's
    /// webhook secret (from the workflow's `staticData`) and sets the
    /// `X-Hub-Signature-256` header. This is necessary because n8n's GitHub
    /// Trigger node verifies the HMAC-SHA256 signature on every incoming
    /// webhook delivery, and the original signature from GitHub (if any)
    /// was computed with a different secret than what n8n expects.
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

        // Get matching triggers
        let matching_triggers: Vec<GitHubTriggerConfig> = {
            let triggers = self.triggers.read();
            triggers
                .iter()
                .filter(|t| t.matches_event(event_type, owner, repository))
                .cloned()
                .collect()
        };

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

        // Wrap in Arc for sharing across async tasks
        let raw_body = Arc::new(raw_body);

        // Forward to all matching triggers concurrently
        // - Production webhooks: only for active workflows
        // - Test webhooks: for all workflows (allows testing before activation)
        let mut forwards = Vec::new();

        for trigger in &matching_triggers {
            let client = self.n8n_client.clone();
            let workflow_name = trigger.workflow_name.clone();

            // Build per-trigger headers with the re-computed HMAC signature
            let signed_headers =
                Self::build_signed_headers(&headers, &raw_body, trigger.webhook_secret.as_deref());
            let signed_headers = Arc::new(signed_headers);

            // Production webhook - only for active workflows
            if trigger.workflow_active {
                let prod_client = client.clone();
                let prod_url = trigger.webhook_url.clone();
                let prod_name = workflow_name.clone();
                let prod_body = raw_body.clone();
                let prod_headers = signed_headers.clone();
                forwards.push(tokio::spawn(async move {
                    forward_to_webhook(
                        &prod_client,
                        &prod_url,
                        &prod_name,
                        "production",
                        &prod_body,
                        &prod_headers,
                    )
                    .await
                }));
            } else {
                debug!(
                    workflow_name = %workflow_name,
                    "Skipping production webhook for inactive GitHub workflow"
                );
            }

            // Test webhook - always forward (for development and testing)
            let test_client = client.clone();
            let test_url = trigger.test_webhook_url.clone();
            let test_name = workflow_name.clone();
            let test_body = raw_body.clone();
            let test_headers = signed_headers.clone();
            forwards.push(tokio::spawn(async move {
                forward_to_webhook(
                    &test_client,
                    &test_url,
                    &test_name,
                    "test",
                    &test_body,
                    &test_headers,
                )
                .await
            }));
        }

        // Wait for all forwards to complete (ignoring join errors)
        for handle in forwards {
            let _ = handle.await;
        }
    }

    /// Build forwarded headers with a re-computed `X-Hub-Signature-256`.
    ///
    /// n8n's GitHub Trigger node verifies the HMAC-SHA256 signature on every
    /// incoming webhook delivery using the secret it generated during workflow
    /// activation. Since the original `X-Hub-Signature-256` from GitHub was
    /// computed with that same secret (sent to GitHub's API), it would normally
    /// be valid. However, in our middleware architecture the event arrives from
    /// GitHub signed with a *different* secret (the one the user configured on
    /// the GitHub → middleware webhook), so we must re-sign with n8n's secret.
    ///
    /// If no secret is available (e.g., the workflow hasn't been activated yet
    /// or staticData wasn't populated), we forward the original headers as-is
    /// and let n8n decide whether to accept or reject.
    fn build_signed_headers(
        original_headers: &HeaderMap,
        body: &str,
        webhook_secret: Option<&str>,
    ) -> HeaderMap {
        let mut headers = original_headers.clone();

        if let Some(secret) = webhook_secret {
            let signature = compute_hmac_sha256(secret, body.as_bytes());

            // Replace or insert the signature header
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
        self.triggers.read().len()
    }
}
