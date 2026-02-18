use crate::config::Config;
use crate::jira::JiraTriggerConfig;
use crate::n8n::N8nClient;
use axum::http::HeaderMap;
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use super::forward_to_webhook;

/// The Jira routing engine that manages trigger configurations and forwards events
pub struct JiraRouter {
    /// Cached Jira trigger configurations
    triggers: Arc<RwLock<Vec<JiraTriggerConfig>>>,

    /// n8n API client (shared with Slack router)
    n8n_client: Arc<N8nClient>,

    /// Configuration
    config: Arc<Config>,
}

impl JiraRouter {
    /// Create a new Jira router instance
    pub fn new(config: Arc<Config>, n8n_client: Arc<N8nClient>) -> Self {
        Self {
            triggers: Arc::new(RwLock::new(Vec::new())),
            n8n_client,
            config,
        }
    }

    /// Start the background task that periodically refreshes Jira trigger configurations
    pub fn start_refresh_task(self: Arc<Self>) {
        let router = self.clone();
        let refresh_interval = self.config.refresh_interval_secs;

        tokio::spawn(async move {
            // Initial load
            if let Err(e) = router.refresh_triggers().await {
                error!(error = %e, "Failed initial Jira trigger load");
            }

            // Periodic refresh
            let mut ticker = interval(Duration::from_secs(refresh_interval));
            loop {
                ticker.tick().await;
                if let Err(e) = router.refresh_triggers().await {
                    warn!(error = %e, "Failed to refresh Jira triggers");
                }
            }
        });
    }

    /// Refresh the Jira trigger configurations from n8n
    async fn refresh_triggers(&self) -> Result<(), crate::n8n::N8nClientError> {
        info!("Refreshing Jira trigger configurations from n8n");
        let new_triggers = self.n8n_client.fetch_jira_triggers().await?;

        let mut triggers = self.triggers.write();
        *triggers = new_triggers;

        Ok(())
    }

    /// Route a Jira event to all matching triggers
    ///
    /// The `raw_body` parameter is the exact raw request body from Jira.
    /// This must be forwarded as-is (not re-serialized) to preserve the
    /// payload integrity and any authentication data.
    pub async fn route_event(&self, webhook_event: &str, raw_body: String, headers: HeaderMap) {
        debug!(
            webhook_event = %webhook_event,
            "Routing Jira event"
        );

        // Get matching triggers
        let matching_triggers: Vec<JiraTriggerConfig> = {
            let triggers = self.triggers.read();
            triggers
                .iter()
                .filter(|t| t.matches_event(webhook_event))
                .cloned()
                .collect()
        };

        if matching_triggers.is_empty() {
            debug!(
                webhook_event = %webhook_event,
                "No matching Jira triggers found for event"
            );
            return;
        }

        info!(
            webhook_event = %webhook_event,
            matching_count = matching_triggers.len(),
            "Forwarding Jira event to matching triggers"
        );

        // Wrap in Arc for sharing across async tasks
        let headers = Arc::new(headers);
        let raw_body = Arc::new(raw_body);

        // Forward to all matching triggers concurrently
        // - Production webhooks: only for active workflows
        // - Test webhooks: for all workflows (allows testing before activation)
        let mut forwards = Vec::new();

        for trigger in &matching_triggers {
            let client = self.n8n_client.clone();
            let workflow_name = trigger.workflow_name.clone();

            // Production webhook - only for active workflows
            if trigger.workflow_active {
                let prod_client = client.clone();
                let prod_url = trigger.webhook_url.clone();
                let prod_name = workflow_name.clone();
                let prod_body = raw_body.clone();
                let prod_headers = headers.clone();
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
                    "Skipping production webhook for inactive Jira workflow"
                );
            }

            // Test webhook - always forward (for development and testing)
            let test_client = client.clone();
            let test_url = trigger.test_webhook_url.clone();
            let test_name = workflow_name.clone();
            let test_body = raw_body.clone();
            let test_headers = headers.clone();
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

    /// Get the current number of loaded Jira triggers (for health checks)
    pub fn trigger_count(&self) -> usize {
        self.triggers.read().len()
    }
}
