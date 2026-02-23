use crate::config::Config;
use crate::db::Database;
use crate::n8n::N8nClient;
use crate::slack::SlackEventCallback;
use axum::http::HeaderMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use super::forward_to_webhook;

/// The Slack routing engine that manages trigger configurations and forwards events.
///
/// Trigger metadata is stored in SQLite. The periodic refresh job writes to
/// the database, and routing reads from it.
pub struct SlackRouter {
    /// Shared database handle
    db: Arc<Database>,

    /// n8n API client
    n8n_client: Arc<N8nClient>,

    /// Configuration
    config: Arc<Config>,
}

impl SlackRouter {
    /// Create a new router instance with a shared n8n client
    pub fn new(config: Arc<Config>, n8n_client: Arc<N8nClient>, db: Arc<Database>) -> Self {
        Self {
            db,
            n8n_client,
            config,
        }
    }

    /// Start the background task that periodically refreshes trigger configurations
    pub fn start_refresh_task(self: Arc<Self>) {
        let router = self.clone();
        let refresh_interval = self.config.refresh_interval_secs;

        tokio::spawn(async move {
            // Initial load
            if let Err(e) = router.refresh_triggers().await {
                error!(error = %e, "Failed initial trigger load");
            }

            // Periodic refresh
            let mut ticker = interval(Duration::from_secs(refresh_interval));
            loop {
                ticker.tick().await;
                if let Err(e) = router.refresh_triggers().await {
                    warn!(error = %e, "Failed to refresh triggers");
                }
            }
        });
    }

    /// Refresh the trigger configurations from n8n and write to DB
    async fn refresh_triggers(&self) -> Result<(), crate::n8n::N8nClientError> {
        info!("Refreshing Slack trigger configurations from n8n");
        let new_triggers = self.n8n_client.fetch_slack_triggers().await?;

        if let Err(e) = self.db.sync_slack_triggers(&new_triggers) {
            warn!(error = %e, "Failed to sync Slack triggers to database");
        }

        Ok(())
    }

    /// Reconstruct the production webhook URL for a trigger.
    fn build_webhook_url(&self, webhook_id: &str) -> String {
        let base = self.config.n8n_api_url.trim_end_matches('/');
        format!(
            "{}/{}/{}/webhook",
            base, self.config.n8n_endpoint_webhook, webhook_id
        )
    }

    /// Reconstruct the test webhook URL for a trigger.
    fn build_test_webhook_url(&self, webhook_id: &str) -> String {
        let base = self.config.n8n_api_url.trim_end_matches('/');
        format!(
            "{}/{}/{}/webhook",
            base, self.config.n8n_endpoint_webhook_test, webhook_id
        )
    }

    /// Route a Slack event to all matching triggers.
    ///
    /// Reads triggers from the database, filters by event type and channel,
    /// reconstructs webhook URLs, and forwards.
    pub async fn route_event(
        &self,
        callback: &SlackEventCallback,
        raw_body: String,
        headers: HeaderMap,
    ) {
        let event = &callback.event;
        let n8n_event_type = event.to_n8n_event_type();
        let channel = event.channel.as_deref();

        debug!(
            event_type = %event.event_type,
            n8n_event_type = %n8n_event_type,
            channel = ?channel,
            event_id = %callback.event_id,
            "Routing Slack event"
        );

        // Get all Slack triggers from the database
        let all_rows = match self.db.query_slack_triggers() {
            Ok(rows) => rows,
            Err(e) => {
                error!(error = %e, "Failed to query Slack triggers from database");
                return;
            }
        };

        // Filter by event type and channel (replicating SlackTriggerConfig::matches_event logic)
        let matching_triggers: Vec<_> = all_rows
            .iter()
            .filter(|t| {
                // Event type must match (or trigger accepts any event)
                let type_matches = t.event_type == "any_event" || t.event_type == n8n_event_type;
                if !type_matches {
                    return false;
                }

                // Channel must match (or trigger watches whole workspace)
                if t.watch_whole_workspace {
                    return true;
                }

                match channel {
                    Some(ch) => t.channels.contains(&ch.to_string()),
                    None => matches!(
                        t.event_type.as_str(),
                        "user_created" | "channel_created" | "any_event"
                    ),
                }
            })
            .collect();

        if matching_triggers.is_empty() {
            debug!(
                event_type = %n8n_event_type,
                channel = ?channel,
                "No matching triggers found for event"
            );
            return;
        }

        info!(
            event_id = %callback.event_id,
            event_type = %n8n_event_type,
            matching_count = matching_triggers.len(),
            "Forwarding event to matching triggers"
        );

        // Wrap in Arc for sharing across async tasks
        let headers = Arc::new(headers);
        let raw_body = Arc::new(raw_body);

        let mut forwards = Vec::new();

        for trigger in &matching_triggers {
            let client = self.n8n_client.clone();
            let workflow_name = trigger.workflow_name.clone();

            let prod_url = self.build_webhook_url(&trigger.webhook_id);
            let test_url = self.build_test_webhook_url(&trigger.webhook_id);

            // Production webhook - only for active workflows
            if trigger.workflow_active {
                let prod_client = client.clone();
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
                    "Skipping production webhook for inactive workflow"
                );
            }

            // Test webhook - always forward
            let test_client = client.clone();
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

        for handle in forwards {
            let _ = handle.await;
        }
    }

    /// Get the current number of loaded triggers (for health checks)
    pub fn trigger_count(&self) -> usize {
        self.db.count_slack_triggers().unwrap_or(0)
    }
}
