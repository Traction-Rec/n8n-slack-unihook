use crate::config::Config;
use crate::db::Database;
use crate::n8n::N8nClient;
use axum::http::HeaderMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use super::forward_to_webhook;

/// The Jira routing engine that manages trigger configurations and forwards events.
///
/// Trigger metadata is stored in SQLite. The periodic refresh job writes to
/// the database, and routing reads from it.
pub struct JiraRouter {
    /// Shared database handle
    db: Arc<Database>,

    /// n8n API client (shared with other routers)
    n8n_client: Arc<N8nClient>,

    /// Configuration
    config: Arc<Config>,
}

impl JiraRouter {
    /// Create a new Jira router instance
    pub fn new(config: Arc<Config>, n8n_client: Arc<N8nClient>, db: Arc<Database>) -> Self {
        Self {
            db,
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

    /// Refresh the Jira trigger configurations from n8n and write to DB.
    ///
    /// Called periodically by the background task, and also triggered
    /// immediately when the provider mock intercepts a webhook registration
    /// so that the trigger metadata is available for routing without waiting
    /// for the next periodic sync.
    pub async fn refresh_triggers(&self) -> Result<(), crate::n8n::N8nClientError> {
        info!("Refreshing Jira trigger configurations from n8n");
        let new_triggers = self.n8n_client.fetch_jira_triggers().await?;

        if let Err(e) = self.db.sync_jira_triggers(&new_triggers) {
            warn!(error = %e, "Failed to sync Jira triggers to database");
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

    /// Route a Jira event to all matching triggers.
    ///
    /// Reads triggers from the database, filters by event type, reconstructs
    /// webhook URLs, and forwards.
    pub async fn route_event(
        &self,
        webhook_event: &str,
        raw_body: String,
        headers: HeaderMap,
        query_string: Option<String>,
    ) {
        debug!(
            webhook_event = %webhook_event,
            "Routing Jira event"
        );

        // Get all Jira triggers from the database
        let all_rows = match self.db.query_jira_triggers() {
            Ok(rows) => rows,
            Err(e) => {
                error!(error = %e, "Failed to query Jira triggers from database");
                return;
            }
        };

        // Filter by event type
        let matching_triggers: Vec<_> = all_rows
            .iter()
            .filter(|t| t.events.iter().any(|e| e == "*" || e == webhook_event))
            .collect();

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
        let query_string = Arc::new(query_string);

        let mut forwards = Vec::new();

        for trigger in &matching_triggers {
            let client = self.n8n_client.clone();
            let workflow_name = trigger.workflow_name.clone();

            let prod_url =
                append_query_string(&self.build_webhook_url(&trigger.webhook_id), &query_string);
            let test_url = append_query_string(
                &self.build_test_webhook_url(&trigger.webhook_id),
                &query_string,
            );

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
                    "Skipping production webhook for inactive Jira workflow"
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

    /// Get the current number of loaded Jira triggers (for health checks)
    pub fn trigger_count(&self) -> usize {
        self.db.count_jira_triggers().unwrap_or(0)
    }
}

/// Append an optional query string to a URL.
fn append_query_string(url: &str, query_string: &Option<String>) -> String {
    match query_string {
        Some(qs) if !qs.is_empty() => {
            if url.contains('?') {
                format!("{}&{}", url, qs)
            } else {
                format!("{}?{}", url, qs)
            }
        }
        _ => url.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append_query_string_none() {
        let url = "http://n8n:5678/webhook/abc/webhook";
        assert_eq!(append_query_string(url, &None), url);
    }

    #[test]
    fn test_append_query_string_empty() {
        let url = "http://n8n:5678/webhook/abc/webhook";
        assert_eq!(append_query_string(url, &Some(String::new())), url);
    }

    #[test]
    fn test_append_query_string_to_clean_url() {
        let url = "http://n8n:5678/webhook/abc/webhook";
        assert_eq!(
            append_query_string(url, &Some("secret=abc123".to_string())),
            "http://n8n:5678/webhook/abc/webhook?secret=abc123"
        );
    }

    #[test]
    fn test_append_query_string_to_url_with_existing_params() {
        let url = "http://n8n:5678/webhook/abc/webhook?existing=true";
        assert_eq!(
            append_query_string(url, &Some("secret=abc123".to_string())),
            "http://n8n:5678/webhook/abc/webhook?existing=true&secret=abc123"
        );
    }
}
