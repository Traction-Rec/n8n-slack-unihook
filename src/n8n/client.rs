use crate::config::Config;
use crate::n8n::models::{
    SlackTriggerConfig, WebhookEndpoints, WorkflowsResponse, parse_slack_trigger,
};
use axum::http::HeaderMap;
use reqwest::Client;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Client for interacting with the n8n API
pub struct N8nClient {
    client: Client,
    config: Arc<Config>,
    webhook_endpoints: WebhookEndpoints,
}

impl N8nClient {
    pub fn new(config: Arc<Config>) -> Self {
        let client = Client::new();
        let webhook_endpoints = WebhookEndpoints {
            production: config.n8n_endpoint_webhook.clone(),
            test: config.n8n_endpoint_webhook_test.clone(),
        };
        Self {
            client,
            config,
            webhook_endpoints,
        }
    }

    /// Fetch all active workflows and extract Slack trigger configurations
    pub async fn fetch_slack_triggers(&self) -> Result<Vec<SlackTriggerConfig>, N8nClientError> {
        let mut triggers = Vec::new();
        let mut cursor: Option<String> = None;

        loop {
            let response = self.fetch_workflows_page(cursor.as_deref()).await?;

            for workflow in response.data {
                // Look for Slack Trigger nodes in the workflow
                // We include both active and inactive workflows:
                // - Active workflows: forward to both production and test webhooks
                // - Inactive workflows: forward only to test webhooks (for development)
                for node in &workflow.nodes {
                    if let Some(trigger) = parse_slack_trigger(
                        &workflow,
                        node,
                        &self.config.n8n_api_url,
                        &self.webhook_endpoints,
                    ) {
                        info!(
                            workflow_id = %trigger.workflow_id,
                            workflow_name = %trigger.workflow_name,
                            workflow_active = trigger.workflow_active,
                            event_type = %trigger.event_type,
                            watch_whole_workspace = trigger.watch_whole_workspace,
                            channels = ?trigger.channels,
                            "Found Slack trigger"
                        );
                        triggers.push(trigger);
                    }
                }
            }

            // Check if there are more pages
            match response.next_cursor {
                Some(next) if !next.is_empty() => cursor = Some(next),
                _ => break,
            }
        }

        info!(
            count = triggers.len(),
            "Loaded Slack trigger configurations"
        );
        Ok(triggers)
    }

    /// Fetch a single page of workflows from the n8n API
    async fn fetch_workflows_page(
        &self,
        cursor: Option<&str>,
    ) -> Result<WorkflowsResponse, N8nClientError> {
        let mut url = format!("{}/api/v1/workflows", self.config.n8n_api_url);

        if let Some(c) = cursor {
            url.push_str(&format!("?cursor={}", c));
        }

        debug!(url = %url, "Fetching workflows from n8n");

        let response = self
            .client
            .get(&url)
            .header("X-N8N-API-KEY", &self.config.n8n_api_key)
            .send()
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to connect to n8n API");
                N8nClientError::RequestFailed(e.to_string())
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!(status = %status, body = %body, "n8n API returned error");
            return Err(N8nClientError::ApiError {
                status: status.as_u16(),
                body,
            });
        }

        let workflows: WorkflowsResponse = response.json().await.map_err(|e| {
            error!(error = %e, "Failed to parse n8n API response");
            N8nClientError::ParseError(e.to_string())
        })?;

        Ok(workflows)
    }

    /// Forward a Slack event to a specific webhook URL
    ///
    /// The `raw_body` parameter is the exact raw request body from Slack.
    /// This is forwarded as-is (not re-serialized) to preserve the exact bytes
    /// for Slack signature verification by n8n.
    pub async fn forward_event(
        &self,
        webhook_url: &str,
        raw_body: &str,
        headers: &HeaderMap,
    ) -> Result<(), N8nClientError> {
        debug!(
            webhook_url = %webhook_url,
            forwarded_headers = headers.len(),
            body_len = raw_body.len(),
            "Forwarding event to n8n webhook"
        );

        // Build the request with the raw body (not re-serialized JSON)
        // This preserves the exact bytes for signature verification
        let mut request = self.client.post(webhook_url).body(raw_body.to_string());

        // Forward relevant headers from the original Slack request
        // (includes Content-Type, X-Slack-Signature, X-Slack-Request-Timestamp, etc.)
        for (name, value) in headers.iter() {
            let header_name =
                reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()).ok();
            let header_value = reqwest::header::HeaderValue::from_bytes(value.as_bytes()).ok();

            if let (Some(name), Some(value)) = (header_name, header_value) {
                request = request.header(name, value);
            }
        }

        let response = request.send().await.map_err(|e| {
            warn!(error = %e, webhook_url = %webhook_url, "Failed to forward event");
            N8nClientError::RequestFailed(e.to_string())
        })?;

        if !response.status().is_success() {
            let status = response.status();
            warn!(
                status = %status,
                webhook_url = %webhook_url,
                "Webhook returned non-success status"
            );
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum N8nClientError {
    #[error("Request failed: {0}")]
    RequestFailed(String),

    #[error("API error (status {status}): {body}")]
    ApiError { status: u16, body: String },

    #[error("Failed to parse response: {0}")]
    ParseError(String),
}
