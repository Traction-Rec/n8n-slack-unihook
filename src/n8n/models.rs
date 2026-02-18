use serde::Deserialize;

/// Response from n8n GET /api/v1/workflows endpoint
#[derive(Debug, Deserialize)]
pub struct WorkflowsResponse {
    pub data: Vec<Workflow>,
    #[serde(rename = "nextCursor")]
    pub next_cursor: Option<String>,
}

/// A workflow from the n8n API
#[derive(Debug, Deserialize)]
pub struct Workflow {
    pub id: String,
    pub name: String,
    pub active: bool,
    pub nodes: Vec<WorkflowNode>,
}

/// A node within a workflow
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct WorkflowNode {
    /// The node type (e.g., "n8n-nodes-base.slackTrigger")
    #[serde(rename = "type")]
    pub node_type: String,

    /// Node name
    pub name: String,

    /// Node parameters containing configuration
    #[serde(default)]
    pub parameters: serde_json::Value,

    /// Webhook ID (for trigger nodes)
    #[serde(rename = "webhookId")]
    pub webhook_id: Option<String>,
}

/// Webhook endpoint configuration for parsing triggers
#[derive(Debug, Clone)]
pub struct WebhookEndpoints {
    /// Production webhook endpoint path (e.g., "webhook")
    pub production: String,
    /// Test webhook endpoint path (e.g., "webhook-test")
    pub test: String,
}

impl Default for WebhookEndpoints {
    fn default() -> Self {
        Self {
            production: "webhook".to_string(),
            test: "webhook-test".to_string(),
        }
    }
}
