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

    /// Per-node static data stored by n8n during webhook lifecycle.
    ///
    /// Keys are `"node:<NodeName>"` and values are node-specific objects.
    /// For GitHub Trigger nodes, the value contains `webhookSecret` which
    /// is the HMAC secret n8n generated when registering the webhook with
    /// GitHub. We need this secret to re-sign forwarded payloads so that
    /// n8n's signature verification passes.
    #[serde(rename = "staticData", default)]
    pub static_data: Option<serde_json::Value>,
}

/// A node within a workflow
#[derive(Debug, Clone, Deserialize)]
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
