use crate::n8n::{Workflow, WorkflowNode};

/// Extracted configuration from a Slack Trigger node
#[derive(Debug, Clone)]
pub struct SlackTriggerConfig {
    /// The n8n webhook ID (from `node.webhookId`) used as the correlation key
    /// between trigger metadata and captured webhook secrets in the database.
    pub webhook_id: String,

    /// The workflow ID this trigger belongs to
    pub workflow_id: String,

    /// The workflow name for logging
    pub workflow_name: String,

    /// Whether the workflow is active (triggers enabled in n8n)
    /// When true, events are forwarded to both production and test webhooks
    /// When false, events are only forwarded to test webhooks (for development)
    pub workflow_active: bool,

    /// The event type this trigger listens for
    /// Options: "any_event", "app_mention", "file_public", "file_shared",
    ///          "message", "channel_created", "user_created", "reaction_added"
    pub event_type: String,

    /// Specific channel IDs to watch (empty if watch_whole_workspace is true)
    pub channels: Vec<String>,

    /// Whether to watch the entire workspace
    pub watch_whole_workspace: bool,
}

/// Parse Slack Trigger configuration from a workflow node
pub fn parse_slack_trigger(workflow: &Workflow, node: &WorkflowNode) -> Option<SlackTriggerConfig> {
    // Only process Slack Trigger nodes
    if node.node_type != "n8n-nodes-base.slackTrigger" {
        return None;
    }

    let params = &node.parameters;

    // Extract event type from "trigger" array
    // Format: "trigger": ["any_event"] or ["message"] etc.
    let event_type = params
        .get("trigger")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .unwrap_or("any_event")
        .to_string();

    // Check watchWorkspace flag
    let watch_whole_workspace = params
        .get("watchWorkspace")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Extract channel IDs (only relevant if not watching whole workspace)
    let channels = if watch_whole_workspace {
        Vec::new()
    } else {
        extract_channels(params)
    };

    // Require a webhook ID — it's the correlation key for the database
    let webhook_id = node.webhook_id.as_ref()?;

    Some(SlackTriggerConfig {
        webhook_id: webhook_id.clone(),
        workflow_id: workflow.id.clone(),
        workflow_name: workflow.name.clone(),
        workflow_active: workflow.active,
        event_type,
        channels,
        watch_whole_workspace,
    })
}

/// Extract channel IDs from node parameters
fn extract_channels(params: &serde_json::Value) -> Vec<String> {
    // channelId as resource locator object: {"__rl": true, "value": "C123", "mode": "id"}
    if let Some(value) = params
        .get("channelId")
        .and_then(|obj| obj.get("value"))
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
    {
        return vec![value.to_string()];
    }

    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Helper to create a test workflow
    fn create_workflow(id: &str, name: &str, nodes: Vec<WorkflowNode>) -> Workflow {
        Workflow {
            id: id.to_string(),
            name: name.to_string(),
            active: true,
            nodes,
            static_data: None,
        }
    }

    // Helper to create a Slack trigger node
    fn create_slack_trigger_node(
        webhook_id: Option<&str>,
        params: serde_json::Value,
    ) -> WorkflowNode {
        WorkflowNode {
            node_type: "n8n-nodes-base.slackTrigger".to_string(),
            name: "Slack Trigger".to_string(),
            parameters: params,
            webhook_id: webhook_id.map(|s| s.to_string()),
        }
    }

    // ==================== Parsing Tests ====================

    #[test]
    fn test_parse_slack_trigger_basic() {
        let node = create_slack_trigger_node(
            Some("webhook-123"),
            json!({
                "trigger": ["message"],
                "watchWorkspace": true
            }),
        );
        let workflow = create_workflow("wf1", "My Workflow", vec![node.clone()]);

        let config = parse_slack_trigger(&workflow, &node).unwrap();

        assert_eq!(config.webhook_id, "webhook-123");
        assert_eq!(config.workflow_id, "wf1");
        assert_eq!(config.workflow_name, "My Workflow");
        assert_eq!(config.event_type, "message");
        assert!(config.watch_whole_workspace);
    }

    #[test]
    fn test_parse_slack_trigger_with_channel() {
        let node = create_slack_trigger_node(
            Some("webhook-456"),
            json!({
                "trigger": ["message"],
                "channelId": {
                    "__rl": true,
                    "value": "C123456",
                    "mode": "id"
                }
            }),
        );
        let workflow = create_workflow("wf2", "Channel Workflow", vec![node.clone()]);

        let config = parse_slack_trigger(&workflow, &node).unwrap();

        assert_eq!(config.channels, vec!["C123456"]);
        assert!(!config.watch_whole_workspace);
    }

    #[test]
    fn test_parse_slack_trigger_workspace_wide() {
        let node = create_slack_trigger_node(
            Some("webhook-789"),
            json!({
                "trigger": ["reaction_added"],
                "watchWorkspace": true,
                "options": {}
            }),
        );
        let workflow = create_workflow("wf3", "Workspace Workflow", vec![node.clone()]);

        let config = parse_slack_trigger(&workflow, &node).unwrap();

        assert_eq!(config.event_type, "reaction_added");
        assert!(config.watch_whole_workspace);
        assert!(config.channels.is_empty());
    }

    #[test]
    fn test_parse_non_slack_node_returns_none() {
        let node = WorkflowNode {
            node_type: "n8n-nodes-base.httpRequest".to_string(),
            name: "HTTP Request".to_string(),
            parameters: json!({}),
            webhook_id: Some("webhook-123".to_string()),
        };
        let workflow = create_workflow("wf1", "Workflow", vec![node.clone()]);

        let config = parse_slack_trigger(&workflow, &node);

        assert!(config.is_none());
    }

    #[test]
    fn test_parse_node_without_webhook_id() {
        let node = create_slack_trigger_node(None, json!({"trigger": ["message"]}));
        let workflow = create_workflow("wf1", "Workflow", vec![node.clone()]);

        let config = parse_slack_trigger(&workflow, &node);

        assert!(config.is_none());
    }

    #[test]
    fn test_parse_defaults_to_any_event() {
        let node = create_slack_trigger_node(Some("webhook-123"), json!({}));
        let workflow = create_workflow("wf1", "Workflow", vec![node.clone()]);

        let config = parse_slack_trigger(&workflow, &node).unwrap();

        assert_eq!(config.event_type, "any_event");
    }

    #[test]
    fn test_extract_channels_resource_locator() {
        let params = json!({
            "channelId": {
                "__rl": true,
                "value": "C999888",
                "mode": "id"
            }
        });

        let channels = extract_channels(&params);

        assert_eq!(channels, vec!["C999888"]);
    }

    #[test]
    fn test_extract_channels_empty() {
        let params = json!({});

        let channels = extract_channels(&params);

        assert!(channels.is_empty());
    }

    #[test]
    fn test_extract_channels_empty_value_ignored() {
        let params = json!({
            "channelId": {
                "__rl": true,
                "value": "",
                "mode": "id"
            }
        });

        let channels = extract_channels(&params);

        assert!(channels.is_empty());
    }
}
