use crate::n8n::{WebhookEndpoints, Workflow, WorkflowNode};

/// Extracted configuration from a Slack Trigger node
#[derive(Debug, Clone)]
pub struct SlackTriggerConfig {
    /// The workflow ID this trigger belongs to
    pub workflow_id: String,

    /// The workflow name for logging
    pub workflow_name: String,

    /// Whether the workflow is active (triggers enabled in n8n)
    /// When true, events are forwarded to both production and test webhooks
    /// When false, events are only forwarded to test webhooks (for development)
    pub workflow_active: bool,

    /// The production webhook URL to forward events to (only for active workflows)
    pub webhook_url: String,

    /// The test webhook URL to forward events to (for workflow testing in n8n UI)
    pub test_webhook_url: String,

    /// The event type this trigger listens for
    /// Options: "any_event", "app_mention", "file_public", "file_shared",
    ///          "message", "channel_created", "user_created", "reaction_added"
    pub event_type: String,

    /// Specific channel IDs to watch (empty if watch_whole_workspace is true)
    pub channels: Vec<String>,

    /// Whether to watch the entire workspace
    pub watch_whole_workspace: bool,
}

impl SlackTriggerConfig {
    /// Check if this trigger should receive a given event
    pub fn matches_event(&self, event_type: &str, channel: Option<&str>) -> bool {
        // Event type must match (or trigger accepts any event)
        let type_matches = self.event_type == "any_event" || self.event_type == event_type;

        if !type_matches {
            return false;
        }

        // Channel must match (or trigger watches whole workspace)
        if self.watch_whole_workspace {
            return true;
        }

        // If we have specific channels, the event channel must be in the list
        match channel {
            Some(ch) => self.channels.contains(&ch.to_string()),
            None => {
                // Events without channels (like user_created) only match workspace-wide triggers
                // unless this is a channel-less event type
                matches!(
                    self.event_type.as_str(),
                    "user_created" | "channel_created" | "any_event"
                )
            }
        }
    }
}

/// Parse Slack Trigger configuration from a workflow node
pub fn parse_slack_trigger(
    workflow: &Workflow,
    node: &WorkflowNode,
    base_url: &str,
    endpoints: &WebhookEndpoints,
) -> Option<SlackTriggerConfig> {
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

    // Build webhook URLs from the node's webhook ID
    // n8n's Slack Trigger webhook path is /{endpoint}/{webhookId}/webhook
    let webhook_id = node.webhook_id.as_ref()?;
    let base = base_url.trim_end_matches('/');

    let webhook_url = format!("{}/{}/{}/webhook", base, endpoints.production, webhook_id);

    let test_webhook_url = format!("{}/{}/{}/webhook", base, endpoints.test, webhook_id);

    Some(SlackTriggerConfig {
        workflow_id: workflow.id.clone(),
        workflow_name: workflow.name.clone(),
        workflow_active: workflow.active,
        webhook_url,
        test_webhook_url,
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

    // Helper to create a trigger config for routing tests
    fn create_trigger_config(
        event_type: &str,
        channels: Vec<&str>,
        watch_whole_workspace: bool,
    ) -> SlackTriggerConfig {
        SlackTriggerConfig {
            workflow_id: "wf1".to_string(),
            workflow_name: "Test Workflow".to_string(),
            workflow_active: true,
            webhook_url: "http://localhost:5678/webhook/abc123/webhook".to_string(),
            test_webhook_url: "http://localhost:5678/webhook-test/abc123/webhook".to_string(),
            event_type: event_type.to_string(),
            channels: channels.iter().map(|s| s.to_string()).collect(),
            watch_whole_workspace,
        }
    }

    // Default endpoints for tests
    fn default_endpoints() -> WebhookEndpoints {
        WebhookEndpoints::default()
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
        let endpoints = default_endpoints();

        let config =
            parse_slack_trigger(&workflow, &node, "http://localhost:5678", &endpoints).unwrap();

        assert_eq!(config.workflow_id, "wf1");
        assert_eq!(config.workflow_name, "My Workflow");
        assert_eq!(
            config.webhook_url,
            "http://localhost:5678/webhook/webhook-123/webhook"
        );
        assert_eq!(
            config.test_webhook_url,
            "http://localhost:5678/webhook-test/webhook-123/webhook"
        );
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
        let endpoints = default_endpoints();

        let config = parse_slack_trigger(&workflow, &node, "http://n8n:5678", &endpoints).unwrap();

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
        let endpoints = default_endpoints();

        let config =
            parse_slack_trigger(&workflow, &node, "http://localhost:5678", &endpoints).unwrap();

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
        let endpoints = default_endpoints();

        let config = parse_slack_trigger(&workflow, &node, "http://localhost:5678", &endpoints);

        assert!(config.is_none());
    }

    #[test]
    fn test_parse_node_without_webhook_id() {
        let node = create_slack_trigger_node(None, json!({"trigger": ["message"]}));
        let workflow = create_workflow("wf1", "Workflow", vec![node.clone()]);
        let endpoints = default_endpoints();

        let config = parse_slack_trigger(&workflow, &node, "http://localhost:5678", &endpoints);

        assert!(config.is_none());
    }

    #[test]
    fn test_parse_defaults_to_any_event() {
        let node = create_slack_trigger_node(Some("webhook-123"), json!({}));
        let workflow = create_workflow("wf1", "Workflow", vec![node.clone()]);
        let endpoints = default_endpoints();

        let config =
            parse_slack_trigger(&workflow, &node, "http://localhost:5678", &endpoints).unwrap();

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

    #[test]
    fn test_webhook_url_trailing_slash_handled() {
        let node = create_slack_trigger_node(Some("wh123"), json!({"watchWorkspace": true}));
        let workflow = create_workflow("wf1", "Workflow", vec![node.clone()]);
        let endpoints = default_endpoints();

        let config =
            parse_slack_trigger(&workflow, &node, "http://localhost:5678/", &endpoints).unwrap();

        assert_eq!(
            config.webhook_url,
            "http://localhost:5678/webhook/wh123/webhook"
        );
        assert_eq!(
            config.test_webhook_url,
            "http://localhost:5678/webhook-test/wh123/webhook"
        );
    }

    #[test]
    fn test_custom_webhook_endpoints() {
        let node = create_slack_trigger_node(Some("wh123"), json!({"watchWorkspace": true}));
        let workflow = create_workflow("wf1", "Workflow", vec![node.clone()]);
        let endpoints = WebhookEndpoints {
            production: "custom-webhook".to_string(),
            test: "custom-test".to_string(),
        };

        let config =
            parse_slack_trigger(&workflow, &node, "http://localhost:5678", &endpoints).unwrap();

        assert_eq!(
            config.webhook_url,
            "http://localhost:5678/custom-webhook/wh123/webhook"
        );
        assert_eq!(
            config.test_webhook_url,
            "http://localhost:5678/custom-test/wh123/webhook"
        );
    }

    // ==================== Routing Logic Tests ====================

    #[test]
    fn test_matches_exact_event_type() {
        let trigger = create_trigger_config("message", vec![], true);

        assert!(trigger.matches_event("message", Some("C123")));
    }

    #[test]
    fn test_matches_any_event() {
        let trigger = create_trigger_config("any_event", vec![], true);

        assert!(trigger.matches_event("message", Some("C123")));
        assert!(trigger.matches_event("reaction_added", Some("C123")));
        assert!(trigger.matches_event("app_mention", Some("C123")));
        assert!(trigger.matches_event("random_event", Some("C123")));
    }

    #[test]
    fn test_no_match_wrong_event_type() {
        let trigger = create_trigger_config("message", vec![], true);

        assert!(!trigger.matches_event("reaction_added", Some("C123")));
    }

    #[test]
    fn test_matches_workspace_wide_any_channel() {
        let trigger = create_trigger_config("message", vec![], true);

        assert!(trigger.matches_event("message", Some("C111")));
        assert!(trigger.matches_event("message", Some("C222")));
        assert!(trigger.matches_event("message", Some("C333")));
    }

    #[test]
    fn test_matches_specific_channel() {
        let trigger = create_trigger_config("message", vec!["C123", "C456"], false);

        assert!(trigger.matches_event("message", Some("C123")));
        assert!(trigger.matches_event("message", Some("C456")));
    }

    #[test]
    fn test_no_match_wrong_channel() {
        let trigger = create_trigger_config("message", vec!["C123"], false);

        assert!(!trigger.matches_event("message", Some("C999")));
    }

    #[test]
    fn test_channel_less_events_workspace_only() {
        // Trigger with specific channel should NOT match events without channel
        let trigger = create_trigger_config("message", vec!["C123"], false);

        assert!(!trigger.matches_event("message", None));
    }

    #[test]
    fn test_user_created_matches_without_channel() {
        // user_created is a channel-less event type that should match
        let trigger = create_trigger_config("user_created", vec![], false);

        assert!(trigger.matches_event("user_created", None));
    }

    #[test]
    fn test_channel_created_matches_without_channel() {
        let trigger = create_trigger_config("channel_created", vec![], false);

        assert!(trigger.matches_event("channel_created", None));
    }

    #[test]
    fn test_any_event_matches_without_channel() {
        let trigger = create_trigger_config("any_event", vec![], false);

        assert!(trigger.matches_event("user_created", None));
        assert!(trigger.matches_event("channel_created", None));
    }

    #[test]
    fn test_workspace_wide_matches_without_channel() {
        let trigger = create_trigger_config("message", vec![], true);

        assert!(trigger.matches_event("message", None));
    }
}
