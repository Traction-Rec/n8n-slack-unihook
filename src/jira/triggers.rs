use crate::n8n::{WebhookEndpoints, Workflow, WorkflowNode};

/// Extracted configuration from a Jira Trigger node
#[derive(Debug, Clone)]
pub struct JiraTriggerConfig {
    /// The workflow ID this trigger belongs to
    pub workflow_id: String,

    /// The workflow name for logging
    pub workflow_name: String,

    /// Whether the workflow is active (triggers enabled in n8n)
    /// When true, events are forwarded to both production and test webhooks
    /// When false, events are only forwarded to test webhooks (for development)
    pub workflow_active: bool,

    /// The production webhook URL to forward events to (only for active workflows)
    /// May include query parameters for webhook authentication
    pub webhook_url: String,

    /// The test webhook URL to forward events to (for workflow testing in n8n UI)
    /// May include query parameters for webhook authentication
    pub test_webhook_url: String,

    /// The event types this trigger listens for.
    /// Contains values like `"jira:issue_created"`, `"comment_updated"`, or `"*"` for all events.
    /// Full list from n8n source:
    ///   board_configuration_changed, board_created, board_deleted, board_updated,
    ///   comment_created, comment_deleted, comment_updated,
    ///   jira:issue_created, jira:issue_deleted, jira:issue_updated,
    ///   issuelink_created, issuelink_deleted,
    ///   option_attachments_changed, option_issuelinks_changed, option_subtasks_changed,
    ///   option_timetracking_changed, option_unassigned_issues_changed,
    ///   option_voting_changed, option_watching_changed,
    ///   project_created, project_deleted, project_updated,
    ///   sprint_closed, sprint_created, sprint_deleted, sprint_started, sprint_updated,
    ///   user_created, user_deleted, user_updated,
    ///   jira:version_created, jira:version_deleted, jira:version_moved,
    ///   jira:version_released, jira:version_unreleased, jira:version_updated,
    ///   worklog_created, worklog_deleted, worklog_updated
    pub events: Vec<String>,
}

impl JiraTriggerConfig {
    /// Check if this trigger should receive a given Jira event.
    /// Matches if the trigger listens for the wildcard `*` or the specific event type.
    pub fn matches_event(&self, webhook_event: &str) -> bool {
        self.events.iter().any(|e| e == "*" || e == webhook_event)
    }
}

/// Parse Jira Trigger configuration from a workflow node
pub fn parse_jira_trigger(
    workflow: &Workflow,
    node: &WorkflowNode,
    base_url: &str,
    endpoints: &WebhookEndpoints,
) -> Option<JiraTriggerConfig> {
    // Only process Jira Trigger nodes
    if node.node_type != "n8n-nodes-base.jiraTrigger" {
        return None;
    }

    let params = &node.parameters;

    // Extract events from "events" array
    // Format: "events": ["jira:issue_created", "comment_created"] or ["*"]
    let events: Vec<String> = params
        .get("events")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Build webhook URLs from the node's webhook ID
    // n8n's Jira Trigger webhook path is /{endpoint}/{webhookId}/webhook
    let webhook_id = node.webhook_id.as_ref()?;
    let base = base_url.trim_end_matches('/');

    let webhook_url = format!("{}/{}/{}/webhook", base, endpoints.production, webhook_id);
    let test_webhook_url = format!("{}/{}/{}/webhook", base, endpoints.test, webhook_id);

    Some(JiraTriggerConfig {
        workflow_id: workflow.id.clone(),
        workflow_name: workflow.name.clone(),
        workflow_active: workflow.active,
        webhook_url,
        test_webhook_url,
        events,
    })
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

    // Helper to create a Jira trigger node
    fn create_jira_trigger_node(
        webhook_id: Option<&str>,
        params: serde_json::Value,
    ) -> WorkflowNode {
        WorkflowNode {
            node_type: "n8n-nodes-base.jiraTrigger".to_string(),
            name: "Jira Trigger".to_string(),
            parameters: params,
            webhook_id: webhook_id.map(|s| s.to_string()),
        }
    }

    // Helper to create a JiraTriggerConfig for routing tests
    fn create_jira_trigger_config(events: Vec<&str>) -> JiraTriggerConfig {
        JiraTriggerConfig {
            workflow_id: "wf1".to_string(),
            workflow_name: "Test Jira Workflow".to_string(),
            workflow_active: true,
            webhook_url: "http://localhost:5678/webhook/abc123/webhook".to_string(),
            test_webhook_url: "http://localhost:5678/webhook-test/abc123/webhook".to_string(),
            events: events.iter().map(|s| s.to_string()).collect(),
        }
    }

    // Default endpoints for tests
    fn default_endpoints() -> WebhookEndpoints {
        WebhookEndpoints::default()
    }

    // ==================== Parsing Tests ====================

    #[test]
    fn test_parse_jira_trigger_basic() {
        let node = create_jira_trigger_node(
            Some("webhook-j1"),
            json!({
                "events": ["jira:issue_created"]
            }),
        );
        let workflow = create_workflow("wf1", "Jira Workflow", vec![node.clone()]);
        let endpoints = default_endpoints();

        let config =
            parse_jira_trigger(&workflow, &node, "http://localhost:5678", &endpoints).unwrap();

        assert_eq!(config.workflow_id, "wf1");
        assert_eq!(config.workflow_name, "Jira Workflow");
        assert_eq!(
            config.webhook_url,
            "http://localhost:5678/webhook/webhook-j1/webhook"
        );
        assert_eq!(
            config.test_webhook_url,
            "http://localhost:5678/webhook-test/webhook-j1/webhook"
        );
        assert_eq!(config.events, vec!["jira:issue_created"]);
    }

    #[test]
    fn test_parse_jira_trigger_multiple_events() {
        let node = create_jira_trigger_node(
            Some("webhook-j2"),
            json!({
                "events": ["jira:issue_created", "comment_created", "sprint_started"]
            }),
        );
        let workflow = create_workflow("wf2", "Multi Event Workflow", vec![node.clone()]);
        let endpoints = default_endpoints();

        let config =
            parse_jira_trigger(&workflow, &node, "http://localhost:5678", &endpoints).unwrap();

        assert_eq!(
            config.events,
            vec!["jira:issue_created", "comment_created", "sprint_started"]
        );
    }

    #[test]
    fn test_parse_jira_trigger_wildcard() {
        let node = create_jira_trigger_node(
            Some("webhook-j3"),
            json!({
                "events": ["*"]
            }),
        );
        let workflow = create_workflow("wf3", "Wildcard Workflow", vec![node.clone()]);
        let endpoints = default_endpoints();

        let config =
            parse_jira_trigger(&workflow, &node, "http://localhost:5678", &endpoints).unwrap();

        assert_eq!(config.events, vec!["*"]);
    }

    #[test]
    fn test_parse_jira_trigger_empty_events() {
        let node = create_jira_trigger_node(
            Some("webhook-j4"),
            json!({
                "events": []
            }),
        );
        let workflow = create_workflow("wf4", "Empty Events Workflow", vec![node.clone()]);
        let endpoints = default_endpoints();

        let config =
            parse_jira_trigger(&workflow, &node, "http://localhost:5678", &endpoints).unwrap();

        assert!(config.events.is_empty());
    }

    #[test]
    fn test_parse_jira_trigger_no_events_param() {
        let node = create_jira_trigger_node(Some("webhook-j5"), json!({}));
        let workflow = create_workflow("wf5", "No Events Workflow", vec![node.clone()]);
        let endpoints = default_endpoints();

        let config =
            parse_jira_trigger(&workflow, &node, "http://localhost:5678", &endpoints).unwrap();

        assert!(config.events.is_empty());
    }

    #[test]
    fn test_parse_non_jira_node_returns_none() {
        let node = WorkflowNode {
            node_type: "n8n-nodes-base.httpRequest".to_string(),
            name: "HTTP Request".to_string(),
            parameters: json!({}),
            webhook_id: Some("webhook-123".to_string()),
        };
        let workflow = create_workflow("wf1", "Workflow", vec![node.clone()]);
        let endpoints = default_endpoints();

        let config = parse_jira_trigger(&workflow, &node, "http://localhost:5678", &endpoints);

        assert!(config.is_none());
    }

    #[test]
    fn test_parse_jira_trigger_without_webhook_id() {
        let node = create_jira_trigger_node(None, json!({"events": ["jira:issue_created"]}));
        let workflow = create_workflow("wf1", "Workflow", vec![node.clone()]);
        let endpoints = default_endpoints();

        let config = parse_jira_trigger(&workflow, &node, "http://localhost:5678", &endpoints);

        assert!(config.is_none());
    }

    #[test]
    fn test_parse_jira_trigger_webhook_url_trailing_slash() {
        let node =
            create_jira_trigger_node(Some("jh123"), json!({"events": ["jira:issue_created"]}));
        let workflow = create_workflow("wf1", "Workflow", vec![node.clone()]);
        let endpoints = default_endpoints();

        let config =
            parse_jira_trigger(&workflow, &node, "http://localhost:5678/", &endpoints).unwrap();

        assert_eq!(
            config.webhook_url,
            "http://localhost:5678/webhook/jh123/webhook"
        );
        assert_eq!(
            config.test_webhook_url,
            "http://localhost:5678/webhook-test/jh123/webhook"
        );
    }

    #[test]
    fn test_parse_jira_trigger_custom_endpoints() {
        let node =
            create_jira_trigger_node(Some("jh123"), json!({"events": ["jira:issue_created"]}));
        let workflow = create_workflow("wf1", "Workflow", vec![node.clone()]);
        let endpoints = WebhookEndpoints {
            production: "custom-webhook".to_string(),
            test: "custom-test".to_string(),
        };

        let config =
            parse_jira_trigger(&workflow, &node, "http://localhost:5678", &endpoints).unwrap();

        assert_eq!(
            config.webhook_url,
            "http://localhost:5678/custom-webhook/jh123/webhook"
        );
        assert_eq!(
            config.test_webhook_url,
            "http://localhost:5678/custom-test/jh123/webhook"
        );
    }

    #[test]
    fn test_parse_jira_trigger_workflow_active_flag() {
        let node =
            create_jira_trigger_node(Some("jh123"), json!({"events": ["jira:issue_created"]}));
        let mut workflow = create_workflow("wf1", "Active Workflow", vec![node.clone()]);
        let endpoints = default_endpoints();

        // Active workflow
        let config =
            parse_jira_trigger(&workflow, &node, "http://localhost:5678", &endpoints).unwrap();
        assert!(config.workflow_active);

        // Inactive workflow
        workflow.active = false;
        let config =
            parse_jira_trigger(&workflow, &node, "http://localhost:5678", &endpoints).unwrap();
        assert!(!config.workflow_active);
    }

    // ==================== Routing Logic Tests ====================

    #[test]
    fn test_jira_matches_exact_event() {
        let trigger = create_jira_trigger_config(vec!["jira:issue_created"]);

        assert!(trigger.matches_event("jira:issue_created"));
    }

    #[test]
    fn test_jira_no_match_wrong_event() {
        let trigger = create_jira_trigger_config(vec!["jira:issue_created"]);

        assert!(!trigger.matches_event("comment_created"));
    }

    #[test]
    fn test_jira_wildcard_matches_any_event() {
        let trigger = create_jira_trigger_config(vec!["*"]);

        assert!(trigger.matches_event("jira:issue_created"));
        assert!(trigger.matches_event("jira:issue_updated"));
        assert!(trigger.matches_event("comment_created"));
        assert!(trigger.matches_event("sprint_started"));
        assert!(trigger.matches_event("board_deleted"));
        assert!(trigger.matches_event("worklog_updated"));
        assert!(trigger.matches_event("user_created"));
    }

    #[test]
    fn test_jira_multiple_events_match() {
        let trigger = create_jira_trigger_config(vec!["jira:issue_created", "comment_created"]);

        assert!(trigger.matches_event("jira:issue_created"));
        assert!(trigger.matches_event("comment_created"));
        assert!(!trigger.matches_event("sprint_started"));
    }

    #[test]
    fn test_jira_empty_events_no_match() {
        let trigger = create_jira_trigger_config(vec![]);

        assert!(!trigger.matches_event("jira:issue_created"));
        assert!(!trigger.matches_event("comment_created"));
    }

    #[test]
    fn test_jira_all_event_types_matchable() {
        // Verify all known n8n Jira Trigger event types can be matched
        let all_events = vec![
            "board_configuration_changed",
            "board_created",
            "board_deleted",
            "board_updated",
            "comment_created",
            "comment_deleted",
            "comment_updated",
            "jira:issue_created",
            "jira:issue_deleted",
            "jira:issue_updated",
            "issuelink_created",
            "issuelink_deleted",
            "option_attachments_changed",
            "option_issuelinks_changed",
            "option_subtasks_changed",
            "option_timetracking_changed",
            "option_unassigned_issues_changed",
            "option_voting_changed",
            "option_watching_changed",
            "project_created",
            "project_deleted",
            "project_updated",
            "sprint_closed",
            "sprint_created",
            "sprint_deleted",
            "sprint_started",
            "sprint_updated",
            "user_created",
            "user_deleted",
            "user_updated",
            "jira:version_created",
            "jira:version_deleted",
            "jira:version_moved",
            "jira:version_released",
            "jira:version_unreleased",
            "jira:version_updated",
            "worklog_created",
            "worklog_deleted",
            "worklog_updated",
        ];

        let trigger = create_jira_trigger_config(all_events.clone());

        for event in &all_events {
            assert!(
                trigger.matches_event(event),
                "Expected trigger to match event: {}",
                event
            );
        }
    }
}
