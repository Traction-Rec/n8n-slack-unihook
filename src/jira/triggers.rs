use crate::n8n::{Workflow, WorkflowNode};

/// Extracted configuration from a Jira Trigger node
#[derive(Debug, Clone)]
pub struct JiraTriggerConfig {
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

/// Parse Jira Trigger configuration from a workflow node
pub fn parse_jira_trigger(workflow: &Workflow, node: &WorkflowNode) -> Option<JiraTriggerConfig> {
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

    // Require a webhook ID — it's the correlation key for the database
    let webhook_id = node.webhook_id.as_ref()?;

    Some(JiraTriggerConfig {
        webhook_id: webhook_id.clone(),
        workflow_id: workflow.id.clone(),
        workflow_name: workflow.name.clone(),
        workflow_active: workflow.active,
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
            static_data: None,
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

        let config = parse_jira_trigger(&workflow, &node).unwrap();

        assert_eq!(config.webhook_id, "webhook-j1");
        assert_eq!(config.workflow_id, "wf1");
        assert_eq!(config.workflow_name, "Jira Workflow");
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

        let config = parse_jira_trigger(&workflow, &node).unwrap();

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

        let config = parse_jira_trigger(&workflow, &node).unwrap();

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

        let config = parse_jira_trigger(&workflow, &node).unwrap();

        assert!(config.events.is_empty());
    }

    #[test]
    fn test_parse_jira_trigger_no_events_param() {
        let node = create_jira_trigger_node(Some("webhook-j5"), json!({}));
        let workflow = create_workflow("wf5", "No Events Workflow", vec![node.clone()]);

        let config = parse_jira_trigger(&workflow, &node).unwrap();

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

        let config = parse_jira_trigger(&workflow, &node);

        assert!(config.is_none());
    }

    #[test]
    fn test_parse_jira_trigger_without_webhook_id() {
        let node = create_jira_trigger_node(None, json!({"events": ["jira:issue_created"]}));
        let workflow = create_workflow("wf1", "Workflow", vec![node.clone()]);

        let config = parse_jira_trigger(&workflow, &node);

        assert!(config.is_none());
    }

    #[test]
    fn test_parse_jira_trigger_workflow_active_flag() {
        let node =
            create_jira_trigger_node(Some("jh123"), json!({"events": ["jira:issue_created"]}));
        let mut workflow = create_workflow("wf1", "Active Workflow", vec![node.clone()]);

        // Active workflow
        let config = parse_jira_trigger(&workflow, &node).unwrap();
        assert!(config.workflow_active);

        // Inactive workflow
        workflow.active = false;
        let config = parse_jira_trigger(&workflow, &node).unwrap();
        assert!(!config.workflow_active);
    }
}
