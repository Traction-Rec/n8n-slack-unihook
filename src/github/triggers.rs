use crate::n8n::{Workflow, WorkflowNode};

/// Extracted configuration from a GitHub Trigger node
#[derive(Debug, Clone)]
pub struct GitHubTriggerConfig {
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
    /// Contains values like `"push"`, `"issues"`, `"pull_request"`, or `"*"` for all events.
    /// Full list from n8n source:
    ///   *, check_run, check_suite, commit_comment, create, delete, deploy_key,
    ///   deployment, deployment_status, fork, github_app_authorization, gollum,
    ///   installation, installation_repositories, issue_comment, issues, label,
    ///   marketplace_purchase, member, membership, milestone, organization,
    ///   org_block, page_build, project, project_card, project_column, public,
    ///   pull_request, pull_request_review, pull_request_review_comment, push,
    ///   release, repository, repository_import, repository_vulnerability_alert,
    ///   security_advisory, star, status, team, team_add, watch
    pub events: Vec<String>,

    /// The repository owner this trigger is configured for (e.g., "n8n-io")
    pub owner: String,

    /// The repository name this trigger is configured for (e.g., "n8n")
    pub repository: String,

    /// The HMAC secret that n8n generated when registering the webhook with GitHub.
    ///
    /// n8n's GitHub Trigger node creates a random secret during workflow activation
    /// and stores it in the workflow's `staticData`. It then verifies incoming webhook
    /// payloads using `X-Hub-Signature-256` (HMAC-SHA256 of the raw body with this
    /// secret). When our middleware forwards events to n8n, we must re-sign the
    /// payload with this secret so n8n's verification passes.
    pub webhook_secret: Option<String>,
}

/// Extract a resource locator value from a node parameter.
///
/// n8n resource locator parameters can be in two formats:
/// 1. Object format: `{"__rl": true, "value": "n8n-io", "mode": "name"}`
/// 2. Simple string format: `"n8n-io"` (less common but possible)
fn extract_resource_locator_value(params: &serde_json::Value, field: &str) -> Option<String> {
    let param = params.get(field)?;

    // Try object format first (resource locator)
    if let Some(value) = param.get("value").and_then(|v| v.as_str())
        && !value.is_empty()
    {
        return Some(value.to_string());
    }

    // Fall back to simple string format
    if let Some(value) = param.as_str()
        && !value.is_empty()
    {
        return Some(value.to_string());
    }

    None
}

/// Extract the webhook secret from a workflow's staticData for a given node.
///
/// n8n stores per-node static data under `staticData["node:<NodeName>"]`.
/// For GitHub Trigger nodes, this object contains `webhookSecret` — the HMAC
/// secret n8n generated when it registered the webhook with GitHub.
fn extract_webhook_secret(workflow: &Workflow, node_name: &str) -> Option<String> {
    workflow
        .static_data
        .as_ref()?
        .get(format!("node:{}", node_name))?
        .get("webhookSecret")?
        .as_str()
        .map(|s| s.to_string())
}

/// Parse GitHub Trigger configuration from a workflow node
pub fn parse_github_trigger(
    workflow: &Workflow,
    node: &WorkflowNode,
) -> Option<GitHubTriggerConfig> {
    // Only process GitHub Trigger nodes
    if node.node_type != "n8n-nodes-base.githubTrigger" {
        return None;
    }

    let params = &node.parameters;

    // Extract events from "events" array
    // Format: "events": ["push", "issues"] or ["*"]
    let events: Vec<String> = params
        .get("events")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Extract owner and repository from resource locator parameters
    let owner = extract_resource_locator_value(params, "owner").unwrap_or_default();
    let repository = extract_resource_locator_value(params, "repository").unwrap_or_default();

    // Require a webhook ID — it's the correlation key for the database
    let webhook_id = node.webhook_id.as_ref()?;

    // Extract the webhook secret from staticData so we can re-sign forwarded
    // payloads for n8n's signature verification
    let webhook_secret = extract_webhook_secret(workflow, &node.name);

    Some(GitHubTriggerConfig {
        webhook_id: webhook_id.clone(),
        workflow_id: workflow.id.clone(),
        workflow_name: workflow.name.clone(),
        workflow_active: workflow.active,
        events,
        owner,
        repository,
        webhook_secret,
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

    // Helper to create a GitHub trigger node
    fn create_github_trigger_node(
        webhook_id: Option<&str>,
        params: serde_json::Value,
    ) -> WorkflowNode {
        WorkflowNode {
            node_type: "n8n-nodes-base.githubTrigger".to_string(),
            name: "GitHub Trigger".to_string(),
            parameters: params,
            webhook_id: webhook_id.map(|s| s.to_string()),
        }
    }

    // ==================== Parsing Tests ====================

    #[test]
    fn test_parse_github_trigger_basic() {
        let node = create_github_trigger_node(
            Some("webhook-gh1"),
            json!({
                "events": ["push"],
                "owner": {
                    "__rl": true,
                    "value": "n8n-io",
                    "mode": "name"
                },
                "repository": {
                    "__rl": true,
                    "value": "n8n",
                    "mode": "name"
                }
            }),
        );
        let workflow = create_workflow("wf1", "GitHub Workflow", vec![node.clone()]);

        let config = parse_github_trigger(&workflow, &node).unwrap();

        assert_eq!(config.webhook_id, "webhook-gh1");
        assert_eq!(config.workflow_id, "wf1");
        assert_eq!(config.workflow_name, "GitHub Workflow");
        assert_eq!(config.events, vec!["push"]);
        assert_eq!(config.owner, "n8n-io");
        assert_eq!(config.repository, "n8n");
    }

    #[test]
    fn test_parse_github_trigger_multiple_events() {
        let node = create_github_trigger_node(
            Some("webhook-gh2"),
            json!({
                "events": ["push", "issues", "pull_request"],
                "owner": {
                    "__rl": true,
                    "value": "testorg",
                    "mode": "name"
                },
                "repository": {
                    "__rl": true,
                    "value": "testrepo",
                    "mode": "name"
                }
            }),
        );
        let workflow = create_workflow("wf2", "Multi Event Workflow", vec![node.clone()]);

        let config = parse_github_trigger(&workflow, &node).unwrap();

        assert_eq!(config.events, vec!["push", "issues", "pull_request"]);
    }

    #[test]
    fn test_parse_github_trigger_wildcard() {
        let node = create_github_trigger_node(
            Some("webhook-gh3"),
            json!({
                "events": ["*"],
                "owner": {
                    "__rl": true,
                    "value": "testorg",
                    "mode": "name"
                },
                "repository": {
                    "__rl": true,
                    "value": "testrepo",
                    "mode": "name"
                }
            }),
        );
        let workflow = create_workflow("wf3", "Wildcard Workflow", vec![node.clone()]);

        let config = parse_github_trigger(&workflow, &node).unwrap();

        assert_eq!(config.events, vec!["*"]);
    }

    #[test]
    fn test_parse_github_trigger_empty_events() {
        let node = create_github_trigger_node(
            Some("webhook-gh4"),
            json!({
                "events": [],
                "owner": {
                    "__rl": true,
                    "value": "testorg",
                    "mode": "name"
                },
                "repository": {
                    "__rl": true,
                    "value": "testrepo",
                    "mode": "name"
                }
            }),
        );
        let workflow = create_workflow("wf4", "Empty Events Workflow", vec![node.clone()]);

        let config = parse_github_trigger(&workflow, &node).unwrap();

        assert!(config.events.is_empty());
    }

    #[test]
    fn test_parse_github_trigger_no_events_param() {
        let node = create_github_trigger_node(
            Some("webhook-gh5"),
            json!({
                "owner": {
                    "__rl": true,
                    "value": "testorg",
                    "mode": "name"
                },
                "repository": {
                    "__rl": true,
                    "value": "testrepo",
                    "mode": "name"
                }
            }),
        );
        let workflow = create_workflow("wf5", "No Events Workflow", vec![node.clone()]);

        let config = parse_github_trigger(&workflow, &node).unwrap();

        assert!(config.events.is_empty());
    }

    #[test]
    fn test_parse_non_github_node_returns_none() {
        let node = WorkflowNode {
            node_type: "n8n-nodes-base.httpRequest".to_string(),
            name: "HTTP Request".to_string(),
            parameters: json!({}),
            webhook_id: Some("webhook-123".to_string()),
        };
        let workflow = create_workflow("wf1", "Workflow", vec![node.clone()]);

        let config = parse_github_trigger(&workflow, &node);

        assert!(config.is_none());
    }

    #[test]
    fn test_parse_github_trigger_without_webhook_id() {
        let node = create_github_trigger_node(
            None,
            json!({
                "events": ["push"],
                "owner": { "__rl": true, "value": "testorg", "mode": "name" },
                "repository": { "__rl": true, "value": "testrepo", "mode": "name" }
            }),
        );
        let workflow = create_workflow("wf1", "Workflow", vec![node.clone()]);

        let config = parse_github_trigger(&workflow, &node);

        assert!(config.is_none());
    }

    #[test]
    fn test_parse_github_trigger_workflow_active_flag() {
        let node = create_github_trigger_node(
            Some("gh123"),
            json!({
                "events": ["push"],
                "owner": { "__rl": true, "value": "testorg", "mode": "name" },
                "repository": { "__rl": true, "value": "testrepo", "mode": "name" }
            }),
        );
        let mut workflow = create_workflow("wf1", "Active Workflow", vec![node.clone()]);

        // Active workflow
        let config = parse_github_trigger(&workflow, &node).unwrap();
        assert!(config.workflow_active);

        // Inactive workflow
        workflow.active = false;
        let config = parse_github_trigger(&workflow, &node).unwrap();
        assert!(!config.workflow_active);
    }

    #[test]
    fn test_parse_github_trigger_simple_string_params() {
        // Some older or simpler configs might use plain strings instead of resource locators
        let node = create_github_trigger_node(
            Some("gh123"),
            json!({
                "events": ["push"],
                "owner": "simple-owner",
                "repository": "simple-repo"
            }),
        );
        let workflow = create_workflow("wf1", "Workflow", vec![node.clone()]);

        let config = parse_github_trigger(&workflow, &node).unwrap();

        assert_eq!(config.owner, "simple-owner");
        assert_eq!(config.repository, "simple-repo");
    }

    #[test]
    fn test_parse_github_trigger_missing_owner_repo() {
        let node = create_github_trigger_node(
            Some("gh123"),
            json!({
                "events": ["push"]
            }),
        );
        let workflow = create_workflow("wf1", "Workflow", vec![node.clone()]);

        let config = parse_github_trigger(&workflow, &node).unwrap();

        assert_eq!(config.owner, "");
        assert_eq!(config.repository, "");
    }

    // ==================== Webhook Secret Extraction Tests ====================

    #[test]
    fn test_parse_github_trigger_extracts_webhook_secret() {
        let node = create_github_trigger_node(
            Some("gh-secret-1"),
            json!({
                "events": ["push"],
                "owner": "n8n-io",
                "repository": "n8n"
            }),
        );
        let mut workflow = create_workflow("wf1", "Workflow", vec![node.clone()]);
        workflow.static_data = Some(json!({
            "node:GitHub Trigger": {
                "webhookId": 1,
                "webhookEvents": ["push"],
                "webhookSecret": "abc123secret"
            }
        }));

        let config = parse_github_trigger(&workflow, &node).unwrap();

        assert_eq!(config.webhook_secret, Some("abc123secret".to_string()));
    }

    #[test]
    fn test_parse_github_trigger_no_static_data() {
        let node = create_github_trigger_node(
            Some("gh-no-sd"),
            json!({
                "events": ["push"],
                "owner": "n8n-io",
                "repository": "n8n"
            }),
        );
        let workflow = create_workflow("wf1", "Workflow", vec![node.clone()]);

        let config = parse_github_trigger(&workflow, &node).unwrap();

        assert_eq!(config.webhook_secret, None);
    }

    #[test]
    fn test_parse_github_trigger_static_data_missing_node_key() {
        let node = create_github_trigger_node(
            Some("gh-missing-key"),
            json!({
                "events": ["push"],
                "owner": "n8n-io",
                "repository": "n8n"
            }),
        );
        let mut workflow = create_workflow("wf1", "Workflow", vec![node.clone()]);
        workflow.static_data = Some(json!({
            "node:Some Other Node": {
                "webhookSecret": "should-not-match"
            }
        }));

        let config = parse_github_trigger(&workflow, &node).unwrap();

        assert_eq!(config.webhook_secret, None);
    }
}
