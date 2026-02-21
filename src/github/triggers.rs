use crate::n8n::{WebhookEndpoints, Workflow, WorkflowNode};

/// Extracted configuration from a GitHub Trigger node
#[derive(Debug, Clone)]
pub struct GitHubTriggerConfig {
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

impl GitHubTriggerConfig {
    /// Check if this trigger should receive a given GitHub event.
    ///
    /// Matches if:
    /// 1. The trigger listens for the wildcard `*` or the specific event type, AND
    /// 2. The owner and repository match the payload's repository info
    ///
    /// If the payload has no repository info (rare org-level events), only triggers
    /// with empty owner/repository will match.
    pub fn matches_event(
        &self,
        event_type: &str,
        owner: Option<&str>,
        repository: Option<&str>,
    ) -> bool {
        // Check event type match (wildcard or exact)
        let event_matches = self.events.iter().any(|e| e == "*" || e == event_type);
        if !event_matches {
            return false;
        }

        // Check owner/repository match (case-insensitive)
        let owner_matches = match owner {
            Some(o) => self.owner.eq_ignore_ascii_case(o),
            None => self.owner.is_empty(),
        };

        let repo_matches = match repository {
            Some(r) => self.repository.eq_ignore_ascii_case(r),
            None => self.repository.is_empty(),
        };

        owner_matches && repo_matches
    }
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
    base_url: &str,
    endpoints: &WebhookEndpoints,
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

    // Build webhook URLs from the node's webhook ID
    // n8n's GitHub Trigger webhook path is /{endpoint}/{webhookId}/webhook
    let webhook_id = node.webhook_id.as_ref()?;
    let base = base_url.trim_end_matches('/');

    let webhook_url = format!("{}/{}/{}/webhook", base, endpoints.production, webhook_id);
    let test_webhook_url = format!("{}/{}/{}/webhook", base, endpoints.test, webhook_id);

    // Extract the webhook secret from staticData so we can re-sign forwarded
    // payloads for n8n's signature verification
    let webhook_secret = extract_webhook_secret(workflow, &node.name);

    Some(GitHubTriggerConfig {
        workflow_id: workflow.id.clone(),
        workflow_name: workflow.name.clone(),
        workflow_active: workflow.active,
        webhook_url,
        test_webhook_url,
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

    // Helper to create a GitHubTriggerConfig for routing tests
    fn create_github_trigger_config(
        events: Vec<&str>,
        owner: &str,
        repository: &str,
    ) -> GitHubTriggerConfig {
        GitHubTriggerConfig {
            workflow_id: "wf1".to_string(),
            workflow_name: "Test GitHub Workflow".to_string(),
            workflow_active: true,
            webhook_url: "http://localhost:5678/webhook/abc123/webhook".to_string(),
            test_webhook_url: "http://localhost:5678/webhook-test/abc123/webhook".to_string(),
            events: events.iter().map(|s| s.to_string()).collect(),
            owner: owner.to_string(),
            repository: repository.to_string(),
            webhook_secret: None,
        }
    }

    // Default endpoints for tests
    fn default_endpoints() -> WebhookEndpoints {
        WebhookEndpoints::default()
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
        let endpoints = default_endpoints();

        let config =
            parse_github_trigger(&workflow, &node, "http://localhost:5678", &endpoints).unwrap();

        assert_eq!(config.workflow_id, "wf1");
        assert_eq!(config.workflow_name, "GitHub Workflow");
        assert_eq!(
            config.webhook_url,
            "http://localhost:5678/webhook/webhook-gh1/webhook"
        );
        assert_eq!(
            config.test_webhook_url,
            "http://localhost:5678/webhook-test/webhook-gh1/webhook"
        );
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
        let endpoints = default_endpoints();

        let config =
            parse_github_trigger(&workflow, &node, "http://localhost:5678", &endpoints).unwrap();

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
        let endpoints = default_endpoints();

        let config =
            parse_github_trigger(&workflow, &node, "http://localhost:5678", &endpoints).unwrap();

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
        let endpoints = default_endpoints();

        let config =
            parse_github_trigger(&workflow, &node, "http://localhost:5678", &endpoints).unwrap();

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
        let endpoints = default_endpoints();

        let config =
            parse_github_trigger(&workflow, &node, "http://localhost:5678", &endpoints).unwrap();

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
        let endpoints = default_endpoints();

        let config = parse_github_trigger(&workflow, &node, "http://localhost:5678", &endpoints);

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
        let endpoints = default_endpoints();

        let config = parse_github_trigger(&workflow, &node, "http://localhost:5678", &endpoints);

        assert!(config.is_none());
    }

    #[test]
    fn test_parse_github_trigger_webhook_url_trailing_slash() {
        let node = create_github_trigger_node(
            Some("gh123"),
            json!({
                "events": ["push"],
                "owner": { "__rl": true, "value": "testorg", "mode": "name" },
                "repository": { "__rl": true, "value": "testrepo", "mode": "name" }
            }),
        );
        let workflow = create_workflow("wf1", "Workflow", vec![node.clone()]);
        let endpoints = default_endpoints();

        let config =
            parse_github_trigger(&workflow, &node, "http://localhost:5678/", &endpoints).unwrap();

        assert_eq!(
            config.webhook_url,
            "http://localhost:5678/webhook/gh123/webhook"
        );
        assert_eq!(
            config.test_webhook_url,
            "http://localhost:5678/webhook-test/gh123/webhook"
        );
    }

    #[test]
    fn test_parse_github_trigger_custom_endpoints() {
        let node = create_github_trigger_node(
            Some("gh123"),
            json!({
                "events": ["push"],
                "owner": { "__rl": true, "value": "testorg", "mode": "name" },
                "repository": { "__rl": true, "value": "testrepo", "mode": "name" }
            }),
        );
        let workflow = create_workflow("wf1", "Workflow", vec![node.clone()]);
        let endpoints = WebhookEndpoints {
            production: "custom-webhook".to_string(),
            test: "custom-test".to_string(),
        };

        let config =
            parse_github_trigger(&workflow, &node, "http://localhost:5678", &endpoints).unwrap();

        assert_eq!(
            config.webhook_url,
            "http://localhost:5678/custom-webhook/gh123/webhook"
        );
        assert_eq!(
            config.test_webhook_url,
            "http://localhost:5678/custom-test/gh123/webhook"
        );
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
        let endpoints = default_endpoints();

        // Active workflow
        let config =
            parse_github_trigger(&workflow, &node, "http://localhost:5678", &endpoints).unwrap();
        assert!(config.workflow_active);

        // Inactive workflow
        workflow.active = false;
        let config =
            parse_github_trigger(&workflow, &node, "http://localhost:5678", &endpoints).unwrap();
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
        let endpoints = default_endpoints();

        let config =
            parse_github_trigger(&workflow, &node, "http://localhost:5678", &endpoints).unwrap();

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
        let endpoints = default_endpoints();

        let config =
            parse_github_trigger(&workflow, &node, "http://localhost:5678", &endpoints).unwrap();

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
        let endpoints = default_endpoints();

        let config =
            parse_github_trigger(&workflow, &node, "http://localhost:5678", &endpoints).unwrap();

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
        let endpoints = default_endpoints();

        let config =
            parse_github_trigger(&workflow, &node, "http://localhost:5678", &endpoints).unwrap();

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
        let endpoints = default_endpoints();

        let config =
            parse_github_trigger(&workflow, &node, "http://localhost:5678", &endpoints).unwrap();

        assert_eq!(config.webhook_secret, None);
    }

    // ==================== Routing Logic Tests ====================

    #[test]
    fn test_github_matches_exact_event() {
        let trigger = create_github_trigger_config(vec!["push"], "n8n-io", "n8n");

        assert!(trigger.matches_event("push", Some("n8n-io"), Some("n8n")));
    }

    #[test]
    fn test_github_no_match_wrong_event() {
        let trigger = create_github_trigger_config(vec!["push"], "n8n-io", "n8n");

        assert!(!trigger.matches_event("issues", Some("n8n-io"), Some("n8n")));
    }

    #[test]
    fn test_github_wildcard_matches_any_event() {
        let trigger = create_github_trigger_config(vec!["*"], "n8n-io", "n8n");

        assert!(trigger.matches_event("push", Some("n8n-io"), Some("n8n")));
        assert!(trigger.matches_event("issues", Some("n8n-io"), Some("n8n")));
        assert!(trigger.matches_event("pull_request", Some("n8n-io"), Some("n8n")));
        assert!(trigger.matches_event("star", Some("n8n-io"), Some("n8n")));
        assert!(trigger.matches_event("release", Some("n8n-io"), Some("n8n")));
    }

    #[test]
    fn test_github_no_match_wrong_owner() {
        let trigger = create_github_trigger_config(vec!["push"], "n8n-io", "n8n");

        assert!(!trigger.matches_event("push", Some("other-org"), Some("n8n")));
    }

    #[test]
    fn test_github_no_match_wrong_repository() {
        let trigger = create_github_trigger_config(vec!["push"], "n8n-io", "n8n");

        assert!(!trigger.matches_event("push", Some("n8n-io"), Some("other-repo")));
    }

    #[test]
    fn test_github_multiple_events_match() {
        let trigger = create_github_trigger_config(vec!["push", "issues"], "n8n-io", "n8n");

        assert!(trigger.matches_event("push", Some("n8n-io"), Some("n8n")));
        assert!(trigger.matches_event("issues", Some("n8n-io"), Some("n8n")));
        assert!(!trigger.matches_event("pull_request", Some("n8n-io"), Some("n8n")));
    }

    #[test]
    fn test_github_empty_events_no_match() {
        let trigger = create_github_trigger_config(vec![], "n8n-io", "n8n");

        assert!(!trigger.matches_event("push", Some("n8n-io"), Some("n8n")));
    }

    #[test]
    fn test_github_owner_matching_case_insensitive() {
        let trigger = create_github_trigger_config(vec!["push"], "N8N-IO", "n8n");

        assert!(trigger.matches_event("push", Some("n8n-io"), Some("n8n")));
        assert!(trigger.matches_event("push", Some("N8N-IO"), Some("n8n")));
    }

    #[test]
    fn test_github_repo_matching_case_insensitive() {
        let trigger = create_github_trigger_config(vec!["push"], "n8n-io", "N8N");

        assert!(trigger.matches_event("push", Some("n8n-io"), Some("n8n")));
        assert!(trigger.matches_event("push", Some("n8n-io"), Some("N8N")));
    }

    #[test]
    fn test_github_no_repo_info_no_match() {
        // Event without repository info should not match triggers scoped to a repo
        let trigger = create_github_trigger_config(vec!["*"], "n8n-io", "n8n");

        assert!(!trigger.matches_event("push", None, None));
    }

    #[test]
    fn test_github_all_event_types_matchable() {
        // Verify all known n8n GitHub Trigger event types can be matched
        let all_events = vec![
            "check_run",
            "check_suite",
            "commit_comment",
            "create",
            "delete",
            "deploy_key",
            "deployment",
            "deployment_status",
            "fork",
            "github_app_authorization",
            "gollum",
            "installation",
            "installation_repositories",
            "issue_comment",
            "issues",
            "label",
            "marketplace_purchase",
            "member",
            "membership",
            "milestone",
            "organization",
            "org_block",
            "page_build",
            "project",
            "project_card",
            "project_column",
            "public",
            "pull_request",
            "pull_request_review",
            "pull_request_review_comment",
            "push",
            "release",
            "repository",
            "repository_import",
            "repository_vulnerability_alert",
            "security_advisory",
            "star",
            "status",
            "team",
            "team_add",
            "watch",
        ];

        let trigger = create_github_trigger_config(all_events.clone(), "n8n-io", "n8n");

        for event in &all_events {
            assert!(
                trigger.matches_event(event, Some("n8n-io"), Some("n8n")),
                "Expected trigger to match event: {}",
                event
            );
        }
    }
}
