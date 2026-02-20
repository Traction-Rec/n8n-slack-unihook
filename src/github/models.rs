use serde::Deserialize;

/// Minimal deserialization of a GitHub webhook payload.
///
/// GitHub sends a JSON body with repository information and event-specific data.
/// The event type itself comes from the `X-GitHub-Event` header, not from the body.
///
/// We only parse the fields we need for routing; the full body is forwarded
/// as-is to n8n to preserve authentication and payload integrity.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct GitHubWebhookPayload {
    /// Repository information (present on most events, absent on some org-level events)
    pub repository: Option<GitHubRepository>,

    /// Present on ping events sent when a webhook is first created
    pub hook_id: Option<u64>,

    /// Action field (e.g., "opened", "closed") -- present on most events except push/ping
    pub action: Option<String>,

    /// Capture any additional fields (we don't need them for routing,
    /// but this lets us inspect the payload in logs if needed)
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Repository information from a GitHub webhook payload
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct GitHubRepository {
    /// Repository name (e.g., "n8n")
    pub name: String,

    /// Full repository name (e.g., "n8n-io/n8n")
    pub full_name: String,

    /// Repository owner
    pub owner: GitHubOwner,
}

/// Repository owner from a GitHub webhook payload
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct GitHubOwner {
    /// Owner login name (e.g., "n8n-io")
    pub login: String,
}

impl GitHubWebhookPayload {
    /// Check if this payload is a ping event.
    ///
    /// GitHub sends a ping event when a webhook is first created. These have
    /// `hook_id` set but no `action` field. We detect them to return 200 OK
    /// without routing to workflows (matching n8n's own behavior).
    pub fn is_ping(&self) -> bool {
        self.hook_id.is_some() && self.action.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_push_event_payload() {
        let json = r#"{
            "ref": "refs/heads/main",
            "before": "abc123",
            "after": "def456",
            "repository": {
                "name": "n8n",
                "full_name": "n8n-io/n8n",
                "owner": {
                    "login": "n8n-io"
                }
            },
            "pusher": {
                "name": "testuser"
            }
        }"#;

        let payload: GitHubWebhookPayload = serde_json::from_str(json).unwrap();
        let repo = payload.repository.as_ref().unwrap();
        assert_eq!(repo.name, "n8n");
        assert_eq!(repo.full_name, "n8n-io/n8n");
        assert_eq!(repo.owner.login, "n8n-io");
        assert!(payload.hook_id.is_none());
        assert!(payload.action.is_none());
        assert!(!payload.is_ping());
    }

    #[test]
    fn test_parse_issues_event_payload() {
        let json = r#"{
            "action": "opened",
            "issue": {
                "number": 42,
                "title": "Test issue"
            },
            "repository": {
                "name": "my-repo",
                "full_name": "testuser/my-repo",
                "owner": {
                    "login": "testuser"
                }
            }
        }"#;

        let payload: GitHubWebhookPayload = serde_json::from_str(json).unwrap();
        let repo = payload.repository.as_ref().unwrap();
        assert_eq!(repo.name, "my-repo");
        assert_eq!(repo.owner.login, "testuser");
        assert_eq!(payload.action.as_deref(), Some("opened"));
        assert!(!payload.is_ping());
    }

    #[test]
    fn test_parse_pull_request_event_payload() {
        let json = r#"{
            "action": "opened",
            "number": 1,
            "pull_request": {
                "title": "Fix bug"
            },
            "repository": {
                "name": "project",
                "full_name": "org/project",
                "owner": {
                    "login": "org"
                }
            }
        }"#;

        let payload: GitHubWebhookPayload = serde_json::from_str(json).unwrap();
        let repo = payload.repository.as_ref().unwrap();
        assert_eq!(repo.name, "project");
        assert_eq!(repo.full_name, "org/project");
        assert_eq!(repo.owner.login, "org");
        assert_eq!(payload.action.as_deref(), Some("opened"));
    }

    #[test]
    fn test_parse_ping_event() {
        let json = r#"{
            "zen": "Speak like a human.",
            "hook_id": 12345,
            "hook": {
                "type": "Repository",
                "id": 12345,
                "events": ["push"]
            },
            "repository": {
                "name": "my-repo",
                "full_name": "testuser/my-repo",
                "owner": {
                    "login": "testuser"
                }
            }
        }"#;

        let payload: GitHubWebhookPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.hook_id, Some(12345));
        assert!(payload.action.is_none());
        assert!(payload.is_ping());
    }

    #[test]
    fn test_parse_ping_with_action_is_not_ping() {
        // If somehow both hook_id and action are present, it's not a ping
        let json = r#"{
            "hook_id": 12345,
            "action": "created",
            "repository": {
                "name": "my-repo",
                "full_name": "testuser/my-repo",
                "owner": {
                    "login": "testuser"
                }
            }
        }"#;

        let payload: GitHubWebhookPayload = serde_json::from_str(json).unwrap();
        assert!(!payload.is_ping());
    }

    #[test]
    fn test_parse_payload_without_repository() {
        // Some org-level events may not have repository info
        let json = r#"{
            "action": "member_added",
            "membership": {
                "user": {
                    "login": "testuser"
                }
            }
        }"#;

        let payload: GitHubWebhookPayload = serde_json::from_str(json).unwrap();
        assert!(payload.repository.is_none());
        assert_eq!(payload.action.as_deref(), Some("member_added"));
    }

    #[test]
    fn test_parse_minimal_payload() {
        let json = r#"{}"#;

        let payload: GitHubWebhookPayload = serde_json::from_str(json).unwrap();
        assert!(payload.repository.is_none());
        assert!(payload.hook_id.is_none());
        assert!(payload.action.is_none());
        assert!(!payload.is_ping());
    }

    #[test]
    fn test_extra_fields_captured() {
        let json = r#"{
            "action": "opened",
            "custom_field": "value",
            "number": 42,
            "repository": {
                "name": "repo",
                "full_name": "user/repo",
                "owner": {
                    "login": "user"
                }
            }
        }"#;

        let payload: GitHubWebhookPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.extra["custom_field"], "value");
        assert_eq!(payload.extra["number"], 42);
    }
}
