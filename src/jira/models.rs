use serde::Deserialize;

/// Minimal deserialization of a Jira webhook payload.
///
/// Jira sends a JSON body with a `webhookEvent` field that identifies the
/// event type (e.g., `"jira:issue_created"`, `"comment_updated"`).
/// We only parse the fields we need for routing; the full body is forwarded
/// as-is to n8n to preserve authentication and payload integrity.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct JiraWebhookPayload {
    /// The event type sent by Jira (e.g., "jira:issue_created")
    #[serde(rename = "webhookEvent")]
    pub webhook_event: String,

    /// Capture any additional fields (we don't need them for routing,
    /// but this lets us inspect the payload in logs if needed)
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_issue_created_event() {
        let json = r#"{
            "webhookEvent": "jira:issue_created",
            "timestamp": 1234567890,
            "issue": {
                "id": "10001",
                "key": "PROJ-123",
                "fields": {
                    "summary": "Test issue"
                }
            }
        }"#;

        let payload: JiraWebhookPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.webhook_event, "jira:issue_created");
    }

    #[test]
    fn test_parse_comment_created_event() {
        let json = r#"{
            "webhookEvent": "comment_created",
            "timestamp": 1234567890,
            "comment": {
                "id": "10042",
                "body": "This is a comment"
            }
        }"#;

        let payload: JiraWebhookPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.webhook_event, "comment_created");
    }

    #[test]
    fn test_parse_board_event() {
        let json = r#"{
            "webhookEvent": "board_created",
            "board": {
                "id": 1,
                "name": "My Board"
            }
        }"#;

        let payload: JiraWebhookPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.webhook_event, "board_created");
    }

    #[test]
    fn test_parse_sprint_event() {
        let json = r#"{
            "webhookEvent": "sprint_started",
            "sprint": {
                "id": 42,
                "name": "Sprint 1"
            }
        }"#;

        let payload: JiraWebhookPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.webhook_event, "sprint_started");
    }

    #[test]
    fn test_parse_version_event() {
        let json = r#"{
            "webhookEvent": "jira:version_released",
            "version": {
                "id": "10000",
                "name": "v1.0"
            }
        }"#;

        let payload: JiraWebhookPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.webhook_event, "jira:version_released");
    }

    #[test]
    fn test_parse_worklog_event() {
        let json = r#"{
            "webhookEvent": "worklog_created",
            "worklog": {
                "id": "100"
            }
        }"#;

        let payload: JiraWebhookPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.webhook_event, "worklog_created");
    }

    #[test]
    fn test_parse_user_event() {
        let json = r#"{
            "webhookEvent": "user_created",
            "user": {
                "accountId": "abc123"
            }
        }"#;

        let payload: JiraWebhookPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.webhook_event, "user_created");
    }

    #[test]
    fn test_parse_minimal_payload() {
        let json = r#"{"webhookEvent": "jira:issue_updated"}"#;

        let payload: JiraWebhookPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.webhook_event, "jira:issue_updated");
    }

    #[test]
    fn test_extra_fields_captured() {
        let json = r#"{
            "webhookEvent": "jira:issue_created",
            "timestamp": 1234567890,
            "custom_field": "value"
        }"#;

        let payload: JiraWebhookPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.webhook_event, "jira:issue_created");
        assert_eq!(payload.extra["timestamp"], 1234567890);
        assert_eq!(payload.extra["custom_field"], "value");
    }
}
