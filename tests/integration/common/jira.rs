//! Jira-specific test payload helpers

use serde_json::Value;

/// Create a Jira issue created webhook payload
pub fn create_jira_issue_created_payload(project_key: &str, issue_key: &str) -> Value {
    serde_json::json!({
        "webhookEvent": "jira:issue_created",
        "timestamp": 1234567890000i64,
        "issue": {
            "id": "10001",
            "key": issue_key,
            "fields": {
                "summary": "Test issue",
                "project": {
                    "key": project_key
                },
                "issuetype": {
                    "name": "Task"
                }
            }
        },
        "user": {
            "accountId": "test-user-123",
            "displayName": "Test User"
        }
    })
}

/// Create a Jira issue updated webhook payload
pub fn create_jira_issue_updated_payload(project_key: &str, issue_key: &str) -> Value {
    serde_json::json!({
        "webhookEvent": "jira:issue_updated",
        "timestamp": 1234567890000i64,
        "issue": {
            "id": "10001",
            "key": issue_key,
            "fields": {
                "summary": "Updated issue",
                "project": {
                    "key": project_key
                }
            }
        },
        "user": {
            "accountId": "test-user-123",
            "displayName": "Test User"
        },
        "changelog": {
            "items": [
                {
                    "field": "summary",
                    "fromString": "Old summary",
                    "toString": "Updated issue"
                }
            ]
        }
    })
}

/// Create a Jira comment created webhook payload
pub fn create_jira_comment_created_payload(issue_key: &str, comment_body: &str) -> Value {
    serde_json::json!({
        "webhookEvent": "comment_created",
        "timestamp": 1234567890000i64,
        "issue": {
            "id": "10001",
            "key": issue_key,
            "fields": {
                "summary": "Test issue"
            }
        },
        "comment": {
            "id": "10042",
            "body": comment_body,
            "author": {
                "accountId": "test-user-123",
                "displayName": "Test User"
            }
        }
    })
}

/// Create a generic Jira webhook payload with a specified event type
pub fn create_jira_event_payload(webhook_event: &str) -> Value {
    serde_json::json!({
        "webhookEvent": webhook_event,
        "timestamp": 1234567890000i64
    })
}
