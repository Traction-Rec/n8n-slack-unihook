//! GitHub-specific test payload helpers

use serde_json::Value;

/// Create a GitHub push event webhook payload
pub fn create_github_push_payload(owner: &str, repo: &str) -> Value {
    serde_json::json!({
        "ref": "refs/heads/main",
        "before": "0000000000000000000000000000000000000000",
        "after": "abc123def456789012345678901234567890abcd",
        "repository": {
            "name": repo,
            "full_name": format!("{}/{}", owner, repo),
            "owner": {
                "login": owner
            }
        },
        "pusher": {
            "name": "test-user",
            "email": "test@example.com"
        },
        "sender": {
            "login": "test-user",
            "id": 1
        },
        "commits": [
            {
                "id": "abc123def456789012345678901234567890abcd",
                "message": "Test commit",
                "author": {
                    "name": "Test User",
                    "email": "test@example.com"
                }
            }
        ]
    })
}

/// Create a GitHub issues event webhook payload
pub fn create_github_issues_payload(owner: &str, repo: &str, action: &str) -> Value {
    serde_json::json!({
        "action": action,
        "issue": {
            "number": 1,
            "title": "Test issue",
            "state": "open",
            "user": {
                "login": "test-user"
            }
        },
        "repository": {
            "name": repo,
            "full_name": format!("{}/{}", owner, repo),
            "owner": {
                "login": owner
            }
        },
        "sender": {
            "login": "test-user",
            "id": 1
        }
    })
}

/// Create a GitHub pull_request event webhook payload
pub fn create_github_pull_request_payload(owner: &str, repo: &str, action: &str) -> Value {
    serde_json::json!({
        "action": action,
        "number": 1,
        "pull_request": {
            "number": 1,
            "title": "Test PR",
            "state": "open",
            "user": {
                "login": "test-user"
            }
        },
        "repository": {
            "name": repo,
            "full_name": format!("{}/{}", owner, repo),
            "owner": {
                "login": owner
            }
        },
        "sender": {
            "login": "test-user",
            "id": 1
        }
    })
}

/// Create a GitHub ping event webhook payload (sent when webhook is first created)
pub fn create_github_ping_payload(owner: &str, repo: &str) -> Value {
    serde_json::json!({
        "zen": "Speak like a human.",
        "hook_id": 12345,
        "hook": {
            "type": "Repository",
            "id": 12345,
            "events": ["push"],
            "active": true
        },
        "repository": {
            "name": repo,
            "full_name": format!("{}/{}", owner, repo),
            "owner": {
                "login": owner
            }
        },
        "sender": {
            "login": "test-user",
            "id": 1
        }
    })
}
