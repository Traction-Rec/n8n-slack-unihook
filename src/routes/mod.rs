pub mod jira;
pub mod slack;

pub use jira::handle_jira_event;
pub use slack::handle_slack_event;

use crate::router::{JiraRouter, SlackRouter};
use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Json},
};
use std::sync::Arc;

/// Application state shared across handlers
pub struct AppState {
    pub slack_router: Arc<SlackRouter>,
    pub jira_router: Arc<JiraRouter>,
}

/// Extract headers that should be forwarded to n8n, filtering by allowed prefixes.
///
/// Only headers whose name starts with one of the given prefixes are included.
/// This is used by both the Slack and Jira route handlers with their respective
/// prefix lists (e.g. `x-slack-` vs `x-atlassian-`).
pub fn extract_forwarded_headers(headers: &HeaderMap, allowed_prefixes: &[&str]) -> HeaderMap {
    let mut forwarded = HeaderMap::new();
    for (name, value) in headers.iter() {
        let name_lower = name.as_str().to_lowercase();
        if allowed_prefixes
            .iter()
            .any(|prefix| name_lower.starts_with(prefix))
        {
            forwarded.insert(name.clone(), value.clone());
        }
    }
    forwarded
}

/// Health check endpoint
pub async fn health_check(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let slack_trigger_count = state.slack_router.trigger_count();
    let jira_trigger_count = state.jira_router.trigger_count();
    Json(serde_json::json!({
        "status": "healthy",
        "slack_triggers_loaded": slack_trigger_count,
        "jira_triggers_loaded": jira_trigger_count
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderName;
    use axum::http::HeaderValue;

    #[test]
    fn test_forwards_matching_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-slack-signature"),
            HeaderValue::from_static("v0=abc123"),
        );
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Bearer token123"),
        );

        let forwarded = extract_forwarded_headers(&headers, &["x-slack-", "content-type"]);

        assert_eq!(forwarded.len(), 2);
        assert!(forwarded.contains_key("x-slack-signature"));
        assert!(forwarded.contains_key("content-type"));
        assert!(!forwarded.contains_key("authorization"));
    }

    #[test]
    fn test_forwards_atlassian_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-atlassian-webhook-identifier"),
            HeaderValue::from_static("hook-123"),
        );
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            HeaderName::from_static("host"),
            HeaderValue::from_static("example.com"),
        );

        let forwarded = extract_forwarded_headers(&headers, &["x-atlassian-", "content-type"]);

        assert_eq!(forwarded.len(), 2);
        assert!(forwarded.contains_key("x-atlassian-webhook-identifier"));
        assert!(forwarded.contains_key("content-type"));
        assert!(!forwarded.contains_key("host"));
    }

    #[test]
    fn test_empty_headers_returns_empty() {
        let headers = HeaderMap::new();

        let forwarded = extract_forwarded_headers(&headers, &["x-slack-", "content-type"]);

        assert_eq!(forwarded.len(), 0);
    }

    #[test]
    fn test_no_matching_prefixes_returns_empty() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Bearer token123"),
        );
        headers.insert(
            HeaderName::from_static("host"),
            HeaderValue::from_static("example.com"),
        );

        let forwarded = extract_forwarded_headers(&headers, &["x-slack-", "content-type"]);

        assert_eq!(forwarded.len(), 0);
    }
}
