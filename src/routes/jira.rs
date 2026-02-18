use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::jira::JiraWebhookPayload;

use super::{AppState, extract_forwarded_headers};

/// Headers to forward from Jira to n8n webhooks
/// We forward content-type and any Atlassian-specific headers
const JIRA_FORWARDED_HEADER_PREFIXES: &[&str] = &["x-atlassian-", "content-type"];

/// Handle incoming Jira webhook events
///
/// This endpoint:
/// 1. Parses the `webhookEvent` field from the Jira payload to determine the event type
/// 2. Routes the event to all matching n8n workflows with Jira triggers
/// 3. Forwards the raw body and relevant headers to preserve webhook authentication
pub async fn handle_jira_event(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    // Parse the raw JSON to extract the webhookEvent field
    let payload: JiraWebhookPayload = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "Failed to parse Jira webhook payload");
            debug!(body = %body, "Raw payload that failed to parse");
            return (StatusCode::BAD_REQUEST, "Invalid Jira webhook payload").into_response();
        }
    };

    info!(
        webhook_event = %payload.webhook_event,
        "Received Jira event"
    );

    // Extract headers to forward to n8n
    let forwarded_headers = extract_forwarded_headers(&headers, JIRA_FORWARDED_HEADER_PREFIXES);
    debug!(
        forwarded_header_count = forwarded_headers.len(),
        "Extracted headers to forward"
    );

    // Route the event asynchronously but respond immediately
    let jira_router = state.jira_router.clone();
    let webhook_event = payload.webhook_event.clone();
    tokio::spawn(async move {
        jira_router
            .route_event(&webhook_event, body, forwarded_headers)
            .await;
    });

    // Return 200 OK immediately to acknowledge receipt
    StatusCode::OK.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderName;
    use axum::http::HeaderValue;

    #[test]
    fn test_forwards_content_type_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );

        let forwarded = extract_forwarded_headers(&headers, JIRA_FORWARDED_HEADER_PREFIXES);

        assert_eq!(forwarded.len(), 1);
        assert_eq!(forwarded.get("content-type").unwrap(), "application/json");
    }

    #[test]
    fn test_forwards_atlassian_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-atlassian-webhook-identifier"),
            HeaderValue::from_static("hook-123"),
        );
        headers.insert(
            HeaderName::from_static("x-atlassian-token"),
            HeaderValue::from_static("no-check"),
        );

        let forwarded = extract_forwarded_headers(&headers, JIRA_FORWARDED_HEADER_PREFIXES);

        assert_eq!(forwarded.len(), 2);
        assert!(forwarded.contains_key("x-atlassian-webhook-identifier"));
        assert!(forwarded.contains_key("x-atlassian-token"));
    }

    #[test]
    fn test_does_not_forward_arbitrary_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Bearer token123"),
        );
        headers.insert(
            HeaderName::from_static("x-custom-header"),
            HeaderValue::from_static("custom-value"),
        );
        headers.insert(
            HeaderName::from_static("host"),
            HeaderValue::from_static("example.com"),
        );
        headers.insert(
            HeaderName::from_static("user-agent"),
            HeaderValue::from_static("Jira/1.0"),
        );

        let forwarded = extract_forwarded_headers(&headers, JIRA_FORWARDED_HEADER_PREFIXES);

        assert_eq!(forwarded.len(), 0);
    }

    #[test]
    fn test_filters_mixed_headers() {
        let mut headers = HeaderMap::new();
        // Should be forwarded
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            HeaderName::from_static("x-atlassian-webhook-identifier"),
            HeaderValue::from_static("hook-123"),
        );
        // Should NOT be forwarded
        headers.insert(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Bearer token123"),
        );
        headers.insert(
            HeaderName::from_static("host"),
            HeaderValue::from_static("example.com"),
        );

        let forwarded = extract_forwarded_headers(&headers, JIRA_FORWARDED_HEADER_PREFIXES);

        assert_eq!(forwarded.len(), 2);
        assert!(forwarded.contains_key("content-type"));
        assert!(forwarded.contains_key("x-atlassian-webhook-identifier"));
        assert!(!forwarded.contains_key("authorization"));
        assert!(!forwarded.contains_key("host"));
    }

    #[test]
    fn test_empty_headers_returns_empty() {
        let headers = HeaderMap::new();

        let forwarded = extract_forwarded_headers(&headers, JIRA_FORWARDED_HEADER_PREFIXES);

        assert_eq!(forwarded.len(), 0);
    }
}
