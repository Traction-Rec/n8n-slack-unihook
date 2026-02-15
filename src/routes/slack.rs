use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
};
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::router::Router;
use crate::slack::{SlackPayload, UrlVerificationResponse};

/// Application state shared across handlers
pub struct AppState {
    pub router: Arc<Router>,
}

/// Headers to forward from Slack to n8n webhooks
const FORWARDED_HEADER_PREFIXES: &[&str] = &["x-slack-", "content-type"];

/// Extract headers that should be forwarded to n8n
fn extract_forwarded_headers(headers: &HeaderMap) -> HeaderMap {
    let mut forwarded = HeaderMap::new();
    for (name, value) in headers.iter() {
        let name_lower = name.as_str().to_lowercase();
        if FORWARDED_HEADER_PREFIXES
            .iter()
            .any(|prefix| name_lower.starts_with(prefix))
        {
            forwarded.insert(name.clone(), value.clone());
        }
    }
    forwarded
}

/// Handle incoming Slack events
///
/// This endpoint handles:
/// 1. URL verification challenges from Slack
/// 2. Event callbacks that get routed to matching n8n workflows
pub async fn handle_slack_event(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    // Parse the raw JSON first to keep the original payload for forwarding
    let raw_payload: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "Failed to parse Slack payload as JSON");
            return (StatusCode::BAD_REQUEST, "Invalid JSON").into_response();
        }
    };

    // Parse into our typed structure
    let payload: SlackPayload = match serde_json::from_value(raw_payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "Failed to parse Slack payload structure");
            debug!(body = %body, "Raw payload that failed to parse");
            return (StatusCode::BAD_REQUEST, "Invalid Slack payload").into_response();
        }
    };

    match payload {
        SlackPayload::UrlVerification { challenge } => {
            info!("Received URL verification challenge from Slack");
            Json(UrlVerificationResponse { challenge }).into_response()
        }
        SlackPayload::EventCallback(callback) => {
            info!(
                event_type = %callback.event.event_type,
                event_id = %callback.event_id,
                team_id = %callback.team_id,
                "Received Slack event"
            );

            // Extract headers to forward to n8n
            let forwarded_headers = extract_forwarded_headers(&headers);
            debug!(
                forwarded_header_count = forwarded_headers.len(),
                "Extracted headers to forward"
            );

            // Route the event asynchronously but respond immediately to Slack
            // Slack requires a response within 3 seconds
            // IMPORTANT: We pass the raw body string (not re-serialized JSON) to preserve
            // the exact bytes for Slack signature verification
            let router = state.router.clone();
            tokio::spawn(async move {
                router.route_event(&callback, body, forwarded_headers).await;
            });

            // Return 200 OK immediately to acknowledge receipt
            StatusCode::OK.into_response()
        }
    }
}

/// Health check endpoint
pub async fn health_check(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let trigger_count = state.router.trigger_count();
    Json(serde_json::json!({
        "status": "healthy",
        "triggers_loaded": trigger_count
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderName;
    use axum::http::HeaderValue;

    #[test]
    fn test_forwards_slack_signature_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-slack-signature"),
            HeaderValue::from_static("v0=abc123"),
        );

        let forwarded = extract_forwarded_headers(&headers);

        assert_eq!(forwarded.len(), 1);
        assert_eq!(forwarded.get("x-slack-signature").unwrap(), "v0=abc123");
    }

    #[test]
    fn test_forwards_slack_request_timestamp_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-slack-request-timestamp"),
            HeaderValue::from_static("1234567890"),
        );

        let forwarded = extract_forwarded_headers(&headers);

        assert_eq!(forwarded.len(), 1);
        assert_eq!(
            forwarded.get("x-slack-request-timestamp").unwrap(),
            "1234567890"
        );
    }

    #[test]
    fn test_forwards_content_type_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );

        let forwarded = extract_forwarded_headers(&headers);

        assert_eq!(forwarded.len(), 1);
        assert_eq!(forwarded.get("content-type").unwrap(), "application/json");
    }

    #[test]
    fn test_forwards_multiple_slack_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-slack-signature"),
            HeaderValue::from_static("v0=abc123"),
        );
        headers.insert(
            HeaderName::from_static("x-slack-request-timestamp"),
            HeaderValue::from_static("1234567890"),
        );
        headers.insert(
            HeaderName::from_static("x-slack-retry-num"),
            HeaderValue::from_static("1"),
        );
        headers.insert(
            HeaderName::from_static("x-slack-retry-reason"),
            HeaderValue::from_static("http_timeout"),
        );
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );

        let forwarded = extract_forwarded_headers(&headers);

        assert_eq!(forwarded.len(), 5);
        assert!(forwarded.contains_key("x-slack-signature"));
        assert!(forwarded.contains_key("x-slack-request-timestamp"));
        assert!(forwarded.contains_key("x-slack-retry-num"));
        assert!(forwarded.contains_key("x-slack-retry-reason"));
        assert!(forwarded.contains_key("content-type"));
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
            HeaderValue::from_static("Slackbot"),
        );

        let forwarded = extract_forwarded_headers(&headers);

        assert_eq!(forwarded.len(), 0);
        assert!(!forwarded.contains_key("authorization"));
        assert!(!forwarded.contains_key("x-custom-header"));
        assert!(!forwarded.contains_key("host"));
        assert!(!forwarded.contains_key("user-agent"));
    }

    #[test]
    fn test_filters_mixed_headers() {
        let mut headers = HeaderMap::new();
        // Should be forwarded
        headers.insert(
            HeaderName::from_static("x-slack-signature"),
            HeaderValue::from_static("v0=abc123"),
        );
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
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

        let forwarded = extract_forwarded_headers(&headers);

        assert_eq!(forwarded.len(), 2);
        assert!(forwarded.contains_key("x-slack-signature"));
        assert!(forwarded.contains_key("content-type"));
        assert!(!forwarded.contains_key("authorization"));
        assert!(!forwarded.contains_key("host"));
    }

    #[test]
    fn test_empty_headers_returns_empty() {
        let headers = HeaderMap::new();

        let forwarded = extract_forwarded_headers(&headers);

        assert_eq!(forwarded.len(), 0);
    }

    #[test]
    fn test_header_matching_is_case_insensitive() {
        let mut headers = HeaderMap::new();
        // HTTP headers are case-insensitive, but HeaderMap normalizes to lowercase
        // This test verifies our prefix matching works correctly
        headers.insert(
            HeaderName::from_static("x-slack-signature"),
            HeaderValue::from_static("v0=abc123"),
        );

        let forwarded = extract_forwarded_headers(&headers);

        assert_eq!(forwarded.len(), 1);
        // The key should be accessible regardless of case in the original
        assert!(forwarded.get("x-slack-signature").is_some());
    }
}
