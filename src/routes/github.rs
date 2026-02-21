use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::crypto::verify_hmac_sha256;
use crate::github::GitHubWebhookPayload;

use super::{AppState, extract_forwarded_headers};

/// Headers to forward from GitHub to n8n webhooks
/// We forward content-type, GitHub-specific headers, and the hub signature
const GITHUB_FORWARDED_HEADER_PREFIXES: &[&str] = &["x-github-", "x-hub-signature", "content-type"];

/// Handle incoming GitHub webhook events
///
/// This endpoint:
/// 1. If `GITHUB_WEBHOOK_SECRET` is configured, verifies the `X-Hub-Signature-256`
///    header using HMAC-SHA256 (returns 401 if invalid or missing)
/// 2. Extracts the event type from the `X-GitHub-Event` header
/// 3. Parses the repository owner/name from the payload body
/// 4. Detects and acknowledges ping events without routing
/// 5. Routes real events to all matching n8n workflows with GitHub triggers
/// 6. Forwards the raw body and relevant headers to preserve webhook authentication
pub async fn handle_github_event(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    // Verify inbound signature if a shared secret is configured
    if let Some(ref secret) = state.config.github_webhook_secret {
        let signature = headers
            .get("x-hub-signature-256")
            .and_then(|v| v.to_str().ok());

        match signature {
            Some(sig) if verify_hmac_sha256(secret, body.as_bytes(), sig) => {
                debug!("GitHub webhook signature verified successfully");
            }
            Some(_) => {
                warn!("GitHub webhook signature verification failed");
                return (StatusCode::UNAUTHORIZED, "Invalid signature").into_response();
            }
            None => {
                warn!("Missing X-Hub-Signature-256 header but GITHUB_WEBHOOK_SECRET is set");
                return (StatusCode::UNAUTHORIZED, "Missing signature").into_response();
            }
        }
    }

    // Extract the event type from the X-GitHub-Event header
    let event_type = match headers.get("x-github-event").and_then(|v| v.to_str().ok()) {
        Some(et) => et.to_string(),
        None => {
            warn!("Missing X-GitHub-Event header");
            return (StatusCode::BAD_REQUEST, "Missing X-GitHub-Event header").into_response();
        }
    };

    // Parse the payload to extract repository info and detect pings
    let payload: GitHubWebhookPayload = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "Failed to parse GitHub webhook payload");
            debug!(body = %body, "Raw payload that failed to parse");
            return (StatusCode::BAD_REQUEST, "Invalid GitHub webhook payload").into_response();
        }
    };

    // Handle ping events -- return OK but don't route to workflows
    // GitHub sends a ping when a webhook is first created
    if payload.is_ping() {
        info!(
            event_type = %event_type,
            hook_id = ?payload.hook_id,
            "Received GitHub ping event, acknowledging"
        );
        return StatusCode::OK.into_response();
    }

    // Extract owner/repo from the payload for routing
    let (owner, repository) = match &payload.repository {
        Some(repo) => (Some(repo.owner.login.as_str()), Some(repo.name.as_str())),
        None => (None, None),
    };

    info!(
        event_type = %event_type,
        owner = ?owner,
        repository = ?repository,
        "Received GitHub event"
    );

    // Extract headers to forward to n8n
    let forwarded_headers = extract_forwarded_headers(&headers, GITHUB_FORWARDED_HEADER_PREFIXES);
    debug!(
        forwarded_header_count = forwarded_headers.len(),
        "Extracted headers to forward"
    );

    // Route the event asynchronously but respond immediately
    let github_router = state.github_router.clone();
    let event_type_owned = event_type.clone();
    let owner_owned = owner.map(|s| s.to_string());
    let repo_owned = repository.map(|s| s.to_string());
    tokio::spawn(async move {
        github_router
            .route_event(
                &event_type_owned,
                owner_owned.as_deref(),
                repo_owned.as_deref(),
                body,
                forwarded_headers,
            )
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

        let forwarded = extract_forwarded_headers(&headers, GITHUB_FORWARDED_HEADER_PREFIXES);

        assert_eq!(forwarded.len(), 1);
        assert_eq!(forwarded.get("content-type").unwrap(), "application/json");
    }

    #[test]
    fn test_forwards_github_event_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-github-event"),
            HeaderValue::from_static("push"),
        );

        let forwarded = extract_forwarded_headers(&headers, GITHUB_FORWARDED_HEADER_PREFIXES);

        assert_eq!(forwarded.len(), 1);
        assert_eq!(forwarded.get("x-github-event").unwrap(), "push");
    }

    #[test]
    fn test_forwards_github_delivery_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-github-delivery"),
            HeaderValue::from_static("abc-123-def"),
        );

        let forwarded = extract_forwarded_headers(&headers, GITHUB_FORWARDED_HEADER_PREFIXES);

        assert_eq!(forwarded.len(), 1);
        assert_eq!(forwarded.get("x-github-delivery").unwrap(), "abc-123-def");
    }

    #[test]
    fn test_forwards_hub_signature_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-hub-signature-256"),
            HeaderValue::from_static("sha256=abc123"),
        );

        let forwarded = extract_forwarded_headers(&headers, GITHUB_FORWARDED_HEADER_PREFIXES);

        assert_eq!(forwarded.len(), 1);
        assert_eq!(
            forwarded.get("x-hub-signature-256").unwrap(),
            "sha256=abc123"
        );
    }

    #[test]
    fn test_forwards_multiple_github_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-github-event"),
            HeaderValue::from_static("push"),
        );
        headers.insert(
            HeaderName::from_static("x-github-delivery"),
            HeaderValue::from_static("abc-123"),
        );
        headers.insert(
            HeaderName::from_static("x-github-hook-id"),
            HeaderValue::from_static("12345"),
        );
        headers.insert(
            HeaderName::from_static("x-hub-signature-256"),
            HeaderValue::from_static("sha256=abc"),
        );
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );

        let forwarded = extract_forwarded_headers(&headers, GITHUB_FORWARDED_HEADER_PREFIXES);

        assert_eq!(forwarded.len(), 5);
        assert!(forwarded.contains_key("x-github-event"));
        assert!(forwarded.contains_key("x-github-delivery"));
        assert!(forwarded.contains_key("x-github-hook-id"));
        assert!(forwarded.contains_key("x-hub-signature-256"));
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
            HeaderValue::from_static("GitHub-Hookshot/abc123"),
        );

        let forwarded = extract_forwarded_headers(&headers, GITHUB_FORWARDED_HEADER_PREFIXES);

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
            HeaderName::from_static("x-github-event"),
            HeaderValue::from_static("push"),
        );
        headers.insert(
            HeaderName::from_static("x-hub-signature-256"),
            HeaderValue::from_static("sha256=abc"),
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

        let forwarded = extract_forwarded_headers(&headers, GITHUB_FORWARDED_HEADER_PREFIXES);

        assert_eq!(forwarded.len(), 3);
        assert!(forwarded.contains_key("content-type"));
        assert!(forwarded.contains_key("x-github-event"));
        assert!(forwarded.contains_key("x-hub-signature-256"));
        assert!(!forwarded.contains_key("authorization"));
        assert!(!forwarded.contains_key("host"));
    }

    #[test]
    fn test_empty_headers_returns_empty() {
        let headers = HeaderMap::new();

        let forwarded = extract_forwarded_headers(&headers, GITHUB_FORWARDED_HEADER_PREFIXES);

        assert_eq!(forwarded.len(), 0);
    }
}
