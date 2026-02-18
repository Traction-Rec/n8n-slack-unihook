//! Slack-specific test payload helpers and signature computation

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

use super::uuid_simple;

type HmacSha256 = Hmac<Sha256>;

/// Compute a Slack request signature
///
/// The signature is computed as:
/// sig_basestring = "v0:" + timestamp + ":" + request_body
/// signature = "v0=" + HMAC-SHA256(signing_secret, sig_basestring).hex()
pub fn compute_slack_signature(signing_secret: &str, timestamp: &str, body: &str) -> String {
    let sig_basestring = format!("v0:{}:{}", timestamp, body);

    let mut mac = HmacSha256::new_from_slice(signing_secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(sig_basestring.as_bytes());

    let result = mac.finalize();
    let signature_bytes = result.into_bytes();

    format!("v0={}", hex::encode(signature_bytes))
}

/// Create a Slack URL verification challenge payload
pub fn create_url_verification_payload(challenge: &str) -> Value {
    serde_json::json!({
        "type": "url_verification",
        "challenge": challenge
    })
}

/// Create a Slack message event payload
pub fn create_message_event_payload(channel: &str, text: &str) -> Value {
    serde_json::json!({
        "type": "event_callback",
        "token": "test-token",
        "team_id": "T12345",
        "api_app_id": "A12345",
        "event": {
            "type": "message",
            "channel": channel,
            "user": "U12345",
            "text": text,
            "ts": "1234567890.123456"
        },
        "event_id": format!("Ev{}", uuid_simple()),
        "event_time": 1234567890
    })
}

/// Create a Slack reaction added event payload
pub fn create_reaction_event_payload(channel: &str, reaction: &str) -> Value {
    serde_json::json!({
        "type": "event_callback",
        "token": "test-token",
        "team_id": "T12345",
        "api_app_id": "A12345",
        "event": {
            "type": "reaction_added",
            "user": "U12345",
            "reaction": reaction,
            "item": {
                "type": "message",
                "channel": channel,
                "ts": "1234567890.123456"
            },
            "event_ts": "1234567890.123456"
        },
        "event_id": format!("Ev{}", uuid_simple()),
        "event_time": 1234567890
    })
}

/// Create an app mention event payload
pub fn create_app_mention_payload(channel: &str, text: &str) -> Value {
    serde_json::json!({
        "type": "event_callback",
        "token": "test-token",
        "team_id": "T12345",
        "api_app_id": "A12345",
        "event": {
            "type": "app_mention",
            "channel": channel,
            "user": "U12345",
            "text": text,
            "ts": "1234567890.123456"
        },
        "event_id": format!("Ev{}", uuid_simple()),
        "event_time": 1234567890
    })
}
