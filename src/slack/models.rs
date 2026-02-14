use serde::{Deserialize, Serialize};

/// The outer envelope for all Slack Events API payloads.
/// This handles both URL verification challenges and actual events.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum SlackPayload {
    /// Slack sends this when verifying the webhook URL
    #[serde(rename = "url_verification")]
    UrlVerification { challenge: String },

    /// Slack sends this for actual events
    #[serde(rename = "event_callback")]
    EventCallback(Box<SlackEventCallback>),
}

/// The event callback wrapper containing the actual event
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct SlackEventCallback {
    /// The Slack team/workspace ID
    pub team_id: String,

    /// The API app ID
    pub api_app_id: String,

    /// Unique event ID for deduplication
    pub event_id: String,

    /// Unix timestamp of when the event was dispatched
    pub event_time: u64,

    /// The actual event data
    pub event: SlackEvent,

    /// Optional authorizations array
    #[serde(default)]
    pub authorizations: Vec<SlackAuthorization>,
}

/// Authorization info for the event
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct SlackAuthorization {
    pub enterprise_id: Option<String>,
    pub team_id: Option<String>,
    pub user_id: Option<String>,
    pub is_bot: bool,
    pub is_enterprise_install: bool,
}

/// The actual Slack event with common fields.
/// We use a flexible structure to capture various event types.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct SlackEvent {
    /// Event type (e.g., "message", "reaction_added", "app_mention")
    #[serde(rename = "type")]
    pub event_type: String,

    /// Channel where the event occurred (not present for all events)
    pub channel: Option<String>,

    /// User who triggered the event (not present for all events)
    pub user: Option<String>,

    /// Timestamp of the event/message
    pub ts: Option<String>,

    /// For message events, the text content
    pub text: Option<String>,

    /// For reaction events, the reaction name
    pub reaction: Option<String>,

    /// Subtype for message events (e.g., "bot_message", "file_share")
    pub subtype: Option<String>,

    /// For file events
    pub file_id: Option<String>,

    /// For channel events
    pub channel_type: Option<String>,

    /// Bot ID if the event was triggered by a bot
    pub bot_id: Option<String>,

    /// Capture any additional fields we don't explicitly handle
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Response for URL verification challenge
#[derive(Debug, Serialize)]
pub struct UrlVerificationResponse {
    pub challenge: String,
}

impl SlackEvent {
    /// Maps Slack event types to n8n Slack Trigger event names.
    /// Returns the event type string that n8n uses for filtering.
    /// Note: n8n uses snake_case format (e.g., "reaction_added", "any_event")
    pub fn to_n8n_event_type(&self) -> &str {
        match self.event_type.as_str() {
            "message" => {
                // Check for subtypes that map to different n8n events
                match self.subtype.as_deref() {
                    Some("file_share") => "file_shared",
                    _ => "message",
                }
            }
            "reaction_added" => "reaction_added",
            "app_mention" => "app_mention",
            "channel_created" => "channel_created",
            "team_join" => "user_created",
            "file_public" => "file_public",
            "file_shared" => "file_shared",
            _ => &self.event_type,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_verification_parsing() {
        let json = r#"{
            "type": "url_verification",
            "challenge": "test-challenge-token"
        }"#;

        let payload: SlackPayload = serde_json::from_str(json).unwrap();
        match payload {
            SlackPayload::UrlVerification { challenge } => {
                assert_eq!(challenge, "test-challenge-token");
            }
            _ => panic!("Expected UrlVerification"),
        }
    }

    #[test]
    fn test_event_callback_parsing() {
        let json = r#"{
            "type": "event_callback",
            "team_id": "T123456",
            "api_app_id": "A123456",
            "event_id": "Ev123456",
            "event_time": 1234567890,
            "event": {
                "type": "message",
                "channel": "C123456",
                "user": "U123456",
                "text": "Hello world",
                "ts": "1234567890.123456"
            }
        }"#;

        let payload: SlackPayload = serde_json::from_str(json).unwrap();
        match payload {
            SlackPayload::EventCallback(callback) => {
                assert_eq!(callback.team_id, "T123456");
                assert_eq!(callback.api_app_id, "A123456");
                assert_eq!(callback.event_id, "Ev123456");
                assert_eq!(callback.event_time, 1234567890);
                assert_eq!(callback.event.event_type, "message");
                assert_eq!(callback.event.channel, Some("C123456".to_string()));
            }
            _ => panic!("Expected EventCallback"),
        }
    }

    #[test]
    fn test_message_event_parsing() {
        let json = r#"{
            "type": "message",
            "channel": "C123456",
            "user": "U123456",
            "text": "Hello world",
            "ts": "1234567890.123456"
        }"#;

        let event: SlackEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.event_type, "message");
        assert_eq!(event.channel, Some("C123456".to_string()));
        assert_eq!(event.user, Some("U123456".to_string()));
        assert_eq!(event.text, Some("Hello world".to_string()));
        assert_eq!(event.ts, Some("1234567890.123456".to_string()));
    }

    #[test]
    fn test_reaction_event_parsing() {
        let json = r#"{
            "type": "reaction_added",
            "user": "U123456",
            "reaction": "thumbsup",
            "item": {
                "type": "message",
                "channel": "C123456",
                "ts": "1234567890.123456"
            }
        }"#;

        let event: SlackEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.event_type, "reaction_added");
        assert_eq!(event.user, Some("U123456".to_string()));
        assert_eq!(event.reaction, Some("thumbsup".to_string()));
    }

    #[test]
    fn test_app_mention_parsing() {
        let json = r#"{
            "type": "app_mention",
            "channel": "C123456",
            "user": "U123456",
            "text": "<@U987654> hello bot",
            "ts": "1234567890.123456"
        }"#;

        let event: SlackEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.event_type, "app_mention");
        assert_eq!(event.channel, Some("C123456".to_string()));
        assert_eq!(event.text, Some("<@U987654> hello bot".to_string()));
    }

    #[test]
    fn test_event_type_mapping_message() {
        let event = SlackEvent {
            event_type: "message".to_string(),
            channel: Some("C123".to_string()),
            user: None,
            ts: None,
            text: None,
            reaction: None,
            subtype: None,
            file_id: None,
            channel_type: None,
            bot_id: None,
            extra: serde_json::Value::Null,
        };
        assert_eq!(event.to_n8n_event_type(), "message");
    }

    #[test]
    fn test_event_type_mapping_file_share() {
        let event = SlackEvent {
            event_type: "message".to_string(),
            channel: Some("C123".to_string()),
            user: None,
            ts: None,
            text: None,
            reaction: None,
            subtype: Some("file_share".to_string()),
            file_id: None,
            channel_type: None,
            bot_id: None,
            extra: serde_json::Value::Null,
        };
        assert_eq!(event.to_n8n_event_type(), "file_shared");
    }

    #[test]
    fn test_event_type_mapping_reaction() {
        let event = SlackEvent {
            event_type: "reaction_added".to_string(),
            channel: None,
            user: None,
            ts: None,
            text: None,
            reaction: Some("thumbsup".to_string()),
            subtype: None,
            file_id: None,
            channel_type: None,
            bot_id: None,
            extra: serde_json::Value::Null,
        };
        assert_eq!(event.to_n8n_event_type(), "reaction_added");
    }

    #[test]
    fn test_event_type_mapping_app_mention() {
        let event = SlackEvent {
            event_type: "app_mention".to_string(),
            channel: Some("C123".to_string()),
            user: None,
            ts: None,
            text: None,
            reaction: None,
            subtype: None,
            file_id: None,
            channel_type: None,
            bot_id: None,
            extra: serde_json::Value::Null,
        };
        assert_eq!(event.to_n8n_event_type(), "app_mention");
    }

    #[test]
    fn test_event_type_mapping_channel_created() {
        let event = SlackEvent {
            event_type: "channel_created".to_string(),
            channel: None,
            user: None,
            ts: None,
            text: None,
            reaction: None,
            subtype: None,
            file_id: None,
            channel_type: None,
            bot_id: None,
            extra: serde_json::Value::Null,
        };
        assert_eq!(event.to_n8n_event_type(), "channel_created");
    }

    #[test]
    fn test_event_type_mapping_team_join() {
        let event = SlackEvent {
            event_type: "team_join".to_string(),
            channel: None,
            user: None,
            ts: None,
            text: None,
            reaction: None,
            subtype: None,
            file_id: None,
            channel_type: None,
            bot_id: None,
            extra: serde_json::Value::Null,
        };
        assert_eq!(event.to_n8n_event_type(), "user_created");
    }

    #[test]
    fn test_event_type_mapping_unknown_passthrough() {
        let event = SlackEvent {
            event_type: "some_unknown_event".to_string(),
            channel: None,
            user: None,
            ts: None,
            text: None,
            reaction: None,
            subtype: None,
            file_id: None,
            channel_type: None,
            bot_id: None,
            extra: serde_json::Value::Null,
        };
        assert_eq!(event.to_n8n_event_type(), "some_unknown_event");
    }
}
