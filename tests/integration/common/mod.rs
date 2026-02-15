//! Common utilities for integration tests

#![allow(dead_code)]

pub mod docker;
pub mod n8n_client;

pub use docker::{
    DockerConfig, services_running, start_docker_env, stop_docker_env, wait_for_services,
};
pub use n8n_client::{N8nTestClient, WorkflowResponse};

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use std::sync::OnceLock;
use std::time::Duration;

/// Test environment URLs
pub const N8N_URL: &str = "http://localhost:6789";
pub const UNIHOOK_URL: &str = "http://localhost:3000";

/// Test user credentials for n8n setup
pub const TEST_EMAIL: &str = "test@example.com";
pub const TEST_PASSWORD: &str = "TestPassword123"; // Must contain uppercase
pub const TEST_FIRST_NAME: &str = "Test";
pub const TEST_LAST_NAME: &str = "User";

/// Test Slack signing secret for signature verification tests
/// This must match the signing secret configured in the test Slack credential
pub const TEST_SLACK_SIGNING_SECRET: &str = "test-signing-secret-for-integration-tests";

/// Default timeout for waiting on services
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

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

/// Global API key storage (set once during test setup)
static API_KEY: OnceLock<String> = OnceLock::new();

/// Get the API key from environment or create one if needed
///
/// The test script should set TEST_N8N_API_KEY environment variable
pub async fn get_or_create_api_key() -> Result<String, TestEnvError> {
    // Return cached key if available
    if let Some(key) = API_KEY.get() {
        return Ok(key.clone());
    }

    // Check if API key is provided via environment (from the test script)
    if let Ok(key) = std::env::var("TEST_N8N_API_KEY") {
        let _ = API_KEY.set(key.clone());
        return Ok(key);
    }

    // Otherwise, set up n8n and create an API key
    let client = N8nTestClient::new(N8N_URL);

    // Check if n8n needs initial setup
    let needs_setup = client
        .needs_setup()
        .await
        .map_err(|e| TestEnvError::N8nError(format!("Failed to check n8n setup status: {}", e)))?;

    if needs_setup {
        println!("Setting up n8n owner account...");
        client
            .setup_owner(TEST_EMAIL, TEST_PASSWORD, TEST_FIRST_NAME, TEST_LAST_NAME)
            .await
            .map_err(|e| TestEnvError::N8nError(format!("Failed to setup n8n owner: {}", e)))?;
        println!("Owner account created successfully");
    }

    // Create an API key with a unique label
    println!("Creating API key...");
    let api_key = client
        .create_api_key(TEST_EMAIL, TEST_PASSWORD)
        .await
        .map_err(|e| TestEnvError::N8nError(format!("Failed to create API key: {}", e)))?;

    println!("API key created successfully");

    // Store for future use (ignore error if already set by another thread)
    let _ = API_KEY.set(api_key.clone());

    Ok(api_key)
}

/// Test environment that manages setup and teardown
pub struct TestEnvironment {
    pub n8n_client: N8nTestClient,
    pub http_client: reqwest::Client,
    docker_config: DockerConfig,
    manage_docker: bool,
    /// Slack credential ID for attaching to Slack Trigger nodes
    slack_credential_id: Option<String>,
}

impl TestEnvironment {
    /// Create a new test environment
    /// If `manage_docker` is true, will start/stop Docker automatically
    pub async fn new(manage_docker: bool) -> Result<Self, TestEnvError> {
        let docker_config = DockerConfig::default();

        // Check if services are already running
        let already_running = services_running(N8N_URL, UNIHOOK_URL).await;

        let should_manage = manage_docker && !already_running;

        if should_manage {
            start_docker_env(&docker_config)
                .map_err(|e| TestEnvError::DockerError(e.to_string()))?;

            wait_for_services(N8N_URL, UNIHOOK_URL, DEFAULT_TIMEOUT)
                .await
                .map_err(|e| TestEnvError::DockerError(e.to_string()))?;
        } else if !already_running {
            return Err(TestEnvError::ServicesNotRunning(
                "Services are not running. Start them with: docker compose -f docker-compose.test.yml up -d".to_string()
            ));
        }

        // Get or create API key for n8n
        let api_key = get_or_create_api_key().await?;

        // Get Slack credential ID from environment (created by test script)
        let slack_credential_id = std::env::var("SLACK_CREDENTIAL_ID").ok();
        if let Some(ref cred_id) = slack_credential_id {
            println!("Using Slack credential ID: {}", cred_id);
        }

        let n8n_client = N8nTestClient::new(N8N_URL).with_api_key(api_key);
        let http_client = reqwest::Client::new();

        Ok(Self {
            n8n_client,
            http_client,
            docker_config,
            manage_docker: should_manage,
            slack_credential_id,
        })
    }

    /// Import and activate a test workflow
    /// If a Slack credential ID is available, it will be attached to Slack Trigger nodes
    pub async fn setup_workflow(
        &self,
        workflow_json: &Value,
    ) -> Result<WorkflowResponse, TestEnvError> {
        let workflow = self
            .n8n_client
            .import_workflow(workflow_json)
            .await
            .map_err(|e| TestEnvError::N8nError(e.to_string()))?;

        // If we have a Slack credential, attach it to the workflow's Slack Trigger nodes
        if let Some(ref cred_id) = self.slack_credential_id {
            self.n8n_client
                .attach_slack_credential(&workflow.id, cred_id)
                .await
                .map_err(|e| {
                    TestEnvError::N8nError(format!("Failed to attach Slack credential: {}", e))
                })?;
        }

        let activated = self
            .n8n_client
            .activate_workflow(&workflow.id)
            .await
            .map_err(|e| TestEnvError::N8nError(e.to_string()))?;

        // Give slack-unihook time to refresh triggers
        tokio::time::sleep(Duration::from_secs(6)).await;

        Ok(activated)
    }

    /// Clean up a specific workflow
    pub async fn cleanup_workflow(&self, workflow_id: &str) -> Result<(), TestEnvError> {
        let _ = self.n8n_client.deactivate_workflow(workflow_id).await;
        self.n8n_client
            .delete_workflow(workflow_id)
            .await
            .map_err(|e| TestEnvError::N8nError(e.to_string()))?;
        Ok(())
    }

    /// Clean up all workflows
    pub async fn cleanup_all(&self) -> Result<(), TestEnvError> {
        self.n8n_client
            .cleanup_all_workflows()
            .await
            .map_err(|e| TestEnvError::N8nError(e.to_string()))?;
        Ok(())
    }

    /// Send a Slack event to slack-unihook
    pub async fn send_slack_event(
        &self,
        payload: &Value,
    ) -> Result<reqwest::Response, TestEnvError> {
        self.http_client
            .post(format!("{}/slack/events", UNIHOOK_URL))
            .json(payload)
            .send()
            .await
            .map_err(|e| TestEnvError::RequestError(e.to_string()))
    }

    /// Send a signed Slack event to slack-unihook
    ///
    /// This sends the event with proper Slack signature headers, exactly as
    /// Slack would send it. The raw body is sent as-is (not re-serialized)
    /// to ensure the signature remains valid.
    pub async fn send_signed_slack_event(
        &self,
        payload: &Value,
        signing_secret: &str,
    ) -> Result<reqwest::Response, TestEnvError> {
        // Serialize the payload to a string (this is the "raw" body)
        let body = serde_json::to_string(payload).map_err(|e| {
            TestEnvError::RequestError(format!("Failed to serialize payload: {}", e))
        })?;

        // Get current timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();

        // Compute the signature
        let signature = compute_slack_signature(signing_secret, &timestamp, &body);

        // Send with Slack headers
        self.http_client
            .post(format!("{}/slack/events", UNIHOOK_URL))
            .header("content-type", "application/json")
            .header("x-slack-signature", signature)
            .header("x-slack-request-timestamp", timestamp)
            .body(body)
            .send()
            .await
            .map_err(|e| TestEnvError::RequestError(e.to_string()))
    }

    /// Get health status from slack-unihook
    pub async fn get_health(&self) -> Result<Value, TestEnvError> {
        let response = self
            .http_client
            .get(format!("{}/health", UNIHOOK_URL))
            .send()
            .await
            .map_err(|e| TestEnvError::RequestError(e.to_string()))?;

        response
            .json()
            .await
            .map_err(|e| TestEnvError::RequestError(e.to_string()))
    }
}

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        if self.manage_docker {
            let _ = stop_docker_env(&self.docker_config);
        }
    }
}

#[derive(Debug)]
pub enum TestEnvError {
    DockerError(String),
    N8nError(String),
    RequestError(String),
    ServicesNotRunning(String),
}

impl std::fmt::Display for TestEnvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TestEnvError::DockerError(msg) => write!(f, "Docker error: {}", msg),
            TestEnvError::N8nError(msg) => write!(f, "n8n error: {}", msg),
            TestEnvError::RequestError(msg) => write!(f, "Request error: {}", msg),
            TestEnvError::ServicesNotRunning(msg) => write!(f, "Services not running: {}", msg),
        }
    }
}

impl std::error::Error for TestEnvError {}

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

/// Generate a simple unique identifier
fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}", nanos)
}
