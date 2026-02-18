//! Common utilities for integration tests

#![allow(dead_code)]

pub mod docker;
pub mod jira;
pub mod n8n_client;
pub mod slack;

pub use docker::{
    DockerConfig, services_running, start_docker_env, stop_docker_env, wait_for_services,
};
pub use jira::*;
pub use n8n_client::{N8nTestClient, WorkflowResponse};
pub use slack::*;

use serde_json::Value;
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

/// Generate a simple unique identifier
pub(crate) fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}", nanos)
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

// ==================== Test Environment ====================

/// Test environment that manages setup and teardown
pub struct TestEnvironment {
    pub n8n_client: N8nTestClient,
    pub http_client: reqwest::Client,
    docker_config: DockerConfig,
    manage_docker: bool,
    /// Slack credential ID for attaching to Slack Trigger nodes
    slack_credential_id: Option<String>,
    /// Jira credential ID for attaching to Jira Trigger nodes
    jira_credential_id: Option<String>,
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

        // Get Jira credential ID from environment (created by test script)
        let jira_credential_id = std::env::var("JIRA_CREDENTIAL_ID").ok();
        if let Some(ref cred_id) = jira_credential_id {
            println!("Using Jira credential ID: {}", cred_id);
        }

        let n8n_client = N8nTestClient::new(N8N_URL).with_api_key(api_key);
        let http_client = reqwest::Client::new();

        Ok(Self {
            n8n_client,
            http_client,
            docker_config,
            manage_docker: should_manage,
            slack_credential_id,
            jira_credential_id,
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

        // If we have a Jira credential, attach it to the workflow's Jira Trigger nodes
        if let Some(ref cred_id) = self.jira_credential_id {
            self.n8n_client
                .attach_jira_credential(&workflow.id, cred_id)
                .await
                .map_err(|e| {
                    TestEnvError::N8nError(format!("Failed to attach Jira credential: {}", e))
                })?;
        }

        let activated = self
            .n8n_client
            .activate_workflow(&workflow.id)
            .await
            .map_err(|e| TestEnvError::N8nError(e.to_string()))?;

        // Give unihook time to refresh triggers
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

    /// Send a Jira event to the unihook middleware's /jira/events endpoint
    ///
    /// Forwards the payload as-is with content-type header.
    pub async fn send_jira_event(
        &self,
        payload: &Value,
    ) -> Result<reqwest::Response, TestEnvError> {
        let body = serde_json::to_string(payload).map_err(|e| {
            TestEnvError::RequestError(format!("Failed to serialize payload: {}", e))
        })?;

        self.http_client
            .post(format!("{}/jira/events", UNIHOOK_URL))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| TestEnvError::RequestError(e.to_string()))
    }

    /// Send a Slack event to unihook (automatically signed)
    ///
    /// This sends the event with proper Slack signature headers using the
    /// default test signing secret. All events are signed to match n8n's
    /// signature verification behavior.
    pub async fn send_slack_event(
        &self,
        payload: &Value,
    ) -> Result<reqwest::Response, TestEnvError> {
        // Always sign with the test signing secret
        self.send_signed_slack_event(payload, TEST_SLACK_SIGNING_SECRET)
            .await
    }

    /// Send a signed Slack event to unihook
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

    /// Get health status from unihook
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

// ==================== Error Types ====================

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

// ==================== Shared Test Helpers ====================

/// Node types to assign unique webhook IDs to during workflow loading
const TRIGGER_NODE_TYPES: &[&str] = &["n8n-nodes-base.slackTrigger", "n8n-nodes-base.jiraTrigger"];

/// Load a workflow fixture from the workflows directory.
///
/// Automatically assigns unique webhookIds to all trigger nodes (Slack, Jira, etc.)
/// to avoid conflicts between test runs.
pub fn load_workflow(name: &str) -> serde_json::Value {
    let path = format!(
        "{}/tests/integration/workflows/{}.json",
        env!("CARGO_MANIFEST_DIR"),
        name
    );
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("Failed to read workflow fixture: {}", path));
    let mut workflow: serde_json::Value =
        serde_json::from_str(&content).expect("Failed to parse workflow JSON");

    // Generate a unique suffix for webhook IDs
    let unique_id = uuid_simple();

    // Add webhookId to all known trigger node types
    if let Some(nodes) = workflow.get_mut("nodes").and_then(|n| n.as_array_mut()) {
        for node in nodes {
            let is_trigger = node
                .get("type")
                .and_then(|t| t.as_str())
                .is_some_and(|t| TRIGGER_NODE_TYPES.contains(&t));

            if is_trigger {
                node["webhookId"] =
                    serde_json::Value::String(format!("test-webhook-{}-{}", name, unique_id));
            }
        }
    }

    workflow
}

/// Get the execution count for a workflow
pub async fn get_execution_count(env: &TestEnvironment, workflow_id: &str) -> i64 {
    env.n8n_client
        .get_executions(Some(workflow_id))
        .await
        .map(|r| r.data.len() as i64)
        .unwrap_or(0)
}

/// Wait for a workflow's execution count to reach the expected value.
///
/// Polls every 500ms for up to 5 seconds.
pub async fn wait_for_execution(
    env: &TestEnvironment,
    workflow_id: &str,
    expected_count: i64,
) -> bool {
    for _ in 0..10 {
        let count = get_execution_count(env, workflow_id).await;
        if count >= expected_count {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    false
}

/// Wait for the Jira trigger count reported by the /health endpoint to reach
/// the expected value.
///
/// The trigger count is updated by the background refresh task, so after
/// activating or deactivating a workflow we need to poll until the refresh
/// picks up the change. Polls every second for up to 15 seconds (enough for
/// at least two refresh cycles with the default 5-second interval).
pub async fn wait_for_jira_trigger_count(env: &TestEnvironment, expected: i64) -> bool {
    for _ in 0..15 {
        if env
            .get_health()
            .await
            .is_ok_and(|h| h["jira_triggers_loaded"].as_i64().unwrap_or(-1) == expected)
        {
            return true;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    false
}
