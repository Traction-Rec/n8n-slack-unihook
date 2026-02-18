//! n8n API client for test setup and verification

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Test client for interacting with n8n API
pub struct N8nTestClient {
    client: Client,
    base_url: String,
    api_key: Option<String>,
}

impl N8nTestClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: None,
        }
    }

    /// Set the API key for authenticated requests
    pub fn with_api_key(mut self, api_key: String) -> Self {
        self.api_key = Some(api_key);
        self
    }

    /// Check if n8n needs initial owner setup
    pub async fn needs_setup(&self) -> Result<bool, N8nTestError> {
        let url = format!("{}/rest/settings", self.base_url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| N8nTestError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(N8nTestError::RequestFailed(
                "Failed to get settings".to_string(),
            ));
        }

        let settings: SettingsResponse = response
            .json()
            .await
            .map_err(|e| N8nTestError::ParseError(e.to_string()))?;

        Ok(settings.data.user_management.show_setup_on_first_load)
    }

    /// Complete the initial owner setup for n8n
    pub async fn setup_owner(
        &self,
        email: &str,
        password: &str,
        first_name: &str,
        last_name: &str,
    ) -> Result<SetupResponse, N8nTestError> {
        let url = format!("{}/rest/owner/setup", self.base_url);

        let payload = serde_json::json!({
            "email": email,
            "password": password,
            "firstName": first_name,
            "lastName": last_name
        });

        let response = self
            .client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| N8nTestError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(N8nTestError::ApiError {
                status: status.as_u16(),
                body,
            });
        }

        let wrapper: DataWrapper<SetupResponse> = response
            .json()
            .await
            .map_err(|e| N8nTestError::ParseError(e.to_string()))?;

        Ok(wrapper.data)
    }

    /// Create an API key using cookie-based authentication
    pub async fn create_api_key(
        &self,
        email: &str,
        password: &str,
    ) -> Result<String, N8nTestError> {
        // Create a client with cookie store enabled
        let client = Client::builder()
            .cookie_store(true)
            .build()
            .map_err(|e| N8nTestError::RequestFailed(e.to_string()))?;

        // Login first
        let login_url = format!("{}/rest/login", self.base_url);

        let login_payload = serde_json::json!({
            "emailOrLdapLoginId": email,
            "password": password
        });

        let login_response = client
            .post(&login_url)
            .json(&login_payload)
            .send()
            .await
            .map_err(|e| N8nTestError::RequestFailed(e.to_string()))?;

        if !login_response.status().is_success() {
            let status = login_response.status();
            let body = login_response.text().await.unwrap_or_default();
            return Err(N8nTestError::ApiError {
                status: status.as_u16(),
                body: format!("Login failed: {}", body),
            });
        }

        // Create API key with required scopes and expiration (1 year from now)
        let api_key_url = format!("{}/rest/api-keys", self.base_url);

        // Calculate expiration timestamp (1 year from now in milliseconds)
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
            + (365 * 24 * 60 * 60 * 1000);

        let api_key_payload = serde_json::json!({
            "label": "integration-test-key",
            "scopes": [
                "workflow:create",
                "workflow:delete",
                "workflow:read",
                "workflow:update",
                "workflow:list",
                "workflow:execute"
            ],
            "expiresAt": expires_at
        });

        let api_key_response = client
            .post(&api_key_url)
            .json(&api_key_payload)
            .send()
            .await
            .map_err(|e| N8nTestError::RequestFailed(e.to_string()))?;

        if !api_key_response.status().is_success() {
            let status = api_key_response.status();
            let body = api_key_response.text().await.unwrap_or_default();
            return Err(N8nTestError::ApiError {
                status: status.as_u16(),
                body: format!("Failed to create API key: {}", body),
            });
        }

        let api_key_data: DataWrapper<ApiKeyResponse> = api_key_response
            .json()
            .await
            .map_err(|e| N8nTestError::ParseError(e.to_string()))?;

        Ok(api_key_data.data.raw_api_key)
    }

    /// Import a workflow from JSON
    pub async fn import_workflow(
        &self,
        workflow_json: &Value,
    ) -> Result<WorkflowResponse, N8nTestError> {
        let url = format!("{}/api/v1/workflows", self.base_url);

        let mut request = self.client.post(&url);

        if let Some(ref api_key) = self.api_key {
            request = request.header("X-N8N-API-KEY", api_key);
        }

        let response = request
            .json(workflow_json)
            .send()
            .await
            .map_err(|e| N8nTestError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(N8nTestError::ApiError {
                status: status.as_u16(),
                body,
            });
        }

        response
            .json()
            .await
            .map_err(|e| N8nTestError::ParseError(e.to_string()))
    }

    /// Attach Slack API credential to all Slack Trigger nodes in a workflow
    /// This is required for n8n to properly register the webhook for the trigger
    pub async fn attach_slack_credential(
        &self,
        workflow_id: &str,
        credential_id: &str,
    ) -> Result<(), N8nTestError> {
        // First, get the current workflow
        let workflow = self.get_workflow(workflow_id).await?;

        // Find and update Slack Trigger nodes with the credential
        let nodes_value = workflow
            .get("nodes")
            .ok_or_else(|| N8nTestError::ParseError("No nodes field in workflow".to_string()))?;

        let mut nodes: Vec<serde_json::Value> = serde_json::from_value(nodes_value.clone())
            .map_err(|e| N8nTestError::ParseError(format!("Failed to parse nodes: {}", e)))?;

        let mut updated = false;

        for node in &mut nodes {
            if node.get("type").and_then(|t| t.as_str()) == Some("n8n-nodes-base.slackTrigger") {
                // Add credentials to this node
                let credentials = serde_json::json!({
                    "slackApi": {
                        "id": credential_id,
                        "name": "Test Slack API"
                    }
                });
                node.as_object_mut()
                    .unwrap()
                    .insert("credentials".to_string(), credentials);
                updated = true;
            }
        }

        if !updated {
            // No Slack Trigger nodes found, nothing to do
            return Ok(());
        }

        // Build update payload with only the required fields for PUT
        let update_payload = serde_json::json!({
            "name": workflow.get("name").cloned().unwrap_or(serde_json::json!("Workflow")),
            "nodes": nodes,
            "connections": workflow.get("connections").cloned().unwrap_or(serde_json::json!({})),
            "settings": workflow.get("settings").cloned().unwrap_or(serde_json::json!({}))
        });

        self.update_workflow(workflow_id, &update_payload).await?;

        Ok(())
    }

    /// Attach Jira Software Cloud API credential to all Jira Trigger nodes in a workflow
    /// This is required for n8n to properly register the webhook for the trigger
    pub async fn attach_jira_credential(
        &self,
        workflow_id: &str,
        credential_id: &str,
    ) -> Result<(), N8nTestError> {
        // First, get the current workflow
        let workflow = self.get_workflow(workflow_id).await?;

        // Find and update Jira Trigger nodes with the credential
        let nodes_value = workflow
            .get("nodes")
            .ok_or_else(|| N8nTestError::ParseError("No nodes field in workflow".to_string()))?;

        let mut nodes: Vec<serde_json::Value> = serde_json::from_value(nodes_value.clone())
            .map_err(|e| N8nTestError::ParseError(format!("Failed to parse nodes: {}", e)))?;

        let mut updated = false;

        for node in &mut nodes {
            if node.get("type").and_then(|t| t.as_str()) == Some("n8n-nodes-base.jiraTrigger") {
                // Add credentials to this node
                let credentials = serde_json::json!({
                    "jiraSoftwareCloudApi": {
                        "id": credential_id,
                        "name": "Test Jira Software Cloud API"
                    }
                });
                node.as_object_mut()
                    .unwrap()
                    .insert("credentials".to_string(), credentials);
                updated = true;
            }
        }

        if !updated {
            // No Jira Trigger nodes found, nothing to do
            return Ok(());
        }

        // Build update payload with only the required fields for PUT
        let update_payload = serde_json::json!({
            "name": workflow.get("name").cloned().unwrap_or(serde_json::json!("Workflow")),
            "nodes": nodes,
            "connections": workflow.get("connections").cloned().unwrap_or(serde_json::json!({})),
            "settings": workflow.get("settings").cloned().unwrap_or(serde_json::json!({}))
        });

        self.update_workflow(workflow_id, &update_payload).await?;

        Ok(())
    }

    /// Get a workflow by ID
    pub async fn get_workflow(&self, workflow_id: &str) -> Result<serde_json::Value, N8nTestError> {
        let url = format!("{}/api/v1/workflows/{}", self.base_url, workflow_id);

        let mut request = self.client.get(&url);

        if let Some(ref api_key) = self.api_key {
            request = request.header("X-N8N-API-KEY", api_key);
        }

        let response = request
            .send()
            .await
            .map_err(|e| N8nTestError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(N8nTestError::ApiError {
                status: status.as_u16(),
                body,
            });
        }

        response
            .json()
            .await
            .map_err(|e| N8nTestError::ParseError(e.to_string()))
    }

    /// Update a workflow
    pub async fn update_workflow(
        &self,
        workflow_id: &str,
        update_data: &serde_json::Value,
    ) -> Result<serde_json::Value, N8nTestError> {
        let url = format!("{}/api/v1/workflows/{}", self.base_url, workflow_id);

        let mut request = self.client.put(&url);

        if let Some(ref api_key) = self.api_key {
            request = request.header("X-N8N-API-KEY", api_key);
        }

        let response = request
            .json(update_data)
            .send()
            .await
            .map_err(|e| N8nTestError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(N8nTestError::ApiError {
                status: status.as_u16(),
                body,
            });
        }

        response
            .json()
            .await
            .map_err(|e| N8nTestError::ParseError(e.to_string()))
    }

    /// Activate a workflow
    pub async fn activate_workflow(
        &self,
        workflow_id: &str,
    ) -> Result<WorkflowResponse, N8nTestError> {
        let url = format!(
            "{}/api/v1/workflows/{}/activate",
            self.base_url, workflow_id
        );

        let mut request = self.client.post(&url);

        if let Some(ref api_key) = self.api_key {
            request = request.header("X-N8N-API-KEY", api_key);
        }

        let response = request
            .send()
            .await
            .map_err(|e| N8nTestError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(N8nTestError::ApiError {
                status: status.as_u16(),
                body,
            });
        }

        response
            .json()
            .await
            .map_err(|e| N8nTestError::ParseError(e.to_string()))
    }

    /// Deactivate a workflow
    pub async fn deactivate_workflow(
        &self,
        workflow_id: &str,
    ) -> Result<WorkflowResponse, N8nTestError> {
        let url = format!(
            "{}/api/v1/workflows/{}/deactivate",
            self.base_url, workflow_id
        );

        let mut request = self.client.post(&url);

        if let Some(ref api_key) = self.api_key {
            request = request.header("X-N8N-API-KEY", api_key);
        }

        let response = request
            .send()
            .await
            .map_err(|e| N8nTestError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(N8nTestError::ApiError {
                status: status.as_u16(),
                body,
            });
        }

        response
            .json()
            .await
            .map_err(|e| N8nTestError::ParseError(e.to_string()))
    }

    /// Delete a workflow
    pub async fn delete_workflow(&self, workflow_id: &str) -> Result<(), N8nTestError> {
        let url = format!("{}/api/v1/workflows/{}", self.base_url, workflow_id);

        let mut request = self.client.delete(&url);

        if let Some(ref api_key) = self.api_key {
            request = request.header("X-N8N-API-KEY", api_key);
        }

        let response = request
            .send()
            .await
            .map_err(|e| N8nTestError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(N8nTestError::ApiError {
                status: status.as_u16(),
                body,
            });
        }

        Ok(())
    }

    /// Get all workflows
    pub async fn get_workflows(&self) -> Result<WorkflowsListResponse, N8nTestError> {
        let url = format!("{}/api/v1/workflows", self.base_url);

        let mut request = self.client.get(&url);

        if let Some(ref api_key) = self.api_key {
            request = request.header("X-N8N-API-KEY", api_key);
        }

        let response = request
            .send()
            .await
            .map_err(|e| N8nTestError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(N8nTestError::ApiError {
                status: status.as_u16(),
                body,
            });
        }

        response
            .json()
            .await
            .map_err(|e| N8nTestError::ParseError(e.to_string()))
    }

    /// Get workflow executions (for verifying event delivery)
    pub async fn get_executions(
        &self,
        workflow_id: Option<&str>,
    ) -> Result<ExecutionsResponse, N8nTestError> {
        let mut url = format!("{}/api/v1/executions", self.base_url);

        if let Some(wf_id) = workflow_id {
            url.push_str(&format!("?workflowId={}", wf_id));
        }

        let mut request = self.client.get(&url);

        if let Some(ref api_key) = self.api_key {
            request = request.header("X-N8N-API-KEY", api_key);
        }

        let response = request
            .send()
            .await
            .map_err(|e| N8nTestError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(N8nTestError::ApiError {
                status: status.as_u16(),
                body,
            });
        }

        response
            .json()
            .await
            .map_err(|e| N8nTestError::ParseError(e.to_string()))
    }

    /// Clean up all test workflows
    pub async fn cleanup_all_workflows(&self) -> Result<(), N8nTestError> {
        let workflows = self.get_workflows().await?;

        for workflow in workflows.data {
            // Deactivate first if active
            if workflow.active {
                let _ = self.deactivate_workflow(&workflow.id).await;
            }
            self.delete_workflow(&workflow.id).await?;
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct DataWrapper<T> {
    data: T,
}

#[derive(Debug, Deserialize)]
struct SettingsResponse {
    data: SettingsData,
}

#[derive(Debug, Deserialize)]
struct SettingsData {
    #[serde(rename = "userManagement")]
    user_management: UserManagementSettings,
}

#[derive(Debug, Deserialize)]
struct UserManagementSettings {
    #[serde(rename = "showSetupOnFirstLoad")]
    show_setup_on_first_load: bool,
}

#[derive(Debug, Deserialize)]
pub struct SetupResponse {
    pub id: String,
    pub email: String,
    #[serde(rename = "firstName")]
    pub first_name: String,
    #[serde(rename = "lastName")]
    pub last_name: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginResponse {
    pub id: String,
    pub email: String,
    #[serde(rename = "firstName")]
    pub first_name: String,
    #[serde(rename = "lastName")]
    pub last_name: String,
}

#[derive(Debug, Deserialize)]
pub struct ApiKeyResponse {
    #[serde(rename = "rawApiKey")]
    pub raw_api_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkflowResponse {
    pub id: String,
    pub name: String,
    pub active: bool,
    #[serde(default)]
    pub nodes: Vec<Value>,
}

#[derive(Debug, Deserialize)]
pub struct WorkflowsListResponse {
    pub data: Vec<WorkflowSummary>,
    #[serde(rename = "nextCursor")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct WorkflowSummary {
    pub id: String,
    pub name: String,
    pub active: bool,
}

#[derive(Debug, Deserialize)]
pub struct ExecutionsResponse {
    pub data: Vec<Execution>,
    #[serde(rename = "nextCursor")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Execution {
    pub id: String,
    #[serde(rename = "workflowId")]
    pub workflow_id: String,
    pub finished: bool,
    pub mode: String,
    #[serde(rename = "startedAt")]
    pub started_at: String,
}

#[derive(Debug)]
pub enum N8nTestError {
    RequestFailed(String),
    ApiError { status: u16, body: String },
    ParseError(String),
}

impl std::fmt::Display for N8nTestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            N8nTestError::RequestFailed(msg) => write!(f, "Request failed: {}", msg),
            N8nTestError::ApiError { status, body } => {
                write!(f, "API error (status {}): {}", status, body)
            }
            N8nTestError::ParseError(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

impl std::error::Error for N8nTestError {}
