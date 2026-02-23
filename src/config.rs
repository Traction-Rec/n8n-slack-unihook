use serde::Deserialize;

/// Configuration for the Slack Unihook router.
/// All values are loaded from environment variables.
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// n8n instance URL (e.g., "http://localhost:5678")
    #[serde(default = "default_n8n_api_url")]
    pub n8n_api_url: String,

    /// n8n API key for authentication
    pub n8n_api_key: String,

    /// Address to bind the HTTP server (default: "0.0.0.0:3000")
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// How often to refresh the routing table from n8n (in seconds)
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval_secs: u64,

    /// n8n production webhook endpoint path (default: "webhook")
    /// Corresponds to n8n's N8N_ENDPOINT_WEBHOOK env var
    #[serde(default = "default_endpoint_webhook")]
    pub n8n_endpoint_webhook: String,

    /// n8n test webhook endpoint path (default: "webhook-test")
    /// Corresponds to n8n's N8N_ENDPOINT_WEBHOOK_TEST env var
    #[serde(default = "default_endpoint_webhook_test")]
    pub n8n_endpoint_webhook_test: String,

    /// Optional shared secret for verifying inbound GitHub webhook signatures.
    /// When set, the `X-Hub-Signature-256` header on incoming requests to
    /// `/github/events` is verified using HMAC-SHA256 before routing.
    /// When unset, inbound verification is skipped (existing behavior).
    #[serde(default)]
    pub github_webhook_secret: Option<String>,

    /// Path to the SQLite database file used for storing webhook secrets and
    /// trigger metadata. Defaults to `"unihook.db"` in the current working
    /// directory. Set to `":memory:"` for an in-memory database (useful for
    /// tests).
    #[serde(default = "default_database_path")]
    pub database_path: String,
}

fn default_n8n_api_url() -> String {
    "http://localhost:5678".to_string()
}

fn default_listen_addr() -> String {
    "0.0.0.0:3000".to_string()
}

fn default_refresh_interval() -> u64 {
    60
}

fn default_endpoint_webhook() -> String {
    "webhook".to_string()
}

fn default_endpoint_webhook_test() -> String {
    "webhook-test".to_string()
}

fn default_database_path() -> String {
    "unihook.db".to_string()
}

impl Config {
    /// Load configuration from environment variables.
    /// Environment variables should be prefixed with nothing (e.g., N8N_API_URL).
    pub fn from_env() -> Result<Self, envy::Error> {
        envy::from_env::<Config>()
    }
}
