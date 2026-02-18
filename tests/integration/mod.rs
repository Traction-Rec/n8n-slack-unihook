//! Integration tests for unihook (Slack + Jira event routing)
//!
//! These tests require a running Docker environment with n8n and unihook.
//! Run with: cargo test --test integration
//!
//! Or use the test script: ./scripts/run-integration-tests.sh

mod common;
mod test_jira_routing;
mod test_slack_routing;
