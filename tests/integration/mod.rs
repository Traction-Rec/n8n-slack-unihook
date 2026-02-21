//! Integration tests for unihook (Slack + Jira + GitHub event routing)
//!
//! These tests require a running Docker environment with n8n and unihook.
//! Run with: cargo test --test integration
//!
//! Or use the test script: ./scripts/run-integration-tests.sh

mod common;
mod test_event_routing;
mod test_github_routing;
mod test_jira_routing;
