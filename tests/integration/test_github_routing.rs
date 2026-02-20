//! Integration tests for GitHub event routing functionality
//!
//! These tests verify the full end-to-end flow:
//!   Test -> Middleware /github/events -> n8n Workflow Execution
//!
//! Each test creates a workflow with a GitHub Trigger node in n8n,
//! sends a GitHub webhook payload to the middleware's /github/events endpoint,
//! and verifies the workflow was (or was not) executed.

use crate::common::{
    TestEnvironment, UNIHOOK_URL, create_github_issues_payload, create_github_ping_payload,
    create_github_push_payload, get_execution_count, load_workflow, wait_for_execution,
    wait_for_github_trigger_count,
};
use std::time::Duration;

// ==================== Inbound Signature Verification Tests ====================

#[tokio::test]
async fn test_github_event_rejected_with_invalid_signature() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Send a GitHub push event signed with the wrong secret
    let payload = create_github_push_payload("test-owner", "test-repo");
    let response = env
        .send_signed_github_event("push", &payload, "wrong-secret")
        .await
        .expect("Failed to send event");

    assert_eq!(
        response.status().as_u16(),
        401,
        "Expected 401 Unauthorized for invalid signature"
    );
}

#[tokio::test]
async fn test_github_event_rejected_without_signature() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Send a GitHub push event without any signature header
    let payload = create_github_push_payload("test-owner", "test-repo");
    let response = env
        .send_unsigned_github_event("push", &payload)
        .await
        .expect("Failed to send event");

    assert_eq!(
        response.status().as_u16(),
        401,
        "Expected 401 Unauthorized for missing signature"
    );
}

#[tokio::test]
async fn test_github_event_accepted_with_valid_signature() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Setup workflow with push trigger
    let workflow = load_workflow("github_push_trigger");
    let created = env
        .setup_workflow(&workflow)
        .await
        .expect("Failed to setup workflow");

    let initial_count = get_execution_count(&env, &created.id).await;

    // Send a correctly-signed GitHub push event (uses TEST_GITHUB_WEBHOOK_SECRET)
    let payload = create_github_push_payload("test-owner", "test-repo");
    let response = env
        .send_github_event("push", &payload)
        .await
        .expect("Failed to send event");

    assert!(
        response.status().is_success(),
        "Expected success for correctly-signed GitHub event, got: {}",
        response.status()
    );

    // Verify workflow was executed
    let execution_occurred = wait_for_execution(&env, &created.id, initial_count + 1).await;
    assert!(
        execution_occurred,
        "Expected workflow execution for correctly-signed GitHub event"
    );

    // Cleanup
    env.cleanup_workflow(&created.id)
        .await
        .expect("Failed to cleanup workflow");
}

// ==================== GitHub Event Routing Tests ====================

#[tokio::test]
async fn test_github_push_triggers_workflow_execution() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Setup workflow with push trigger
    let workflow = load_workflow("github_push_trigger");
    let created = env
        .setup_workflow(&workflow)
        .await
        .expect("Failed to setup workflow");

    // Get initial execution count
    let initial_count = get_execution_count(&env, &created.id).await;

    // Send GitHub push event to middleware /github/events endpoint
    let payload = create_github_push_payload("test-owner", "test-repo");
    let response = env
        .send_github_event("push", &payload)
        .await
        .expect("Failed to send event");

    // Should return 200 OK immediately
    assert!(
        response.status().is_success(),
        "Expected success, got: {}",
        response.status()
    );

    // Verify workflow was actually executed
    let execution_occurred = wait_for_execution(&env, &created.id, initial_count + 1).await;
    assert!(
        execution_occurred,
        "Expected GitHub push workflow execution to be triggered"
    );

    // Cleanup
    env.cleanup_workflow(&created.id)
        .await
        .expect("Failed to cleanup workflow");
}

#[tokio::test]
async fn test_github_wildcard_trigger_receives_push_event() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Setup workflow with wildcard (*) trigger
    let workflow = load_workflow("github_wildcard_trigger");
    let created = env
        .setup_workflow(&workflow)
        .await
        .expect("Failed to setup workflow");

    let initial_count = get_execution_count(&env, &created.id).await;

    // Send GitHub push event to middleware
    let payload = create_github_push_payload("test-owner", "test-repo");
    let response = env
        .send_github_event("push", &payload)
        .await
        .expect("Failed to send event");

    assert!(response.status().is_success());

    // Verify execution occurred - wildcard should match any event
    let execution_occurred = wait_for_execution(&env, &created.id, initial_count + 1).await;
    assert!(
        execution_occurred,
        "Expected wildcard GitHub workflow to execute on push event"
    );

    // Cleanup
    env.cleanup_workflow(&created.id)
        .await
        .expect("Failed to cleanup workflow");
}

#[tokio::test]
async fn test_github_wildcard_trigger_receives_issues_event() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Setup workflow with wildcard (*) trigger
    let workflow = load_workflow("github_wildcard_trigger");
    let created = env
        .setup_workflow(&workflow)
        .await
        .expect("Failed to setup workflow");

    let initial_count = get_execution_count(&env, &created.id).await;

    // Send GitHub issues event to middleware
    let payload = create_github_issues_payload("test-owner", "test-repo", "opened");
    let response = env
        .send_github_event("issues", &payload)
        .await
        .expect("Failed to send event");

    assert!(response.status().is_success());

    // Wildcard trigger should match issues events too
    let execution_occurred = wait_for_execution(&env, &created.id, initial_count + 1).await;
    assert!(
        execution_occurred,
        "Expected wildcard GitHub workflow to execute on issues event"
    );

    // Cleanup
    env.cleanup_workflow(&created.id)
        .await
        .expect("Failed to cleanup workflow");
}

#[tokio::test]
async fn test_github_unmatched_event_does_not_trigger_execution() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Setup workflow that only listens for issues events
    let workflow = load_workflow("github_issues_trigger");
    let created = env
        .setup_workflow(&workflow)
        .await
        .expect("Failed to setup workflow");

    let initial_count = get_execution_count(&env, &created.id).await;

    // Send a push event - should NOT match issues trigger
    let payload = create_github_push_payload("test-owner", "test-repo");
    let response = env
        .send_github_event("push", &payload)
        .await
        .expect("Failed to send event");

    // Should still return 200 OK (ack the event)
    assert!(response.status().is_success());

    // Wait to ensure event was processed
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Verify workflow was NOT executed (event type doesn't match)
    let final_count = get_execution_count(&env, &created.id).await;
    assert_eq!(
        final_count, initial_count,
        "Expected no new executions for unmatched GitHub event type"
    );

    // Cleanup
    env.cleanup_workflow(&created.id)
        .await
        .expect("Failed to cleanup workflow");
}

#[tokio::test]
async fn test_github_event_routed_to_multiple_matching_workflows() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Clean up first and wait for n8n to settle
    env.cleanup_all().await.expect("Failed to cleanup");
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Setup two workflows that should both match a push event:
    // 1. A push-specific trigger
    // 2. A wildcard trigger
    let workflow1 = load_workflow("github_push_trigger");
    let workflow2 = load_workflow("github_wildcard_trigger");

    let created1 = env
        .setup_workflow(&workflow1)
        .await
        .expect("Failed to setup workflow 1");

    // Give n8n a moment before creating the second workflow
    tokio::time::sleep(Duration::from_secs(2)).await;

    let created2 = env
        .setup_workflow(&workflow2)
        .await
        .expect("Failed to setup workflow 2");

    // Get initial execution counts
    let initial_count1 = get_execution_count(&env, &created1.id).await;
    let initial_count2 = get_execution_count(&env, &created2.id).await;

    // Send a push event to middleware /github/events endpoint
    // Both workflows should match (one by specific event, one by wildcard)
    let payload = create_github_push_payload("test-owner", "test-repo");
    let response = env
        .send_github_event("push", &payload)
        .await
        .expect("Failed to send event");

    assert!(response.status().is_success());

    // Verify both workflows were executed
    let exec1_occurred = wait_for_execution(&env, &created1.id, initial_count1 + 1).await;
    let exec2_occurred = wait_for_execution(&env, &created2.id, initial_count2 + 1).await;

    assert!(
        exec1_occurred,
        "Expected github_push_trigger workflow to be executed"
    );
    assert!(
        exec2_occurred,
        "Expected github_wildcard_trigger workflow to be executed"
    );

    // Cleanup
    env.cleanup_workflow(&created1.id)
        .await
        .expect("Failed to cleanup workflow 1");
    env.cleanup_workflow(&created2.id)
        .await
        .expect("Failed to cleanup workflow 2");
}

// ==================== Error Handling Tests ====================

#[tokio::test]
async fn test_github_invalid_json_returns_bad_request() {
    use crate::common::{TEST_GITHUB_WEBHOOK_SECRET, compute_github_signature};

    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Sign the invalid body so it passes inbound signature verification
    let body = "not valid json";
    let signature = compute_github_signature(TEST_GITHUB_WEBHOOK_SECRET, body);

    let response = env
        .http_client
        .post(format!("{}/github/events", UNIHOOK_URL))
        .body(body)
        .header("content-type", "application/json")
        .header("x-github-event", "push")
        .header("x-hub-signature-256", signature)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn test_github_missing_event_header_returns_bad_request() {
    use crate::common::{TEST_GITHUB_WEBHOOK_SECRET, compute_github_signature};

    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Valid JSON but missing required X-GitHub-Event header
    let payload = create_github_push_payload("test-owner", "test-repo");
    let body = serde_json::to_string(&payload).unwrap();

    // Sign the body so it passes inbound signature verification
    let signature = compute_github_signature(TEST_GITHUB_WEBHOOK_SECRET, &body);

    let response = env
        .http_client
        .post(format!("{}/github/events", UNIHOOK_URL))
        .body(body)
        .header("content-type", "application/json")
        .header("x-hub-signature-256", signature)
        // Deliberately omitting x-github-event header
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status().as_u16(), 400);
}

// ==================== Ping Event Tests ====================

#[tokio::test]
async fn test_github_ping_event_returns_ok_without_execution() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Setup a wildcard workflow to ensure it would match if ping was routed
    let workflow = load_workflow("github_wildcard_trigger");
    let created = env
        .setup_workflow(&workflow)
        .await
        .expect("Failed to setup workflow");

    let initial_count = get_execution_count(&env, &created.id).await;

    // Send a ping event (GitHub sends this when a webhook is first created)
    let payload = create_github_ping_payload("test-owner", "test-repo");
    let response = env
        .send_github_event("ping", &payload)
        .await
        .expect("Failed to send event");

    // Should return 200 OK
    assert!(
        response.status().is_success(),
        "Expected success for ping event, got: {}",
        response.status()
    );

    // Wait to ensure event was processed
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Verify workflow was NOT executed (ping events should be acknowledged but not routed)
    let final_count = get_execution_count(&env, &created.id).await;
    assert_eq!(
        final_count, initial_count,
        "Expected no new executions for GitHub ping event"
    );

    // Cleanup
    env.cleanup_workflow(&created.id)
        .await
        .expect("Failed to cleanup workflow");
}

// ==================== Body Preservation Tests ====================

#[tokio::test]
async fn test_github_body_forwarded_to_workflow() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Setup a wildcard GitHub trigger workflow
    let workflow = load_workflow("github_wildcard_trigger");
    let created = env
        .setup_workflow(&workflow)
        .await
        .expect("Failed to setup workflow");

    let initial_count = get_execution_count(&env, &created.id).await;

    // Send a GitHub push event with specific data
    let payload = create_github_push_payload("test-owner", "test-repo");
    let response = env
        .send_github_event("push", &payload)
        .await
        .expect("Failed to send event");

    assert!(response.status().is_success());

    // Verify workflow executed (body was forwarded successfully)
    let execution_occurred = wait_for_execution(&env, &created.id, initial_count + 1).await;
    assert!(
        execution_occurred,
        "Expected workflow to execute with forwarded GitHub body"
    );

    // Cleanup
    env.cleanup_workflow(&created.id)
        .await
        .expect("Failed to cleanup workflow");
}

// ==================== Health Check Integration ====================

#[tokio::test]
async fn test_health_reports_github_triggers() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Clean up first and poll until the refresh picks up the empty state
    env.cleanup_all()
        .await
        .expect("Failed to cleanup all workflows");

    assert!(
        wait_for_github_trigger_count(&env, 0).await,
        "Expected GitHub trigger count to reach 0 after cleanup"
    );

    // Setup a GitHub trigger workflow
    let workflow = load_workflow("github_push_trigger");
    let created = env
        .setup_workflow(&workflow)
        .await
        .expect("Failed to setup workflow");

    // Poll until the trigger count reflects the new workflow
    assert!(
        wait_for_github_trigger_count(&env, 1).await,
        "Expected GitHub trigger count to reach 1 after activating workflow"
    );

    // Cleanup
    env.cleanup_workflow(&created.id)
        .await
        .expect("Failed to cleanup workflow");
}
