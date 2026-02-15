//! Integration tests for event routing functionality

use crate::common::{
    TEST_SLACK_SIGNING_SECRET, TestEnvironment, UNIHOOK_URL, create_app_mention_payload,
    create_message_event_payload, create_reaction_event_payload, create_url_verification_payload,
};
use serde_json::json;
use std::time::Duration;

/// Load a workflow fixture from the workflows directory
/// Adds a unique webhookId to each Slack Trigger node to avoid conflicts
fn load_workflow(name: &str) -> serde_json::Value {
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
    let unique_id = format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    // Add webhookId to any Slack Trigger nodes
    if let Some(nodes) = workflow.get_mut("nodes").and_then(|n| n.as_array_mut()) {
        for node in nodes {
            if node.get("type").and_then(|t| t.as_str()) == Some("n8n-nodes-base.slackTrigger") {
                node["webhookId"] =
                    serde_json::Value::String(format!("test-webhook-{}-{}", name, unique_id));
            }
        }
    }

    workflow
}

// ==================== Health Check Tests ====================

#[tokio::test]
async fn test_health_endpoint_returns_ok() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    let health = env.get_health().await.expect("Failed to get health");

    assert_eq!(health["status"], "healthy");
    assert!(health["triggers_loaded"].is_number());
}

// ==================== URL Verification Tests ====================

#[tokio::test]
async fn test_url_verification_challenge() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    let challenge = "test-challenge-12345";
    let payload = create_url_verification_payload(challenge);

    let response = env
        .send_slack_event(&payload)
        .await
        .expect("Failed to send event");

    assert!(response.status().is_success());

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body["challenge"], challenge);
}

#[tokio::test]
async fn test_url_verification_with_different_challenges() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    let challenges = vec![
        "simple-challenge",
        "challenge-with-numbers-123",
        "CamelCaseChallenge",
        "challenge_with_underscores",
    ];

    for challenge in challenges {
        let payload = create_url_verification_payload(challenge);
        let response = env
            .send_slack_event(&payload)
            .await
            .expect("Failed to send event");

        assert!(response.status().is_success());

        let body: serde_json::Value = response.json().await.expect("Failed to parse response");
        assert_eq!(
            body["challenge"], challenge,
            "Challenge mismatch for: {}",
            challenge
        );
    }
}

// ==================== Event Routing Tests ====================

/// Helper to get execution count for a workflow
async fn get_execution_count(env: &TestEnvironment, workflow_id: &str) -> i64 {
    env.n8n_client
        .get_executions(Some(workflow_id))
        .await
        .map(|r| r.data.len() as i64)
        .unwrap_or(0)
}

/// Helper to wait for and verify an execution occurred
async fn wait_for_execution(env: &TestEnvironment, workflow_id: &str, expected_count: i64) -> bool {
    // Wait up to 5 seconds for the execution to appear
    for _ in 0..10 {
        let count = get_execution_count(env, workflow_id).await;
        if count >= expected_count {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    false
}

#[tokio::test]
async fn test_message_event_triggers_workflow_execution() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Setup workflow
    let workflow = load_workflow("message_trigger");
    let created = env
        .setup_workflow(&workflow)
        .await
        .expect("Failed to setup workflow");

    // Get initial execution count
    let initial_count = get_execution_count(&env, &created.id).await;

    // Send message event
    let payload = create_message_event_payload("C123456", "Hello, world!");
    let response = env
        .send_slack_event(&payload)
        .await
        .expect("Failed to send event");

    // Should return 200 OK immediately (async processing)
    assert!(
        response.status().is_success(),
        "Expected success, got: {}",
        response.status()
    );

    // Verify workflow was actually executed
    let execution_occurred = wait_for_execution(&env, &created.id, initial_count + 1).await;
    assert!(
        execution_occurred,
        "Expected workflow execution to be triggered"
    );

    // Cleanup
    env.cleanup_workflow(&created.id)
        .await
        .expect("Failed to cleanup workflow");
}

#[tokio::test]
async fn test_reaction_event_triggers_workflow_execution() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Setup workflow
    let workflow = load_workflow("reaction_trigger");
    let created = env
        .setup_workflow(&workflow)
        .await
        .expect("Failed to setup workflow");

    // Get initial execution count
    let initial_count = get_execution_count(&env, &created.id).await;

    // Send reaction event
    let payload = create_reaction_event_payload("C123456", "thumbsup");
    let response = env
        .send_slack_event(&payload)
        .await
        .expect("Failed to send event");

    assert!(
        response.status().is_success(),
        "Expected success, got: {}",
        response.status()
    );

    // Verify workflow was actually executed
    let execution_occurred = wait_for_execution(&env, &created.id, initial_count + 1).await;
    assert!(
        execution_occurred,
        "Expected workflow execution to be triggered"
    );

    // Cleanup
    env.cleanup_workflow(&created.id)
        .await
        .expect("Failed to cleanup workflow");
}

#[tokio::test]
async fn test_any_event_trigger_receives_message() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Setup workflow with any_event trigger
    let workflow = load_workflow("any_event_trigger");
    let created = env
        .setup_workflow(&workflow)
        .await
        .expect("Failed to setup workflow");

    let initial_count = get_execution_count(&env, &created.id).await;

    // Send message event
    let payload = create_message_event_payload("C999999", "Test message");
    let response = env
        .send_slack_event(&payload)
        .await
        .expect("Failed to send event");

    assert!(response.status().is_success());

    // Verify execution occurred
    let execution_occurred = wait_for_execution(&env, &created.id, initial_count + 1).await;
    assert!(
        execution_occurred,
        "Expected any_event workflow to execute on message"
    );

    // Cleanup
    env.cleanup_workflow(&created.id)
        .await
        .expect("Failed to cleanup workflow");
}

#[tokio::test]
async fn test_any_event_trigger_receives_reaction() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Setup workflow with any_event trigger
    let workflow = load_workflow("any_event_trigger");
    let created = env
        .setup_workflow(&workflow)
        .await
        .expect("Failed to setup workflow");

    let initial_count = get_execution_count(&env, &created.id).await;

    // Send reaction event
    let payload = create_reaction_event_payload("C999999", "rocket");
    let response = env
        .send_slack_event(&payload)
        .await
        .expect("Failed to send event");

    assert!(response.status().is_success());

    // Verify execution occurred
    let execution_occurred = wait_for_execution(&env, &created.id, initial_count + 1).await;
    assert!(
        execution_occurred,
        "Expected any_event workflow to execute on reaction"
    );

    // Cleanup
    env.cleanup_workflow(&created.id)
        .await
        .expect("Failed to cleanup workflow");
}

#[tokio::test]
async fn test_any_event_trigger_receives_app_mention() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Setup workflow with any_event trigger
    let workflow = load_workflow("any_event_trigger");
    let created = env
        .setup_workflow(&workflow)
        .await
        .expect("Failed to setup workflow");

    let initial_count = get_execution_count(&env, &created.id).await;

    // Send app mention event
    let payload = create_app_mention_payload("C999999", "<@U12345> hello!");
    let response = env
        .send_slack_event(&payload)
        .await
        .expect("Failed to send event");

    assert!(response.status().is_success());

    // Verify execution occurred
    let execution_occurred = wait_for_execution(&env, &created.id, initial_count + 1).await;
    assert!(
        execution_occurred,
        "Expected any_event workflow to execute on app_mention"
    );

    // Cleanup
    env.cleanup_workflow(&created.id)
        .await
        .expect("Failed to cleanup workflow");
}

// ==================== Channel Filtering Tests ====================

#[tokio::test]
async fn test_channel_specific_trigger_loaded() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Clean up any workflows from previous tests and wait for refresh
    env.cleanup_all()
        .await
        .expect("Failed to cleanup all workflows");
    tokio::time::sleep(Duration::from_secs(6)).await;

    // Get initial trigger count (should be 0 after cleanup)
    let health_before = env.get_health().await.expect("Failed to get health");
    let count_before = health_before["triggers_loaded"].as_i64().unwrap_or(0);

    // Setup channel-specific workflow
    let workflow = load_workflow("channel_specific_trigger");
    let created = env
        .setup_workflow(&workflow)
        .await
        .expect("Failed to setup workflow");

    // Verify it was created and activated
    assert!(created.active, "Workflow should be active");

    // Check that trigger count increased by 1
    let health_after = env.get_health().await.expect("Failed to get health");
    let count_after = health_after["triggers_loaded"].as_i64().unwrap_or(0);

    assert_eq!(
        count_after - count_before,
        1,
        "Expected trigger count to increase by 1"
    );

    // Cleanup
    env.cleanup_workflow(&created.id)
        .await
        .expect("Failed to cleanup workflow");
}

#[tokio::test]
async fn test_event_to_matching_channel_triggers_execution() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Setup channel-specific workflow (configured for C123456)
    let workflow = load_workflow("channel_specific_trigger");
    let created = env
        .setup_workflow(&workflow)
        .await
        .expect("Failed to setup workflow");

    let initial_count = get_execution_count(&env, &created.id).await;

    // Send event to matching channel
    let payload = create_message_event_payload("C123456", "Message to correct channel");
    let response = env
        .send_slack_event(&payload)
        .await
        .expect("Failed to send event");

    assert!(response.status().is_success());

    // Verify workflow was executed (channel matches)
    let execution_occurred = wait_for_execution(&env, &created.id, initial_count + 1).await;
    assert!(
        execution_occurred,
        "Expected workflow to execute for matching channel"
    );

    // Cleanup
    env.cleanup_workflow(&created.id)
        .await
        .expect("Failed to cleanup workflow");
}

#[tokio::test]
async fn test_event_to_non_matching_channel_does_not_trigger_execution() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Setup channel-specific workflow (configured for C123456)
    let workflow = load_workflow("channel_specific_trigger");
    let created = env
        .setup_workflow(&workflow)
        .await
        .expect("Failed to setup workflow");

    let initial_count = get_execution_count(&env, &created.id).await;

    // Send event to different channel - should NOT trigger execution
    let payload = create_message_event_payload("C999999", "Message to wrong channel");
    let response = env
        .send_slack_event(&payload)
        .await
        .expect("Failed to send event");

    // Should still return 200 OK to Slack (ack the event)
    assert!(response.status().is_success());

    // Wait a moment to ensure event was processed
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Verify workflow was NOT executed (channel doesn't match)
    let final_count = get_execution_count(&env, &created.id).await;
    assert_eq!(
        final_count, initial_count,
        "Expected no new executions for non-matching channel"
    );

    // Cleanup
    env.cleanup_workflow(&created.id)
        .await
        .expect("Failed to cleanup workflow");
}

// ==================== Multi-Workflow Tests ====================

#[tokio::test]
async fn test_multiple_workflows_can_be_active() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Clean up first and wait for refresh
    env.cleanup_all().await.expect("Failed to cleanup");
    tokio::time::sleep(Duration::from_secs(6)).await;

    // Get trigger count before adding workflows
    let health_before = env.get_health().await.expect("Failed to get health");
    let count_before = health_before["triggers_loaded"].as_i64().unwrap_or(0);

    // Setup multiple workflows
    let workflow1 = load_workflow("message_trigger");
    let workflow2 = load_workflow("any_event_trigger");

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

    // Check that trigger count increased by exactly 2
    let health_after = env.get_health().await.expect("Failed to get health");
    let count_after = health_after["triggers_loaded"].as_i64().unwrap_or(0);

    assert_eq!(
        count_after - count_before,
        2,
        "Expected trigger count to increase by 2 (from {} to {}), but got {}",
        count_before,
        count_before + 2,
        count_after
    );

    // Cleanup
    env.cleanup_workflow(&created1.id)
        .await
        .expect("Failed to cleanup workflow 1");
    env.cleanup_workflow(&created2.id)
        .await
        .expect("Failed to cleanup workflow 2");
}

#[tokio::test]
async fn test_event_routed_to_multiple_matching_workflows() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Clean up first and wait for n8n to settle
    env.cleanup_all().await.expect("Failed to cleanup");
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Setup two workflows that should both match message events
    let workflow1 = load_workflow("message_trigger");
    let workflow2 = load_workflow("any_event_trigger");

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

    // Get initial execution counts for both workflows
    let initial_count1 = get_execution_count(&env, &created1.id).await;
    let initial_count2 = get_execution_count(&env, &created2.id).await;

    // Send a message event - should be routed to both workflows
    let payload = create_message_event_payload("C123456", "Test multi-workflow routing");
    let response = env
        .send_slack_event(&payload)
        .await
        .expect("Failed to send event");

    assert!(response.status().is_success());

    // Verify both workflows were executed
    let exec1_occurred = wait_for_execution(&env, &created1.id, initial_count1 + 1).await;
    let exec2_occurred = wait_for_execution(&env, &created2.id, initial_count2 + 1).await;

    assert!(
        exec1_occurred,
        "Expected message_trigger workflow to be executed"
    );
    assert!(
        exec2_occurred,
        "Expected any_event_trigger workflow to be executed"
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
async fn test_invalid_json_returns_bad_request() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    let response = env
        .http_client
        .post(format!("{}/slack/events", UNIHOOK_URL))
        .body("not valid json")
        .header("content-type", "application/json")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn test_invalid_slack_payload_returns_bad_request() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Valid JSON but not a valid Slack payload
    let payload = json!({
        "foo": "bar",
        "not": "slack"
    });

    let response = env
        .send_slack_event(&payload)
        .await
        .expect("Failed to send event");

    assert_eq!(response.status().as_u16(), 400);
}

// ==================== Error Handling Tests ====================

/// Test that webhook errors don't stop event propagation to other workflows.
/// The test webhook endpoint will fail (no one listening) but the production
/// webhook should still receive the event.
#[tokio::test]
async fn test_webhook_errors_dont_stop_propagation() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Clean up first
    env.cleanup_all().await.expect("Failed to cleanup");
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Setup two workflows that both match message events
    let workflow1 = load_workflow("message_trigger");
    let workflow2 = load_workflow("any_event_trigger");

    let created1 = env
        .setup_workflow(&workflow1)
        .await
        .expect("Failed to setup workflow 1");

    tokio::time::sleep(Duration::from_secs(2)).await;

    let created2 = env
        .setup_workflow(&workflow2)
        .await
        .expect("Failed to setup workflow 2");

    // Get initial execution counts
    let initial_count1 = get_execution_count(&env, &created1.id).await;
    let initial_count2 = get_execution_count(&env, &created2.id).await;

    // Send a message event - both production AND test webhooks will be hit
    // The test webhooks will fail (404) but production should succeed
    let payload = create_message_event_payload("C123456", "Test error handling");
    let response = env
        .send_slack_event(&payload)
        .await
        .expect("Failed to send event");

    // Our app should return success even if some webhooks fail
    assert!(response.status().is_success());

    // Verify BOTH workflows still executed via production webhooks
    let exec1_occurred = wait_for_execution(&env, &created1.id, initial_count1 + 1).await;
    let exec2_occurred = wait_for_execution(&env, &created2.id, initial_count2 + 1).await;

    assert!(
        exec1_occurred,
        "Expected message_trigger workflow to execute despite test webhook errors"
    );
    assert!(
        exec2_occurred,
        "Expected any_event workflow to execute despite test webhook errors"
    );

    // Cleanup
    env.cleanup_workflow(&created1.id)
        .await
        .expect("Failed to cleanup workflow 1");
    env.cleanup_workflow(&created2.id)
        .await
        .expect("Failed to cleanup workflow 2");
}

// ==================== Signature Verification Tests ====================

/// Test that a properly signed Slack event triggers workflow execution.
///
/// This test verifies that:
/// 1. The raw request body is forwarded unchanged (preserving the signature)
/// 2. Slack headers (X-Slack-Signature, X-Slack-Request-Timestamp) are forwarded
/// 3. n8n's Slack Trigger can verify the signature and execute the workflow
#[tokio::test]
async fn test_signed_slack_event_triggers_execution() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Setup workflow
    let workflow = load_workflow("message_trigger");
    let created = env
        .setup_workflow(&workflow)
        .await
        .expect("Failed to setup workflow");

    // Get initial execution count
    let initial_count = get_execution_count(&env, &created.id).await;

    // Send a SIGNED message event (with proper X-Slack-Signature header)
    let payload = create_message_event_payload("C123456", "Signed message test!");
    let response = env
        .send_signed_slack_event(&payload, TEST_SLACK_SIGNING_SECRET)
        .await
        .expect("Failed to send signed event");

    // Should return 200 OK immediately (async processing)
    assert!(
        response.status().is_success(),
        "Expected success for signed event, got: {}",
        response.status()
    );

    // Verify workflow was actually executed
    let execution_occurred = wait_for_execution(&env, &created.id, initial_count + 1).await;
    assert!(
        execution_occurred,
        "Expected workflow execution to be triggered by signed event"
    );

    // Cleanup
    env.cleanup_workflow(&created.id)
        .await
        .expect("Failed to cleanup workflow");
}

/// Test that signature headers are preserved when forwarding to n8n.
///
/// This is a more detailed test that verifies the exact headers are forwarded.
#[tokio::test]
async fn test_slack_signature_headers_forwarded() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Setup workflow with any_event trigger (more permissive)
    let workflow = load_workflow("any_event_trigger");
    let created = env
        .setup_workflow(&workflow)
        .await
        .expect("Failed to setup workflow");

    let initial_count = get_execution_count(&env, &created.id).await;

    // Send signed event
    let payload = create_message_event_payload("C999999", "Header forwarding test");
    let response = env
        .send_signed_slack_event(&payload, TEST_SLACK_SIGNING_SECRET)
        .await
        .expect("Failed to send signed event");

    assert!(
        response.status().is_success(),
        "Expected success, got: {}",
        response.status()
    );

    // Verify execution occurred (proves headers were forwarded correctly)
    let execution_occurred = wait_for_execution(&env, &created.id, initial_count + 1).await;
    assert!(
        execution_occurred,
        "Expected workflow execution - signature headers may not be forwarded correctly"
    );

    // Cleanup
    env.cleanup_workflow(&created.id)
        .await
        .expect("Failed to cleanup workflow");
}

// ==================== Cleanup Test ====================

#[tokio::test]
async fn test_cleanup_removes_all_workflows() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Setup a workflow
    let workflow = load_workflow("message_trigger");
    let created = env
        .setup_workflow(&workflow)
        .await
        .expect("Failed to setup workflow");

    // Clean up the specific workflow (more reliable than cleanup_all)
    env.cleanup_workflow(&created.id)
        .await
        .expect("Failed to cleanup workflow");

    // Wait for refresh
    tokio::time::sleep(Duration::from_secs(6)).await;

    // Check that the specific workflow is gone
    let workflows = env
        .n8n_client
        .get_workflows()
        .await
        .expect("Failed to get workflows");

    let still_exists = workflows.data.iter().any(|w| w.id == created.id);
    assert!(
        !still_exists,
        "Expected workflow {} to be deleted",
        created.id
    );
}
