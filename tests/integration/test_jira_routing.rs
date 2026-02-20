//! Integration tests for Jira event routing functionality
//!
//! These tests verify the full end-to-end flow:
//!   Test -> Middleware /jira/events -> n8n Workflow Execution
//!
//! Each test creates a workflow with a Jira Trigger node in n8n,
//! sends a Jira webhook payload to the middleware's /jira/events endpoint,
//! and verifies the workflow was (or was not) executed.

use crate::common::{
    TestEnvironment, UNIHOOK_URL, create_jira_comment_created_payload,
    create_jira_issue_created_payload, create_jira_issue_updated_payload, get_execution_count,
    load_workflow, wait_for_execution, wait_for_jira_trigger_count,
};
use serde_json::json;
use std::time::Duration;

// ==================== Jira Event Routing Tests ====================

#[tokio::test]
async fn test_jira_issue_created_triggers_workflow_execution() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Setup workflow with jira:issue_created trigger
    let workflow = load_workflow("jira_issue_trigger");
    let created = env
        .setup_workflow(&workflow)
        .await
        .expect("Failed to setup workflow");

    // Get initial execution count
    let initial_count = get_execution_count(&env, &created.id).await;

    // Send Jira issue created event to middleware /jira/events endpoint
    let payload = create_jira_issue_created_payload("PROJ", "PROJ-123");
    let response = env
        .send_jira_event(&payload)
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
        "Expected Jira issue_created workflow execution to be triggered"
    );

    // Cleanup
    env.cleanup_workflow(&created.id)
        .await
        .expect("Failed to cleanup workflow");
}

#[tokio::test]
async fn test_jira_wildcard_trigger_receives_issue_event() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Setup workflow with wildcard (*) trigger
    let workflow = load_workflow("jira_wildcard_trigger");
    let created = env
        .setup_workflow(&workflow)
        .await
        .expect("Failed to setup workflow");

    let initial_count = get_execution_count(&env, &created.id).await;

    // Send Jira issue created event to middleware /jira/events endpoint
    let payload = create_jira_issue_created_payload("PROJ", "PROJ-456");
    let response = env
        .send_jira_event(&payload)
        .await
        .expect("Failed to send event");

    assert!(response.status().is_success());

    // Verify execution occurred - wildcard should match any event
    let execution_occurred = wait_for_execution(&env, &created.id, initial_count + 1).await;
    assert!(
        execution_occurred,
        "Expected wildcard Jira workflow to execute on issue_created"
    );

    // Cleanup
    env.cleanup_workflow(&created.id)
        .await
        .expect("Failed to cleanup workflow");
}

#[tokio::test]
async fn test_jira_wildcard_trigger_receives_comment_event() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Setup workflow with wildcard (*) trigger
    let workflow = load_workflow("jira_wildcard_trigger");
    let created = env
        .setup_workflow(&workflow)
        .await
        .expect("Failed to setup workflow");

    let initial_count = get_execution_count(&env, &created.id).await;

    // Send Jira comment event to middleware /jira/events endpoint
    let payload = create_jira_comment_created_payload("PROJ-123", "Test comment");
    let response = env
        .send_jira_event(&payload)
        .await
        .expect("Failed to send event");

    assert!(response.status().is_success());

    // Wildcard trigger should match comment events too
    let execution_occurred = wait_for_execution(&env, &created.id, initial_count + 1).await;
    assert!(
        execution_occurred,
        "Expected wildcard Jira workflow to execute on comment_created"
    );

    // Cleanup
    env.cleanup_workflow(&created.id)
        .await
        .expect("Failed to cleanup workflow");
}

#[tokio::test]
async fn test_jira_unmatched_event_does_not_trigger_execution() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Setup workflow that only listens for comment_created
    let workflow = load_workflow("jira_comment_trigger");
    let created = env
        .setup_workflow(&workflow)
        .await
        .expect("Failed to setup workflow");

    let initial_count = get_execution_count(&env, &created.id).await;

    // Send a jira:issue_created event - should NOT match comment_created trigger
    let payload = create_jira_issue_created_payload("PROJ", "PROJ-789");
    let response = env
        .send_jira_event(&payload)
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
        "Expected no new executions for unmatched Jira event type"
    );

    // Cleanup
    env.cleanup_workflow(&created.id)
        .await
        .expect("Failed to cleanup workflow");
}

#[tokio::test]
async fn test_jira_event_routed_to_multiple_matching_workflows() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Clean up first and wait for n8n to settle
    env.cleanup_all().await.expect("Failed to cleanup");
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Setup two workflows that should both match jira:issue_created
    // 1. An issue-specific trigger
    // 2. A wildcard trigger
    let workflow1 = load_workflow("jira_issue_trigger");
    let workflow2 = load_workflow("jira_wildcard_trigger");

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

    // Send an issue created event to middleware /jira/events endpoint
    // Both workflows should match (one by specific event, one by wildcard)
    let payload = create_jira_issue_created_payload("PROJ", "PROJ-100");
    let response = env
        .send_jira_event(&payload)
        .await
        .expect("Failed to send event");

    assert!(response.status().is_success());

    // Verify both workflows were executed
    let exec1_occurred = wait_for_execution(&env, &created1.id, initial_count1 + 1).await;
    let exec2_occurred = wait_for_execution(&env, &created2.id, initial_count2 + 1).await;

    assert!(
        exec1_occurred,
        "Expected jira_issue_trigger workflow to be executed"
    );
    assert!(
        exec2_occurred,
        "Expected jira_wildcard_trigger workflow to be executed"
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
async fn test_jira_invalid_json_returns_bad_request() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    let response = env
        .http_client
        .post(format!("{}/jira/events", UNIHOOK_URL))
        .body("not valid json")
        .header("content-type", "application/json")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn test_jira_missing_webhook_event_returns_bad_request() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Valid JSON but missing required webhookEvent field
    let payload = json!({
        "timestamp": 1234567890000i64,
        "issue": {
            "key": "PROJ-123"
        }
    });

    let response = env
        .send_jira_event(&payload)
        .await
        .expect("Failed to send event");

    assert_eq!(response.status().as_u16(), 400);
}

// ==================== Body Preservation Tests ====================

#[tokio::test]
async fn test_jira_body_forwarded_to_workflow() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Setup a wildcard Jira trigger workflow
    let workflow = load_workflow("jira_wildcard_trigger");
    let created = env
        .setup_workflow(&workflow)
        .await
        .expect("Failed to setup workflow");

    let initial_count = get_execution_count(&env, &created.id).await;

    // Send a Jira event with specific data to middleware /jira/events endpoint
    let payload = create_jira_issue_updated_payload("MYPROJ", "MYPROJ-42");
    let response = env
        .send_jira_event(&payload)
        .await
        .expect("Failed to send event");

    assert!(response.status().is_success());

    // Verify workflow executed (body was forwarded successfully)
    let execution_occurred = wait_for_execution(&env, &created.id, initial_count + 1).await;
    assert!(
        execution_occurred,
        "Expected workflow to execute with forwarded Jira body"
    );

    // Cleanup
    env.cleanup_workflow(&created.id)
        .await
        .expect("Failed to cleanup workflow");
}

// ==================== Health Check Integration ====================

#[tokio::test]
async fn test_health_reports_jira_triggers() {
    let env = TestEnvironment::new(false)
        .await
        .expect("Failed to create test environment");

    // Clean up first and poll until the refresh picks up the empty state
    env.cleanup_all()
        .await
        .expect("Failed to cleanup all workflows");

    assert!(
        wait_for_jira_trigger_count(&env, 0).await,
        "Expected Jira trigger count to reach 0 after cleanup"
    );

    // Setup a Jira trigger workflow
    let workflow = load_workflow("jira_issue_trigger");
    let created = env
        .setup_workflow(&workflow)
        .await
        .expect("Failed to setup workflow");

    // Poll until the trigger count reflects the new workflow
    assert!(
        wait_for_jira_trigger_count(&env, 1).await,
        "Expected Jira trigger count to reach 1 after activating workflow"
    );

    // Cleanup
    env.cleanup_workflow(&created.id)
        .await
        .expect("Failed to cleanup workflow");
}
