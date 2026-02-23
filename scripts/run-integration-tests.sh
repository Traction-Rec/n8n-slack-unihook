#!/bin/bash
#
# Integration test runner script
# Starts the Docker test environment, sets up n8n, runs tests, and cleans up
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_DIR/docker-compose.test.yml"
PROJECT_NAME="n8n-unihook-test"

# Test user credentials for n8n setup (password must contain uppercase)
TEST_EMAIL="test@example.com"
TEST_PASSWORD="TestPassword123"
TEST_FIRST_NAME="Test"
TEST_LAST_NAME="User"

# Slack signing secret for signature verification tests
# This must match TEST_SLACK_SIGNING_SECRET in tests/integration/common/mod.rs
SLACK_SIGNING_SECRET="test-signing-secret-for-integration-tests"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Cleanup function
cleanup() {
    if [ "$KEEP_RUNNING" != "true" ]; then
        log_info "Stopping Docker test environment..."
        docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" down -v 2>/dev/null || true
    else
        log_info "Keeping Docker environment running (KEEP_RUNNING=true)"
        if [ -n "$N8N_API_KEY" ]; then
            echo ""
            log_info "To manually start n8n-unihook later, run:"
            echo "  N8N_API_KEY=$N8N_API_KEY docker compose -f $COMPOSE_FILE -p $PROJECT_NAME up -d n8n-unihook"
        fi
    fi
}

# Set up cleanup trap
trap cleanup EXIT

# Parse arguments
KEEP_RUNNING=false
SKIP_DOCKER=false
TEST_FILTER=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --keep-running|-k)
            KEEP_RUNNING=true
            shift
            ;;
        --skip-docker|-s)
            SKIP_DOCKER=true
            shift
            ;;
        --filter|-f)
            TEST_FILTER="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -k, --keep-running    Don't stop Docker containers after tests"
            echo "  -s, --skip-docker     Skip starting Docker (assume already running)"
            echo "  -f, --filter NAME     Only run tests matching NAME"
            echo "  -h, --help            Show this help message"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

cd "$PROJECT_DIR"

# Function to wait for n8n to be healthy
wait_for_n8n() {
    local max_attempts=60
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if curl -s -f http://localhost:6789/healthz > /dev/null 2>&1; then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    
    return 1
}

# Function to wait for n8n-unihook to be healthy
wait_for_unihook() {
    local max_attempts=30
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if curl -s -f http://localhost:3000/health > /dev/null 2>&1; then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    
    return 1
}

# Function to setup n8n owner and create API key
setup_n8n() {
    log_step "Setting up n8n owner account..."
    
    # Always try to create the owner (will fail gracefully if exists)
    local setup_response=$(curl -s -X POST http://localhost:6789/rest/owner/setup \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\",\"firstName\":\"$TEST_FIRST_NAME\",\"lastName\":\"$TEST_LAST_NAME\"}")
    
    if echo "$setup_response" | grep -q '"id"'; then
        log_info "Owner account created successfully"
    elif echo "$setup_response" | grep -q "Instance owner already setup"; then
        log_info "Owner already exists, continuing..."
    else
        log_warn "Owner setup response: $setup_response"
        log_info "Continuing with existing owner..."
    fi
    
    # Wait a moment for n8n to stabilize after setup
    sleep 2
    
    # Login and create API key
    log_step "Logging in to n8n..."
    
    # Create a cookie jar file
    local cookie_jar="/tmp/n8n_cookies_$$"
    
    local login_response=$(curl -s -c "$cookie_jar" -X POST http://localhost:6789/rest/login \
        -H "Content-Type: application/json" \
        -d "{\"emailOrLdapLoginId\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}")
    
    if ! echo "$login_response" | grep -q '"id"'; then
        log_error "Failed to login: $login_response"
        rm -f "$cookie_jar"
        return 1
    fi
    
    log_info "Logged in successfully"
    
    # Create API key with required scopes and expiration
    log_step "Creating API key..."
    
    # Calculate expiration timestamp (1 year from now in milliseconds)
    local expires_at=$(($(date +%s) * 1000 + 365 * 24 * 60 * 60 * 1000))
    
    local api_key_response=$(curl -s -b "$cookie_jar" -X POST http://localhost:6789/rest/api-keys \
        -H "Content-Type: application/json" \
        -d "{\"label\":\"integration-test-key\",\"scopes\":[\"workflow:create\",\"workflow:delete\",\"workflow:read\",\"workflow:update\",\"workflow:list\",\"workflow:execute\"],\"expiresAt\":$expires_at}")
    
    # Extract raw API key from response
    N8N_API_KEY=$(echo "$api_key_response" | grep -o '"rawApiKey":"[^"]*"' | cut -d'"' -f4)
    
    if [ -z "$N8N_API_KEY" ]; then
        log_error "Failed to create API key: $api_key_response"
        rm -f "$cookie_jar"
        return 1
    fi
    
    log_info "API key created successfully"
    export N8N_API_KEY
    
    # Create Slack API credential for test workflows
    # Includes signing secret for signature verification tests
    log_step "Creating Slack API credential with signing secret..."
    
    local credential_response=$(curl -s -b "$cookie_jar" -X POST http://localhost:6789/rest/credentials \
        -H "Content-Type: application/json" \
        -d "{\"name\":\"Test Slack API\",\"type\":\"slackApi\",\"data\":{\"accessToken\":\"xoxb-test-token-for-integration-tests\",\"signatureSecret\":\"$SLACK_SIGNING_SECRET\"}}")
    
    # Extract credential ID from response
    SLACK_CREDENTIAL_ID=$(echo "$credential_response" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
    
    if [ -z "$SLACK_CREDENTIAL_ID" ]; then
        log_error "Failed to create Slack credential: $credential_response"
        rm -f "$cookie_jar"
        return 1
    fi
    
    log_info "Slack API credential created with ID: $SLACK_CREDENTIAL_ID"
    export SLACK_CREDENTIAL_ID
    
    # Create a "dud" Jira Software Cloud API credential for Jira trigger test
    # workflows. The domain points at the n8n-unihook container so that
    # n8n's webhook registration calls are intercepted by Unihook's built-in
    # provider API mock routes (see src/routes/provider_jira.rs).
    log_step "Creating Jira Software Cloud API credential (pointing to n8n-unihook)..."
    
    local jira_credential_response=$(curl -s -b "$cookie_jar" -X POST http://localhost:6789/rest/credentials \
        -H "Content-Type: application/json" \
        -d '{"name":"Test Jira Software Cloud API","type":"jiraSoftwareCloudApi","data":{"email":"test@example.com","apiToken":"test-api-token","domain":"http://n8n-unihook:3000"}}')
    
    # Extract credential ID from response
    JIRA_CREDENTIAL_ID=$(echo "$jira_credential_response" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
    
    if [ -z "$JIRA_CREDENTIAL_ID" ]; then
        log_error "Failed to create Jira credential: $jira_credential_response"
        rm -f "$cookie_jar"
        return 1
    fi
    
    log_info "Jira Software Cloud API credential created with ID: $JIRA_CREDENTIAL_ID"
    export JIRA_CREDENTIAL_ID
    
    # Create a "dud" GitHub API credential for GitHub trigger test workflows.
    # The server points at the n8n-unihook container so that n8n's
    # webhook registration calls are intercepted by Unihook's built-in
    # provider API mock routes (see src/routes/provider_github.rs).
    # Unihook captures the HMAC secret from the registration body and stores
    # it in SQLite for later re-signing.
    log_step "Creating GitHub API credential (pointing to n8n-unihook)..."
    
    local github_credential_response=$(curl -s -b "$cookie_jar" -X POST http://localhost:6789/rest/credentials \
        -H "Content-Type: application/json" \
        -d '{"name":"Test GitHub API","type":"githubApi","data":{"server":"http://n8n-unihook:3000","user":"test-user","accessToken":"test-token"}}')
    
    # Extract credential ID from response
    GITHUB_CREDENTIAL_ID=$(echo "$github_credential_response" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
    
    if [ -z "$GITHUB_CREDENTIAL_ID" ]; then
        log_error "Failed to create GitHub credential: $github_credential_response"
        rm -f "$cookie_jar"
        return 1
    fi
    
    log_info "GitHub API credential created with ID: $GITHUB_CREDENTIAL_ID"
    export GITHUB_CREDENTIAL_ID
    
    # Clean up cookie jar
    rm -f "$cookie_jar"
    
    return 0
}

# Start Docker environment if not skipped
if [ "$SKIP_DOCKER" != "true" ]; then
    # Clean up any existing test environment first (aggressive cleanup)
    log_step "Cleaning up previous test environment..."
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" down -v 2>/dev/null || true
    
    # Also remove any orphaned volumes from previous test runs
    # This ensures a clean state even if previous cleanup failed
    docker volume rm "${PROJECT_NAME}_n8n_test_data" 2>/dev/null || true
    docker volume rm "n8n-unihook-test_n8n_test_data" 2>/dev/null || true
    
    # Remove containers explicitly in case they're orphaned
    docker rm -f n8n-test n8n-unihook-test 2>/dev/null || true
    # Also clean up legacy containers from before the mock-apis removal
    docker rm -f mock-apis-test mock-jira-test mock-github-test 2>/dev/null || true
    
    log_step "Starting n8n and n8n-unihook (initial boot with empty API key for mock endpoints)..."
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" up -d --build n8n n8n-unihook

    log_info "Waiting for n8n to be healthy..."
    if ! wait_for_n8n; then
        log_error "n8n failed to become healthy"
        exit 1
    fi
    log_info "n8n is healthy"

    log_info "Waiting for n8n-unihook to be healthy (mock endpoints)..."
    if ! wait_for_unihook; then
        log_error "n8n-unihook failed to become healthy"
        exit 1
    fi
    log_info "n8n-unihook mock endpoints are ready"
    
    # Wait for n8n REST API to be fully ready (health check passes before all routes are registered)
    log_info "Waiting for n8n REST API to be fully ready..."
    sleep 10

    # Setup n8n and get API key (credentials point at n8n-unihook:3000)
    if ! setup_n8n; then
        log_error "Failed to setup n8n"
        exit 1
    fi
    
    # Restart n8n-unihook with the real API key so trigger sync works
    log_step "Restarting n8n-unihook with real API key..."
    N8N_API_KEY="$N8N_API_KEY" docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" up -d n8n-unihook
    
    log_info "Waiting for n8n-unihook to be healthy..."
    if ! wait_for_unihook; then
        log_error "n8n-unihook failed to become healthy after restart"
        exit 1
    fi
    log_info "n8n-unihook is healthy"

    log_info "All services are ready!"
else
    log_info "Skipping Docker setup (--skip-docker)"
    
    # Verify services are running
    if ! curl -s -f http://localhost:6789/healthz > /dev/null 2>&1; then
        log_error "n8n is not running at http://localhost:6789"
        exit 1
    fi
    
    if ! curl -s -f http://localhost:3000/health > /dev/null 2>&1; then
        log_error "n8n-unihook is not running at http://localhost:3000"
        exit 1
    fi
    
    log_info "Services are already running"
fi

# Run tests with the API key and credential ID available
log_step "Running integration tests..."
echo ""

# Export the API key and credential IDs for the Rust tests to use
export TEST_N8N_API_KEY="$N8N_API_KEY"
export SLACK_CREDENTIAL_ID="$SLACK_CREDENTIAL_ID"
export JIRA_CREDENTIAL_ID="$JIRA_CREDENTIAL_ID"
export GITHUB_CREDENTIAL_ID="$GITHUB_CREDENTIAL_ID"

if [ -n "$TEST_FILTER" ]; then
    TEST_N8N_API_KEY="$N8N_API_KEY" SLACK_CREDENTIAL_ID="$SLACK_CREDENTIAL_ID" JIRA_CREDENTIAL_ID="$JIRA_CREDENTIAL_ID" GITHUB_CREDENTIAL_ID="$GITHUB_CREDENTIAL_ID" cargo test --test integration "$TEST_FILTER" -- --test-threads=1 --nocapture
else
    TEST_N8N_API_KEY="$N8N_API_KEY" SLACK_CREDENTIAL_ID="$SLACK_CREDENTIAL_ID" JIRA_CREDENTIAL_ID="$JIRA_CREDENTIAL_ID" GITHUB_CREDENTIAL_ID="$GITHUB_CREDENTIAL_ID" cargo test --test integration -- --test-threads=1 --nocapture
fi

TEST_RESULT=$?

echo ""
if [ $TEST_RESULT -eq 0 ]; then
    log_info "All integration tests passed!"
else
    log_error "Some integration tests failed!"
fi

exit $TEST_RESULT
