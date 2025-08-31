#!/bin/sh

# Test script for audit logging functionality

set -e

echo "=== Audit Logging Test ==="

# Configuration
SERVER_URL="http://localhost:8000"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Function to print section headers
print_header() {
    echo -e "${YELLOW}--- $1 ---${NC}"
}

# Function to print success messages
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

# Function to print error messages
print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Function to get CSRF token
get_csrf_token() {
    local action=$1
    local response=$(curl -s -X GET "$SERVER_URL/csrf/$action")
    echo "$response" | jq -r '.csrfToken'
}

# Function to register a user for audit tests
setup_user() {
    print_header "Setting up test user for audit logging"
    
    USERNAME="audituser_$(date +%s)"
    EMAIL="audituser_$(date +%s)@example.com"
    PASSWORD="TestPass123!"
    
    # Register
    CSRF_TOKEN=$(get_csrf_token "register")
    response=$(curl -s -X POST "$SERVER_URL/register" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$USERNAME\",\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"csrfToken\":\"$CSRF_TOKEN\"}")
    
    if echo "$response" | jq -e '.message | contains("successfully")' > /dev/null; then
        print_success "User registered successfully"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Failed to register user. Got: $error_msg"
        return 1
    fi
}

# Function to test login audit
test_login_audit() {
    print_header "Testing Login Audit Logging"
    
    # Login
    CSRF_TOKEN=$(get_csrf_token "login")
    response=$(curl -s -X POST "$SERVER_URL/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\",\"csrfToken\":\"$CSRF_TOKEN\"}")
    
    if echo "$response" | jq -e '.token' > /dev/null; then
        print_success "User login successful (audit event should be logged)"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Login failed. Got: $error_msg"
        return 1
    fi
}

# Function to test failed login audit
test_failed_login_audit() {
    print_header "Testing Failed Login Audit Logging"
    
    # Failed login
    CSRF_TOKEN=$(get_csrf_token "login")
    response=$(curl -s -X POST "$SERVER_URL/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$USERNAME\",\"password\":\"WrongPassword123!\",\"csrfToken\":\"$CSRF_TOKEN\"}")
    
    # Even though it fails, it should still log the attempt
    print_success "Failed login attempt made (audit event should be logged)"
    return 0
}

# Function to test logout audit
test_logout_audit() {
    print_header "Testing Logout Audit Logging"
    
    # Login first to get a token
    CSRF_TOKEN=$(get_csrf_token "login")
    response=$(curl -s -X POST "$SERVER_URL/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\",\"csrfToken\":\"$CSRF_TOKEN\"}")
    
    if echo "$response" | jq -e '.token' > /dev/null; then
        ACCESS_TOKEN=$(echo "$response" | jq -r '.token')
    else
        print_error "Failed to get access token for logout"
        return 1
    fi
    
    # Logout
    CSRF_TOKEN=$(get_csrf_token "logout")
    response=$(curl -s -X POST "$SERVER_URL/logout" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "X-CSRF-Token: $CSRF_TOKEN")
    
    if echo "$response" | jq -e '.message | contains("successfully")' > /dev/null; then
        print_success "User logout successful (audit event should be logged)"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Logout failed. Got: $error_msg"
        return 1
    fi
}

# Function to test password reset audit
test_password_reset_audit() {
    print_header "Testing Password Reset Audit Logging"
    
    # Request password reset
    CSRF_TOKEN=$(get_csrf_token "forgot-password")
    response=$(curl -s -X POST "$SERVER_URL/forgot-password" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$EMAIL\",\"csrfToken\":\"$CSRF_TOKEN\"}")
    
    if echo "$response" | jq -e '.message | contains("reset link")' > /dev/null; then
        print_success "Password reset request successful (audit event should be logged)"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Password reset request failed. Got: $error_msg"
        return 1
    fi
}

# Main execution
main() {
    # Check if required tools are available
    if ! command -v curl &> /dev/null; then
        print_error "curl is required but not installed"
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        print_error "jq is required but not installed"
        exit 1
    fi
    
    # Setup user
    setup_user || exit 1
    
    # Run audit tests
    test_login_audit || exit 1
    test_failed_login_audit || exit 1
    test_logout_audit || exit 1
    test_password_reset_audit || exit 1
    
    echo -e "\n${GREEN}=== Audit logging tests completed! ===${NC}"
    echo -e "${YELLOW}Note: To verify audit logs, check the database audit_log table${NC}"
}

main