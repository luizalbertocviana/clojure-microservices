#!/bin/bash

# Test script for password reset functionality

set -e

echo "=== Password Reset Feature Test ==="

# Configuration
SERVER_URL="http://localhost:8000"
USERNAME="testuser_$(date +%s)"
EMAIL="testuser_$(date +%s)@example.com"
PASSWORD="TestPass123!"
NEW_PASSWORD="NewPass456!"

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

# Function to register a user
register_user() {
    print_header "Registering test user"
    
    CSRF_TOKEN=$(get_csrf_token "register")
    
    response=$(curl -s -X POST "$SERVER_URL/register" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$USERNAME\",\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"csrfToken\":\"$CSRF_TOKEN\"}")
    
    if echo "$response" | jq -e '.message | contains("successfully")' > /dev/null; then
        print_success "User registered successfully"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Registration failed: $error_msg"
        return 1
    fi
}

# Function to test password reset workflow
test_password_reset() {
    print_header "Testing Password Reset Workflow"
    
    # Request password reset
    CSRF_TOKEN=$(get_csrf_token "forgot-password")
    
    response=$(curl -s -X POST "$SERVER_URL/forgot-password" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$EMAIL\",\"csrfToken\":\"$CSRF_TOKEN\"}")
    
    if echo "$response" | jq -e '.message | contains("reset link")' > /dev/null; then
        RESET_TOKEN=$(echo "$response" | jq -r '.resetToken')
        print_success "Password reset request successful"
        echo "Reset token: $RESET_TOKEN"
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Password reset request failed: $error_msg"
        return 1
    fi
    
    # Reset password
    CSRF_TOKEN=$(get_csrf_token "reset-password")
    
    response=$(curl -s -X POST "$SERVER_URL/reset-password" \
        -H "Content-Type: application/json" \
        -d "{\"token\":\"$RESET_TOKEN\",\"newPassword\":\"$NEW_PASSWORD\",\"csrfToken\":\"$CSRF_TOKEN\"}")
    
    if echo "$response" | jq -e '.message | contains("successfully")' > /dev/null; then
        print_success "Password reset successful"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Password reset failed: $error_msg"
        return 1
    fi
}

# Function to test login with new password
test_new_password_login() {
    print_header "Testing Login with New Password"
    
    CSRF_TOKEN=$(get_csrf_token "login")
    
    response=$(curl -s -X POST "$SERVER_URL/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$USERNAME\",\"password\":\"$NEW_PASSWORD\",\"csrfToken\":\"$CSRF_TOKEN\"}")
    
    if echo "$response" | jq -e '.token' > /dev/null; then
        print_success "Login with new password successful"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Login with new password failed: $error_msg"
        return 1
    fi
}

# Function to test login with old password (should fail)
test_old_password_invalid() {
    print_header "Testing Login with Old Password (should fail)"
    
    CSRF_TOKEN=$(get_csrf_token "login")
    
    response=$(curl -s -X POST "$SERVER_URL/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\",\"csrfToken\":\"$CSRF_TOKEN\"}")
    
    if echo "$response" | jq -e '.error' > /dev/null; then
        print_success "Login with old password correctly failed"
        return 0
    else
        print_error "Login with old password should have failed but didn't"
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
    
    # Run tests
    register_user || exit 1
    test_password_reset || exit 1
    test_new_password_login || exit 1
    test_old_password_invalid || exit 1
    
    echo -e "\n${GREEN}=== Password reset tests passed! ===${NC}"
}

main