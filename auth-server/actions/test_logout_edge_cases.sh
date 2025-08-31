#!/bin/sh

# Test script for logout edge cases

set -e

echo "=== Logout Edge Cases Test ==="

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

# Function to register and login to get tokens for logout
setup_user_and_login() {
    print_header "Setting up test user and logging in"
    
    USERNAME="testuser_$(date +%s)"
    EMAIL="testuser_$(date +%s)@example.com"
    PASSWORD="TestPass123!"
    
    # Register
    CSRF_TOKEN=$(get_csrf_token "register")
    response=$(curl -s -X POST "$SERVER_URL/register" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$USERNAME\",\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"csrfToken\":\"$CSRF_TOKEN\"}")
    
    if ! echo "$response" | jq -e '.message | contains("successfully")' > /dev/null; then
        print_error "Failed to register test user"
        return 1
    fi
    
    # Login
    CSRF_TOKEN=$(get_csrf_token "login")
    response=$(curl -s -X POST "$SERVER_URL/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\",\"csrfToken\":\"$CSRF_TOKEN\"}")
    
    if echo "$response" | jq -e '.token and .refreshToken' > /dev/null; then
        ACCESS_TOKEN=$(echo "$response" | jq -r '.token')
        REFRESH_TOKEN=$(echo "$response" | jq -r '.refreshToken')
        LOGIN_CSRF_TOKEN=$(echo "$response" | jq -r '.csrfToken')
        print_success "User login successful"
        return 0
    else
        print_error "Failed to login test user"
        return 1
    fi
}

# Function to test logout with invalid CSRF token
test_logout_with_invalid_csrf() {
    print_header "Testing Logout with Invalid CSRF Token"
    
    response=$(curl -s -X POST "$SERVER_URL/logout" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "X-CSRF-Token: invalid-csrf-token")
    
    if echo "$response" | jq -e '.error | contains("Invalid/missing CSRF token")' > /dev/null; then
        print_success "Correctly rejected invalid CSRF token"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Failed to reject invalid CSRF token. Got: $error_msg"
        return 1
    fi
}

# Function to test logout with missing authorization header
test_logout_without_auth_header() {
    print_header "Testing Logout without Authorization Header"
    
    CSRF_TOKEN=$(get_csrf_token "logout")
    
    response=$(curl -s -X POST "$SERVER_URL/logout" \
        -H "Content-Type: application/json" \
        -H "X-CSRF-Token: $CSRF_TOKEN")
    
    if echo "$response" | jq -e '.error | contains("Missing token")' > /dev/null; then
        print_success "Correctly rejected missing authorization header"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Failed to reject missing authorization header. Got: $error_msg"
        return 1
    fi
}

# Function to test successful logout
test_successful_logout() {
    print_header "Testing Successful Logout"
    
    # Need to get a fresh CSRF token for logout
    CSRF_TOKEN=$(get_csrf_token "logout")
    
    response=$(curl -s -X POST "$SERVER_URL/logout" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "X-CSRF-Token: $CSRF_TOKEN")
    
    if echo "$response" | jq -e '.message | contains("successfully")' > /dev/null; then
        print_success "Logout successful"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Logout failed. Got: $error_msg"
        return 1
    fi
}

# Function to test logout with invalidated token
test_logout_with_invalidated_token() {
    print_header "Testing Logout with Invalidated Token"
    
    # Try to logout again with the same token (should fail)
    CSRF_TOKEN=$(get_csrf_token "logout")
    
    response=$(curl -s -X POST "$SERVER_URL/logout" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "X-CSRF-Token: $CSRF_TOKEN")
    
    if echo "$response" | jq -e '.error | contains("Blacklisted token")' > /dev/null; then
        print_success "Correctly rejected invalidated token"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Failed to reject invalidated token. Got: $error_msg"
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
    
    # Setup user and login
    setup_user_and_login || exit 1
    
    # Run tests
    test_logout_with_invalid_csrf || exit 1
    test_logout_without_auth_header || exit 1
    test_successful_logout || exit 1
    test_logout_with_invalidated_token || exit 1
    
    echo -e "\n${GREEN}=== Logout edge cases tests passed! ===${NC}"
}

main