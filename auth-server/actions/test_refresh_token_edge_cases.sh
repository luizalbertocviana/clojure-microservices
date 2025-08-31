#!/bin/sh

# Test script for refresh token edge cases

set -e

echo "=== Refresh Token Edge Cases Test ==="

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

# Function to register and login to get refresh tokens
setup_user_and_tokens() {
    print_header "Setting up test user and tokens"
    
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
        print_success "User and tokens setup successful"
        return 0
    else
        print_error "Failed to login test user"
        return 1
    fi
}

# Function to test invalid refresh token
test_invalid_refresh_token() {
    print_header "Testing Invalid Refresh Token"
    
    CSRF_TOKEN=$(get_csrf_token "refresh")
    
    response=$(curl -s -X POST "$SERVER_URL/refresh" \
        -H "Content-Type: application/json" \
        -d "{\"refreshToken\":\"invalid.token.here\",\"csrfToken\":\"$CSRF_TOKEN\"}")
    
    if echo "$response" | jq -e '.error | contains("Invalid/expired refresh token")' > /dev/null; then
        print_success "Correctly rejected invalid refresh token"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Failed to reject invalid refresh token. Got: $error_msg"
        return 1
    fi
}

# Function to test missing refresh token
test_missing_refresh_token() {
    print_header "Testing Missing Refresh Token"
    
    CSRF_TOKEN=$(get_csrf_token "refresh")
    
    response=$(curl -s -X POST "$SERVER_URL/refresh" \
        -H "Content-Type: application/json" \
        -d "{\"csrfToken\":\"$CSRF_TOKEN\"}")
    
    if echo "$response" | jq -e '.error | contains("Invalid input")' > /dev/null; then
        print_success "Correctly rejected missing refresh token"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Failed to reject missing refresh token. Got: $error_msg"
        return 1
    fi
}

# Function to test refresh with invalid CSRF
test_refresh_with_invalid_csrf() {
    print_header "Testing Refresh with Invalid CSRF Token"
    
    response=$(curl -s -X POST "$SERVER_URL/refresh" \
        -H "Content-Type: application/json" \
        -d "{\"refreshToken\":\"$REFRESH_TOKEN\",\"csrfToken\":\"invalid-csrf-token\"}")
    
    if echo "$response" | jq -e '.error | contains("Invalid/missing CSRF token")' > /dev/null; then
        print_success "Correctly rejected invalid CSRF token"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Failed to reject invalid CSRF token. Got: $error_msg"
        return 1
    fi
}

# Function to test successful refresh
test_successful_refresh() {
    print_header "Testing Successful Refresh"
    
    CSRF_TOKEN=$(get_csrf_token "refresh")
    
    response=$(curl -s -X POST "$SERVER_URL/refresh" \
        -H "Content-Type: application/json" \
        -d "{\"refreshToken\":\"$REFRESH_TOKEN\",\"csrfToken\":\"$CSRF_TOKEN\"}")
    
    if echo "$response" | jq -e '.token and .refreshToken' > /dev/null; then
        NEW_ACCESS_TOKEN=$(echo "$response" | jq -r '.token')
        NEW_REFRESH_TOKEN=$(echo "$response" | jq -r '.refreshToken')
        print_success "Token refresh successful"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Token refresh failed. Got: $error_msg"
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
    
    # Setup user and tokens
    setup_user_and_tokens || exit 1
    
    # Run tests
    test_invalid_refresh_token || exit 1
    test_missing_refresh_token || exit 1
    test_refresh_with_invalid_csrf || exit 1
    test_successful_refresh || exit 1
    
    echo -e "\n${GREEN}=== Refresh token edge cases tests passed! ===${NC}"
}

main