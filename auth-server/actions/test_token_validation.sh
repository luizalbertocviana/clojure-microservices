#!/bin/sh

# Test script for token validation functionality

set -e

echo "=== Token Validation Test ==="

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

# Function to register and login to get valid tokens
setup_user() {
    print_header "Setting up test user"
    
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
    
    if echo "$response" | jq -e '.token' > /dev/null; then
        ACCESS_TOKEN=$(echo "$response" | jq -r '.token')
        print_success "User setup successful"
        return 0
    else
        print_error "Failed to login test user"
        return 1
    fi
}

# Function to test valid token validation
test_valid_token_validation() {
    print_header "Testing Valid Token Validation"
    
    response=$(curl -s -X GET "$SERVER_URL/validate" \
        -H "Authorization: Bearer $ACCESS_TOKEN")
    
    if echo "$response" | jq -e '.username' > /dev/null; then
        validated_user=$(echo "$response" | jq -r '.username')
        print_success "Token validation successful for user: $validated_user"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Token validation failed: $error_msg"
        return 1
    fi
}

# Function to test invalid token validation
test_invalid_token_validation() {
    print_header "Testing Invalid Token Validation"
    
    # Test with invalid token
    response=$(curl -s -X GET "$SERVER_URL/validate" \
        -H "Authorization: Bearer invalid.token.here")
    
    if echo "$response" | jq -e '.error' > /dev/null; then
        print_success "Correctly rejected invalid token"
        return 0
    else
        print_error "Failed to reject invalid token"
        return 1
    fi
}

# Function to test missing token validation
test_missing_token_validation() {
    print_header "Testing Missing Token Validation"
    
    response=$(curl -s -X GET "$SERVER_URL/validate")
    
    if echo "$response" | jq -e '.error' > /dev/null; then
        print_success "Correctly rejected missing token"
        return 0
    else
        print_error "Failed to reject missing token"
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
    
    # Run tests
    test_valid_token_validation || exit 1
    test_invalid_token_validation || exit 1
    test_missing_token_validation || exit 1
    
    echo -e "\n${GREEN}=== Token validation tests passed! ===${NC}"
}

main