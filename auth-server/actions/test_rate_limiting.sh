#!/bin/bash

# Test script for rate limiting functionality

set -e

echo "=== Rate Limiting Feature Test ==="

# Configuration
SERVER_URL="http://localhost:8000"
USERNAME="testuser_$(date +%s)"
WRONG_PASSWORD="wrongpassword"

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

# Function to test login rate limiting
test_login_rate_limiting() {
    print_header "Testing Login Rate Limiting"
    
    # First, register a user
    CSRF_TOKEN=$(get_csrf_token "register")
    
    response=$(curl -s -X POST "$SERVER_URL/register" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$USERNAME\",\"email\":\"$USERNAME@example.com\",\"password\":\"TestPass123!\",\"csrfToken\":\"$CSRF_TOKEN\"}")
    
    if ! echo "$response" | jq -e '.message | contains("successfully")' > /dev/null; then
        print_error "Failed to register test user"
        return 1
    fi
    
    print_success "Test user registered"
    
    # Attempt to login with wrong password multiple times to trigger rate limiting
    print_header "Attempting multiple failed logins to trigger rate limit"
    
    rate_limit_triggered=false
    for i in {1..10}; do
        CSRF_TOKEN=$(get_csrf_token "login")
        
        response=$(curl -s -X POST "$SERVER_URL/login" \
            -H "Content-Type: application/json" \
            -d "{\"username\":\"$USERNAME\",\"password\":\"$WRONG_PASSWORD\",\"csrfToken\":\"$CSRF_TOKEN\"}")
        
        if echo "$response" | jq -e '.error | contains("Rate limit")' > /dev/null; then
            print_success "Rate limit correctly triggered on attempt $i"
            rate_limit_triggered=true
            break
        else
            echo "Attempt $i: Login failed as expected (wrong password)"
            sleep 0.5  # Small delay to avoid overwhelming the server
        fi
    done
    
    if [ "$rate_limit_triggered" = false ]; then
        print_error "Rate limit was not triggered after 10 failed attempts"
        return 1
    fi
    
    return 0
}

# Function to test general rate limiting
test_general_rate_limiting() {
    print_header "Testing General Rate Limiting"
    
    # Make multiple requests to a public endpoint to trigger rate limiting
    rate_limit_triggered=false
    for i in {1..150}; do
        response=$(curl -s -X GET "$SERVER_URL/health")
        
        if echo "$response" | jq -e '.status' > /dev/null; then
            echo "Request $i: Health check successful"
        elif echo "$response" | grep -q "429"; then
            print_success "General rate limit correctly triggered on request $i"
            rate_limit_triggered=true
            break
        else
            echo "Request $i: Unexpected response"
        fi
        
        # Small delay to avoid overwhelming the server
        sleep 0.1
    done
    
    if [ "$rate_limit_triggered" = false ]; then
        print_error "General rate limit was not triggered after 150 requests"
        return 1
    fi
    
    return 0
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
    test_login_rate_limiting || exit 1
    test_general_rate_limiting || exit 1
    
    echo -e "\n${GREEN}=== Rate limiting tests passed! ===${NC}"
}

main