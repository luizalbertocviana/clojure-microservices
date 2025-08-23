#!/bin/bash

# Test script for input validation functionality

set -e

echo "=== Input Validation Test ==="

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

# Function to test registration with invalid inputs
test_invalid_registration_inputs() {
    print_header "Testing Registration with Invalid Inputs"
    
    CSRF_TOKEN=$(get_csrf_token "register")
    
    # Test cases for invalid inputs
    test_cases=(
        # Username too short
        '{"username":"ab","email":"test@example.com","password":"TestPass123!","csrfToken":"CSRF_TOKEN"}|Invalid input'
        # Username with invalid characters
        '{"username":"user@name","email":"test@example.com","password":"TestPass123!","csrfToken":"CSRF_TOKEN"}|Invalid input'
        # Invalid email
        '{"username":"username","email":"invalid-email","password":"TestPass123!","csrfToken":"CSRF_TOKEN"}|Invalid input'
        # Password too short
        '{"username":"username","email":"test@example.com","password":"Short1!","csrfToken":"CSRF_TOKEN"}|Invalid input'
        # Password without uppercase
        '{"username":"username","email":"test@example.com","password":"testpass123!","csrfToken":"CSRF_TOKEN"}|Invalid input'
        # Password without number
        '{"username":"username","email":"test@example.com","password":"TestPassword!","csrfToken":"CSRF_TOKEN"}|Invalid input'
        # Password without special character
        '{"username":"username","email":"test@example.com","password":"TestPass123","csrfToken":"CSRF_TOKEN"}|Invalid input'
        # Missing CSRF token
        '{"username":"username","email":"test@example.com","password":"TestPass123!"}|Invalid/missing CSRF token'
    )
    
    for test_case in "${test_cases[@]}"; do
        IFS='|' read -r payload expected_error <<< "$test_case"
        payload=${payload//CSRF_TOKEN/$CSRF_TOKEN}
        
        response=$(curl -s -X POST "$SERVER_URL/register" \
            -H "Content-Type: application/json" \
            -d "$payload")
        
        if echo "$response" | jq -e ".error | contains(\"$expected_error\")" > /dev/null; then
            print_success "Correctly rejected invalid input: $expected_error"
        else
            error_msg=$(echo "$response" | jq -r '.error')
            print_error "Failed to reject invalid input. Expected '$expected_error', got '$error_msg'"
            return 1
        fi
    done
    
    return 0
}

# Function to test valid registration
test_valid_registration() {
    print_header "Testing Valid Registration"
    
    USERNAME="validuser_$(date +%s)"
    EMAIL="validuser_$(date +%s)@example.com"
    PASSWORD="ValidPass123!"
    
    CSRF_TOKEN=$(get_csrf_token "register")
    
    response=$(curl -s -X POST "$SERVER_URL/register" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$USERNAME\",\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"csrfToken\":\"$CSRF_TOKEN\"}")
    
    if echo "$response" | jq -e '.message | contains("successfully")' > /dev/null; then
        print_success "Valid registration successful"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Valid registration failed: $error_msg"
        return 1
    fi
}

# Function to test duplicate registration
test_duplicate_registration() {
    print_header "Testing Duplicate Registration"
    
    # Try to register the same user again
    CSRF_TOKEN=$(get_csrf_token "register")
    
    response=$(curl -s -X POST "$SERVER_URL/register" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$USERNAME\",\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"csrfToken\":\"$CSRF_TOKEN\"}")
    
    if echo "$response" | jq -e '.error | contains("already exists")' > /dev/null; then
        print_success "Correctly rejected duplicate registration"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Failed to reject duplicate registration. Got: $error_msg"
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
    test_invalid_registration_inputs || exit 1
    test_valid_registration || exit 1
    test_duplicate_registration || exit 1
    
    echo -e "\n${GREEN}=== Input validation tests passed! ===${NC}"
}

main