#!/bin/sh

# Test script for password reset edge cases

set -e

echo "=== Password Reset Edge Cases Test ==="

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

# Function to register a user for password reset tests
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
    
    if echo "$response" | jq -e '.message | contains("successfully")' > /dev/null; then
        print_success "User registered successfully"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Failed to register user. Got: $error_msg"
        return 1
    fi
}

# Function to test forgot password with invalid email
test_forgot_password_invalid_email() {
    print_header "Testing Forgot Password with Invalid Email"
    
    CSRF_TOKEN=$(get_csrf_token "forgot-password")
    
    response=$(curl -s -X POST "$SERVER_URL/forgot-password" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"invalid-email\",\"csrfToken\":\"$CSRF_TOKEN\"}")
    
    if echo "$response" | jq -e '.error | contains("Invalid input")' > /dev/null; then
        print_success "Correctly rejected invalid email"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Failed to reject invalid email. Got: $error_msg"
        return 1
    fi
}

# Function to test forgot password with missing CSRF
test_forgot_password_missing_csrf() {
    print_header "Testing Forgot Password with Missing CSRF"
    
    response=$(curl -s -X POST "$SERVER_URL/forgot-password" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$EMAIL\"}")
    
    if echo "$response" | jq -e '.error | contains("Invalid/missing CSRF token")' > /dev/null; then
        print_success "Correctly rejected missing CSRF token"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Failed to reject missing CSRF token. Got: $error_msg"
        return 1
    fi
}

# Function to test valid forgot password request
test_forgot_password_valid() {
    print_header "Testing Valid Forgot Password Request"
    
    CSRF_TOKEN=$(get_csrf_token "forgot-password")
    
    response=$(curl -s -X POST "$SERVER_URL/forgot-password" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$EMAIL\",\"csrfToken\":\"$CSRF_TOKEN\"}")
    
    if echo "$response" | jq -e '.message | contains("reset link")' > /dev/null; then
        RESET_TOKEN=$(echo "$response" | jq -r '.resetToken')
        print_success "Password reset request successful"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Password reset request failed. Got: $error_msg"
        return 1
    fi
}

# Function to test reset password with invalid token
test_reset_password_invalid_token() {
    print_header "Testing Reset Password with Invalid Token"
    
    CSRF_TOKEN=$(get_csrf_token "reset-password")
    NEW_PASSWORD="NewPass456!"
    
    response=$(curl -s -X POST "$SERVER_URL/reset-password" \
        -H "Content-Type: application/json" \
        -d "{\"token\":\"invalid-token\",\"newPassword\":\"$NEW_PASSWORD\",\"csrfToken\":\"$CSRF_TOKEN\"}")
    
    if echo "$response" | jq -e '.error | contains("Invalid/expired reset token")' > /dev/null; then
        print_success "Correctly rejected invalid reset token"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Failed to reject invalid reset token. Got: $error_msg"
        return 1
    fi
}

# Function to test reset password with invalid password
test_reset_password_invalid_password() {
    print_header "Testing Reset Password with Invalid Password"
    
    # First get a valid reset token
    test_forgot_password_valid || return 1
    
    CSRF_TOKEN=$(get_csrf_token "reset-password")
    
    # Test with too short password
    response=$(curl -s -X POST "$SERVER_URL/reset-password" \
        -H "Content-Type: application/json" \
        -d "{\"token\":\"$RESET_TOKEN\",\"newPassword\":\"short\",\"csrfToken\":\"$CSRF_TOKEN\"}")
    
    if echo "$response" | jq -e '.error | contains("Invalid input")' > /dev/null; then
        print_success "Correctly rejected invalid password"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Failed to reject invalid password. Got: $error_msg"
        return 1
    fi
}

# Function to test reset password with missing CSRF
test_reset_password_missing_csrf() {
    print_header "Testing Reset Password with Missing CSRF"
    
    # First get a valid reset token
    test_forgot_password_valid || return 1
    
    NEW_PASSWORD="NewPass456!"
    
    response=$(curl -s -X POST "$SERVER_URL/reset-password" \
        -H "Content-Type: application/json" \
        -d "{\"token\":\"$RESET_TOKEN\",\"newPassword\":\"$NEW_PASSWORD\"}")
    
    if echo "$response" | jq -e '.error | contains("Invalid/missing CSRF token")' > /dev/null; then
        print_success "Correctly rejected missing CSRF token"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Failed to reject missing CSRF token. Got: $error_msg"
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
    test_forgot_password_invalid_email || exit 1
    test_forgot_password_missing_csrf || exit 1
    test_reset_password_invalid_token || exit 1
    test_reset_password_invalid_password || exit 1
    test_reset_password_missing_csrf || exit 1
    
    echo -e "\n${GREEN}=== Password reset edge cases tests passed! ===${NC}"
}

main