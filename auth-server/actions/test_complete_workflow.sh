#!/bin/sh

# Complete workflow test for the authentication server
# Tests registration, login, token refresh, and logout

set -e  # Exit on any error

echo "=== Authentication Server Complete Workflow Test ==="

# Configuration
SERVER_URL="http://localhost:8000"
USERNAME="testuser_$(date +%s)"  # Unique username with timestamp
EMAIL="testuser_$(date +%s)@example.com"
PASSWORD="TestPass123!"
NEW_PASSWORD="NewPass456!"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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

# Function to check if server is running
check_server() {
    print_header "Checking if server is running"
    if curl -s -f "$SERVER_URL/health" > /dev/null; then
        print_success "Server is running"
        return 0
    else
        print_error "Server is not accessible at $SERVER_URL"
        return 1
    fi
}

# Function to get CSRF token
get_csrf_token() {
    local action=$1
    local response=$(curl -s -X GET "$SERVER_URL/csrf/$action")
    echo "$response" | jq -r '.csrfToken'
}

# Function to register a new user
test_registration() {
    print_header "Testing User Registration"
    
    # Get CSRF token for registration
    CSRF_TOKEN=$(get_csrf_token "register")
    echo "Got CSRF token for registration: $CSRF_TOKEN"
    
    # Register new user
    response=$(curl -s -X POST "$SERVER_URL/register" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$USERNAME\",\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"csrfToken\":\"$CSRF_TOKEN\"}")
    
    # Check response
    if echo "$response" | jq -e '.message | contains("successfully")' > /dev/null; then
        print_success "User registration successful"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Registration failed: $error_msg"
        return 1
    fi
}

# Function to test login
test_login() {
    print_header "Testing User Login"
    
    # Get CSRF token for login
    CSRF_TOKEN=$(get_csrf_token "login")
    echo "Got CSRF token for login: $CSRF_TOKEN"
    
    # Login
    response=$(curl -s -X POST "$SERVER_URL/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\",\"csrfToken\":\"$CSRF_TOKEN\"}")
    
    # Check response
    if echo "$response" | jq -e '.token' > /dev/null; then
        ACCESS_TOKEN=$(echo "$response" | jq -r '.token')
        REFRESH_TOKEN=$(echo "$response" | jq -r '.refreshToken')
        CSRF_TOKEN=$(echo "$response" | jq -r '.csrfToken')
        print_success "User login successful"
        echo "Access token: $ACCESS_TOKEN"
        echo "Refresh token: $REFRESH_TOKEN"
        echo "CSRF token: $CSRF_TOKEN"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Login failed: $error_msg"
        return 1
    fi
}

# Function to test token validation
test_token_validation() {
    print_header "Testing Token Validation"
    
    # Validate access token
    response=$(curl -s -X GET "$SERVER_URL/validate" \
        -H "Authorization: Bearer $ACCESS_TOKEN")
    
    # Check response
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

# Function to test token refresh
test_token_refresh() {
    print_header "Testing Token Refresh"
    
    # Get CSRF token for refresh
    CSRF_TOKEN=$(get_csrf_token "refresh")
    echo "Got CSRF token for refresh: $CSRF_TOKEN"
    
    # Refresh tokens
    response=$(curl -s -X POST "$SERVER_URL/refresh" \
        -H "Content-Type: application/json" \
        -d "{\"refreshToken\":\"$REFRESH_TOKEN\",\"csrfToken\":\"$CSRF_TOKEN\"}")
    
    # Check response
    if echo "$response" | jq -e '.token' > /dev/null; then
        NEW_ACCESS_TOKEN=$(echo "$response" | jq -r '.token')
        NEW_REFRESH_TOKEN=$(echo "$response" | jq -r '.refreshToken')
        print_success "Token refresh successful"
        echo "New access token: $NEW_ACCESS_TOKEN"
        echo "New refresh token: $NEW_REFRESH_TOKEN"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Token refresh failed: $error_msg"
        return 1
    fi
}

# Function to test logout
test_logout() {
    print_header "Testing User Logout"
    
    # Get CSRF token for logout
    CSRF_TOKEN=$(get_csrf_token "logout")
    echo "Got CSRF token for logout: $CSRF_TOKEN"
    
    # Logout
    response=$(curl -s -X POST "$SERVER_URL/logout" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $NEW_ACCESS_TOKEN" \
        -H "X-CSRF-Token: $CSRF_TOKEN")
    
    # Check response
    if echo "$response" | jq -e '.message | contains("successfully")' > /dev/null; then
        print_success "User logout successful"
        return 0
    else
        error_msg=$(echo "$response" | jq -r '.error')
        print_error "Logout failed: $error_msg"
        return 1
    fi
}

# Function to test that tokens are invalidated after logout
test_token_invalidated() {
    print_header "Testing Token Invalidated After Logout"
    
    # Try to validate the old access token (should fail)
    response=$(curl -s -X GET "$SERVER_URL/validate" \
        -H "Authorization: Bearer $NEW_ACCESS_TOKEN")
    
    # Check response
    if echo "$response" | jq -e '.error' > /dev/null; then
        print_success "Token correctly invalidated after logout"
        return 0
    else
        print_error "Token was not properly invalidated after logout"
        return 1
    fi
}

# Main test execution
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
    
    # Check if server is running
    if ! check_server; then
        print_error "Cannot proceed with tests. Please start the server first."
        exit 1
    fi
    
    # Run all tests
    test_registration || exit 1
    test_login || exit 1
    test_token_validation || exit 1
    test_token_refresh || exit 1
    test_logout || exit 1
    test_token_invalidated || exit 1
    
    echo -e "\n${GREEN}=== All tests passed! ===${NC}"
}

# Run the main function
main
