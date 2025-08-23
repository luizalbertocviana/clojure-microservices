#!/bin/sh

# Test script for health endpoint and server status

set -e

echo "=== Server Health Check Test ==="

# Configuration
SERVER_URL="http://localhost:8000"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Function to print section headers
print_header() {
    echo -e "${YELLOW}--- $1 ---${NC}"
}

# Function to print success messages
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

# Function to print info messages
print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Function to print error messages
print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Function to test health endpoint
test_health_endpoint() {
    print_header "Testing Health Endpoint"
    
    response=$(curl -s -X GET "$SERVER_URL/health")
    
    # Check if we got a response
    if [ -z "$response" ]; then
        print_error "No response from health endpoint"
        return 1
    fi
    
    # Parse the response
    status=$(echo "$response" | jq -r '.status')
    database_status=$(echo "$response" | jq -r '.components.database')
    redis_status=$(echo "$response" | jq -r '.components.redis')
    jwt_status=$(echo "$response" | jq -r '.components.jwt')
    rate_limit_size=$(echo "$response" | jq -r '.components.rateLimitSize')
    pool_stats=$(echo "$response" | jq -r '.components.poolStats')
    
    # Display health information
    echo "Server Status: $status"
    echo "Database: $database_status"
    echo "Redis: $redis_status"
    echo "JWT: $jwt_status"
    echo "Rate Limit Entries: $rate_limit_size"
    echo "Connection Pool Stats: $pool_stats"
    
    # Check if overall status is OK
    if [ "$status" = "ok" ]; then
        print_success "Health check passed"
        return 0
    else
        print_error "Health check failed"
        return 1
    fi
}

# Function to test CSRF endpoints
test_csrf_endpoints() {
    print_header "Testing CSRF Endpoints"
    
    # Test a few different CSRF actions
    actions=("register" "login" "refresh" "logout" "forgot-password" "reset-password")
    
    for action in "${actions[@]}"; do
        response=$(curl -s -X GET "$SERVER_URL/csrf/$action")
        
        if echo "$response" | jq -e '.csrfToken' > /dev/null; then
            token=$(echo "$response" | jq -r '.csrfToken')
            if [ ${#token} -gt 20 ]; then
                print_success "CSRF token for '$action' generated successfully"
            else
                print_error "CSRF token for '$action' seems invalid"
                return 1
            fi
        else
            print_error "Failed to get CSRF token for '$action'"
            return 1
        fi
    done
    
    return 0
}

# Function to test 404 handling
test_404_handling() {
    print_header "Testing 404 Handling"
    
    response=$(curl -s -X GET "$SERVER_URL/nonexistent-endpoint")
    
    if echo "$response" | jq -e '.error | contains("Not found")' > /dev/null; then
        print_success "404 handling works correctly"
        return 0
    else
        print_error "404 handling failed"
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
    
    # Check if server is accessible
    if ! curl -s -f "$SERVER_URL/health" > /dev/null; then
        print_error "Server is not accessible at $SERVER_URL"
        print_info "Please make sure the authentication server is running"
        exit 1
    fi
    
    # Run tests
    test_health_endpoint || exit 1
    test_csrf_endpoints || exit 1
    test_404_handling || exit 1
    
    echo -e "\n${GREEN}=== Server health tests passed! ===${NC}"
}

main
