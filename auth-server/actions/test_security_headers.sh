#!/bin/sh

# Test script for security headers

set -e

echo "=== Security Headers Test ==="

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

# Function to test security headers on health endpoint
test_security_headers() {
    print_header "Testing Security Headers"
    
    response_headers=$(curl -s -D - -o /dev/null "$SERVER_URL/health")
    
    # Check for Strict-Transport-Security
    if echo "$response_headers" | grep -q "Strict-Transport-Security: max-age=31536000; includeSubDomains"; then
        print_success "Strict-Transport-Security header present"
    else
        print_error "Missing Strict-Transport-Security header"
        return 1
    fi
    
    # Check for Content-Security-Policy
    if echo "$response_headers" | grep -q "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'"; then
        print_success "Content-Security-Policy header present"
    else
        print_error "Missing Content-Security-Policy header"
        return 1
    fi
    
    # Check for X-Content-Type-Options
    if echo "$response_headers" | grep -q "X-Content-Type-Options: nosniff"; then
        print_success "X-Content-Type-Options header present"
    else
        print_error "Missing X-Content-Type-Options header"
        return 1
    fi
    
    # Check for X-Frame-Options
    if echo "$response_headers" | grep -q "X-Frame-Options: DENY"; then
        print_success "X-Frame-Options header present"
    else
        print_error "Missing X-Frame-Options header"
        return 1
    fi
    
    return 0
}

# Function to test CORS headers
test_cors_headers() {
    print_header "Testing CORS Headers"
    
    response_headers=$(curl -s -D - -o /dev/null -H "Origin: http://localhost:3000" \
        -H "Access-Control-Request-Method: GET" \
        -H "Access-Control-Request-Headers: X-Requested-With" \
        -X OPTIONS "$SERVER_URL/health")
    
    # Check for Access-Control-Allow-Origin
    if echo "$response_headers" | grep -q "Access-Control-Allow-Origin: http://localhost:3000"; then
        print_success "Access-Control-Allow-Origin header present"
    else
        print_error "Missing or incorrect Access-Control-Allow-Origin header"
        return 1
    fi
    
    # Check for Access-Control-Allow-Methods
    if echo "$response_headers" | grep -q "Access-Control-Allow-Methods: GET,POST,OPTIONS"; then
        print_success "Access-Control-Allow-Methods header present"
    else
        print_error "Missing or incorrect Access-Control-Allow-Methods header"
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
    
    if ! command -v grep &> /dev/null; then
        print_error "grep is required but not installed"
        exit 1
    fi
    
    # Run tests
    test_security_headers || exit 1
    test_cors_headers || exit 1
    
    echo -e "\n${GREEN}=== Security headers tests passed! ===${NC}"
}

main