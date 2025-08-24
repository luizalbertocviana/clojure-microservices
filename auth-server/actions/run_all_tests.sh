#!/bin/sh

# Dynamic test runner that executes all other test scripts in this directory
# This script automatically discovers and runs all *.sh files except itself

set -e

echo "=== Authentication Server - Dynamic Test Runner ==="

# Configuration
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER_URL="http://localhost:8000"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Arrays to track failed tests
FAILED_TESTS=()

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

# Function to check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"
    
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
    
    print_success "All prerequisites met"
}

# Function to discover and prioritize test scripts
discover_test_scripts() {
    print_header "Discovering Test Scripts"
    
    # Find all .sh files in the current directory, excluding this script
    ALL_SCRIPTS=$(find "$SCRIPT_DIR" -maxdepth 1 -name "*.sh" ! -name "$(basename "$0")")
    
    if [ -z "$ALL_SCRIPTS" ]; then
        print_error "No test scripts found"
        exit 1
    fi
    
    # Prioritize scripts to avoid timing issues:
    # 1. Health check first (should not be rate limited)
    # 2. Core functionality tests
    # 3. Edge case tests
    # 4. Rate limiting test last (it generates rate limit entries)
    
    HEALTH_SCRIPT=$(echo "$ALL_SCRIPTS" | grep "test_server_health.sh" | head -1)
    RATE_LIMIT_SCRIPT=$(echo "$ALL_SCRIPTS" | grep "test_rate_limiting.sh" | head -1)
    
    # Get all other scripts
    OTHER_SCRIPTS=$(echo "$ALL_SCRIPTS" | grep -v "test_server_health.sh" | grep -v "test_rate_limiting.sh")
    
    # Build ordered list: health first, rate limiting last, others in middle
    TEST_SCRIPTS=""
    
    if [ -n "$HEALTH_SCRIPT" ]; then
        TEST_SCRIPTS="$HEALTH_SCRIPT"
    fi
    
    if [ -n "$OTHER_SCRIPTS" ]; then
        if [ -n "$TEST_SCRIPTS" ]; then
            TEST_SCRIPTS="$TEST_SCRIPTS"$'\n'"$OTHER_SCRIPTS"
        else
            TEST_SCRIPTS="$OTHER_SCRIPTS"
        fi
    fi
    
    if [ -n "$RATE_LIMIT_SCRIPT" ]; then
        if [ -n "$TEST_SCRIPTS" ]; then
            TEST_SCRIPTS="$TEST_SCRIPTS"$'\n'"$RATE_LIMIT_SCRIPT"
        else
            TEST_SCRIPTS="$RATE_LIMIT_SCRIPT"
        fi
    fi
    
    # Remove any empty lines
    TEST_SCRIPTS=$(echo "$TEST_SCRIPTS" | sed '/^\s*$/d')
    
    echo "Found $(echo "$ALL_SCRIPTS" | wc -l) test scripts (ordered execution):"
    echo "$TEST_SCRIPTS" | nl -v1 -s". " | while read -r line; do
        echo "  $line"
    done
    
    print_success "Test script discovery complete"
}

# Function to run a single test script
run_test_script() {
    local script_path="$1"
    local script_name=$(basename "$script_path")
    
    print_header "Running $script_name"
    
    # Execute the script and capture output
    if "$script_path"; then
        print_success "$script_name completed successfully"
        return 0
    else
        print_error "$script_name failed"
        FAILED_TESTS+=("$script_name")
        return 1
    fi
}

# Function to run all test scripts
run_all_tests() {
    print_header "Running All Tests"
    
    local failed_count=0
    local total_count=0
    
    # Save TEST_SCRIPTS to a temporary file to work around variable scope issues
    echo "$TEST_SCRIPTS" > /tmp/test_scripts_$$.txt
    
    # Run each test script in order
    while read -r script; do
        if [ -n "$script" ]; then
            total_count=$((total_count + 1))
            if ! run_test_script "$script"; then
                failed_count=$((failed_count + 1))
            fi
            
            # Add a small delay after rate limiting test to allow rate limit windows to expire
            script_name=$(basename "$script")
            if [ "$script_name" = "test_rate_limiting.sh" ] && [ -n "$script" ]; then
                print_info "Adding delay after rate limiting test to allow rate limit windows to expire..."
                sleep 2
            fi
        fi
    done < /tmp/test_scripts_$$.txt
    
    # Clean up temporary file
    rm -f /tmp/test_scripts_$$.txt
    
    # Print summary
    echo
    print_header "Test Execution Summary"
    
    if [ "$failed_count" -eq 0 ]; then
        print_success "All $total_count tests passed!"
        return 0
    else
        print_error "$failed_count out of $total_count tests failed"
        return 1
    fi
}

# Function to list failing tests
list_failing_tests() {
    if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
        echo
        print_header "Failing Tests"
        for test in "${FAILED_TESTS[@]}"; do
            print_error "$test"
        done
    fi
}

# Function to print usage
print_usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -l, --list     List all discovered test scripts without running them"
    echo
    echo "This script automatically discovers and runs all test scripts in the"
    echo "current directory, except for itself."
}

# Main execution
main() {
    # Parse command line arguments
    case "$1" in
        -h|--help)
            print_usage
            exit 0
            ;;
        -l|--list)
            # Find all .sh files in the current directory, excluding this script
            TEST_SCRIPTS=$(find "$SCRIPT_DIR" -maxdepth 1 -name "*.sh" ! -name "$(basename "$0")" | sort)
            
            if [ -z "$TEST_SCRIPTS" ]; then
                print_error "No test scripts found"
                exit 1
            fi
            
            echo "Found $(echo "$TEST_SCRIPTS" | wc -l) test scripts:"
            echo "$TEST_SCRIPTS" | while read -r script; do
                echo "  - $(basename "$script")"
            done
            exit 0
            ;;
        "")
            # No arguments - run all tests
            ;;
        *)
            print_error "Unknown argument: $1"
            print_usage
            exit 1
            ;;
    esac
    
    # Check prerequisites
    check_prerequisites
    
    # Discover test scripts
    discover_test_scripts
    
    # Run all tests
    if run_all_tests; then
        echo -e "\n${GREEN}=== All tests completed successfully! ===${NC}"
        exit 0
    else
        echo -e "\n${RED}=== Some tests failed! ===${NC}"
        list_failing_tests
        exit 1
    fi
}

# Run main function
main "$@"