# Authentication Server - End-to-End Tests

This directory contains shell scripts for testing the authentication server's functionality through end-to-end tests.

## Test Scripts

1. **test_complete_workflow.sh** - Tests the complete user workflow:
   - User registration
   - User login
   - Token validation
   - Token refresh
   - User logout
   - Token invalidation

2. **test_password_reset.sh** - Tests the password reset functionality:
   - User registration
   - Password reset request
   - Password reset
   - Login with new password
   - Verification that old password no longer works

3. **test_rate_limiting.sh** - Tests rate limiting features:
   - Login rate limiting
   - General API rate limiting

4. **test_server_health.sh** - Tests server health and status endpoints:
   - Health endpoint
   - CSRF token generation
   - 404 handling

5. **test_input_validation.sh** - Tests input validation:
   - Invalid registration inputs
   - Valid registration
   - Duplicate registration prevention

## Dynamic Test Runner

**run_all_tests.sh** - A dynamic test runner that automatically discovers and executes all test scripts in this directory:

```bash
./run_all_tests.sh          # Run all tests
./run_all_tests.sh --list   # List all discovered test scripts
./run_all_tests.sh --help   # Show help message
```

This script excludes itself when discovering test scripts, so you can add or remove test scripts without needing to update the runner.

## Prerequisites

- `curl` must be installed
- `jq` must be installed
- The authentication server must be running

## Running the Tests

Make sure the scripts are executable:

```bash
chmod +x *.sh
```

Then run any script:

```bash
./test_complete_workflow.sh
./test_password_reset.sh
./test_rate_limiting.sh
./test_server_health.sh
./test_input_validation.sh
```

Or run all tests at once:

```bash
./run_all_tests.sh
```

## Environment

The tests assume the server is running at `http://localhost:8000`. If your server is running on a different port or host, you'll need to modify the `SERVER_URL` variable in each script.

## Test Data

The tests create temporary users with unique names (using timestamps) to avoid conflicts. These users remain in the database after the tests complete.