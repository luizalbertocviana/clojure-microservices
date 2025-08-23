# Unit Test Coverage Plan for Authentication Server

## Overview

This document outlines a plan for implementing comprehensive unit test coverage for the Clojure authentication server. The server is a microservice that provides authentication functionality including user registration, login, token management, password reset, and security features.

## Current State

The project currently has:
- No unit tests in Clojure (only end-to-end shell scripts in the `actions/` directory)
- A single source file `auth_server.clj` containing all functionality
- Dependencies on PostgreSQL, Redis, and several Clojure libraries

## Test Framework Selection

For Clojure unit testing, we'll use:
- **clojure.test** - The standard testing framework included with Clojure
- **test.check** - For property-based testing of validation functions

These are lightweight and well-integrated with Clojure's tooling.

## Test Organization

We'll organize tests to mirror the structure of the main source file:
```
test/
├── auth_server_test.clj          # Main test file
├── utils/                        
│   ├── validation_test.clj       # Input validation tests
│   ├── security_test.clj         # Security-related function tests
│   └── token_test.clj            # JWT and CSRF token tests
├── middleware/
│   ├── auth_test.clj             # Authentication middleware tests
│   ├── rate_limit_test.clj       # Rate limiting middleware tests
│   └── security_headers_test.clj # Security headers middleware tests
├── handlers/
│   ├── auth_handler_test.clj     # Authentication handlers tests
│   ├── csrf_handler_test.clj     # CSRF handler tests
│   └── health_handler_test.clj   # Health check handler tests
└── integration/
    ├── db_test.clj               # Database interaction tests
    └── redis_test.clj            # Redis interaction tests
```

## Test Categories

### 1. Utility Functions

Test all pure functions that don't require external dependencies:

#### Validation Functions
- `valid-username?` - Test valid and invalid usernames
- `valid-email?` - Test valid and invalid email addresses
- `valid-password?` - Test password strength validation
- `sanitize` - Test HTML escaping

#### Token Functions
- `sign-token`/`unsign-token` - Test JWT signing and verification
- `generate-csrf`/`validate-csrf` - Test CSRF token generation and validation

#### Store Functions
- `my-incr`, `my-get`, `my-set-ex` - Test both Redis and in-memory implementations

### 2. Middleware

Test each middleware function in isolation:

- Rate limiting middleware
- Authentication middleware
- Security headers middleware
- Logger middleware
- CORS middleware

### 3. Handlers

Test each HTTP handler function:

- Registration handler
- Login handler
- Refresh handler
- Logout handler
- Forgot password handler
- Reset password handler
- CSRF handler
- Health handler

### 4. Integration Tests

Test components that interact with external systems:

- Database functions (with test database)
- Redis functions (with test Redis instance)
- Audit logging

### 5. System Tests

Test complete workflows:

- User registration to login flow
- Token refresh and validation
- Password reset workflow
- Logout and token invalidation

## Implementation Strategy

### Phase 1: Foundation
1. Add test dependencies to `deps.edn`
2. Create basic test directory structure
3. Implement tests for utility functions (pure functions)
4. Set up test database and Redis instances for integration tests

### Phase 2: Core Functionality
1. Test middleware components
2. Test individual handlers
3. Implement integration tests for database and Redis interactions

### Phase 3: System Tests
1. Create comprehensive tests for complete workflows
2. Add property-based tests for validation functions
3. Implement negative test cases (error conditions)

### Phase 4: Coverage and Refinement
1. Measure code coverage
2. Add missing tests for edge cases
3. Refactor tests for maintainability
4. Add performance tests for rate limiting

## Mocking Strategy

To isolate units under test:

1. **Database mocking**: Use in-memory H2 database or mock jdbc calls
2. **Redis mocking**: Use test.check for property-based testing of store functions
3. **Time-dependent functions**: Mock `System/currentTimeMillis` where needed
4. **External services**: Mock JWT signing/verification for focused unit tests

## Test Data Management

1. Use generative testing for creating test data
2. Clean up test data after each test
3. Use fixtures for setting up common test scenarios
4. Separate test data from production data

## Continuous Integration

1. Add test execution to CI pipeline
2. Set up code coverage reporting
3. Configure test database in CI environment
4. Run both unit and integration tests

## Dependencies to Add

```clojure
{:paths ["."]
 :deps {org.clojure/clojure {:mvn/version "1.12.1"}
        ;; ... existing deps ...
        }
 :aliases {:test {:extra-paths ["test"]
                  :extra-deps {org.clojure/test.check {:mvn/version "1.1.1"}
                               io.github.cognitect-labs/test-runner {:git/tag "v0.5.1" :git/sha "dfb30dd"}}
                  :main-opts ["-m" "cognitect.test-runner"]
                  :exec-fn cognitect.test-runner.api/test}}}
```

## Quality Goals

1. **Code Coverage**: Aim for >85% code coverage
2. **Performance**: Tests should run quickly (< 10 seconds for unit tests)
3. **Reliability**: Tests should be deterministic and not depend on external state
4. **Maintainability**: Tests should be easy to understand and modify
5. **Documentation**: Tests should serve as documentation for the code's behavior

## Next Steps

1. ~~Create the test directory structure~~ (Completed)
2. ~~Add test dependencies to project configuration~~ (Completed)
3. ~~Begin implementing tests for utility functions~~ (Completed)
4. Implement tests for middleware components
5. Set up CI configuration for automated testing