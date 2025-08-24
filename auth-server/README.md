# Authentication Server

A robust, production-ready authentication microservice built with Clojure. This service provides secure user registration, login, token management, password reset functionality, and more.

## Features

- User registration with input validation
- Secure login with JWT tokens
- Refresh token mechanism
- Password reset functionality
- CSRF protection
- Rate limiting
- Audit logging
- Health checks
- Database and Redis integration
- CORS support
- Secure HTTP headers

## Technologies Used

- **Clojure**: Functional programming language
- **Ring/Jetty**: HTTP server
- **Reitit**: Routing library
- **Buddy**: Security library for JWT and password hashing
- **PostgreSQL**: Primary database
- **Redis**: Caching and rate limiting
- **Docker Compose**: Service orchestration

## Prerequisites

- Clojure CLI tools
- Docker and Docker Compose
- Java 11 or higher

## Getting Started

### Environment Setup

1. Copy the `.envrc` file to set up your environment variables:
   ```bash
   cp .envrc .env
   ```
2. Modify the `.env` file with your actual configuration values.

### Database Setup

Start the required services using Docker Compose:
```bash
docker-compose up -d
```

This will start:
- PostgreSQL database
- Redis server

### Running the Application

Start the authentication server:
```bash
clojure -M auth_server.clj
```

The server will be available at `http://localhost:8000` by default.

## API Endpoints

### Authentication Flow

1. **Get CSRF Token**
   ```
   GET /csrf/{action}
   ```
   Actions: `register`, `login`, `refresh`, `logout`, `forgot-password`, `reset-password`

2. **User Registration**
   ```
   POST /register
   ```
   Request body:
   ```json
   {
     "username": "string",
     "email": "string",
     "password": "string",
     "csrfToken": "string"
   }
   ```

3. **User Login**
   ```
   POST /login
   ```
   Request body:
   ```json
   {
     "username": "string",
     "password": "string",
     "csrfToken": "string"
   }
   ```
   Response:
   ```json
   {
     "token": "access_token",
     "refreshToken": "refresh_token",
     "csrfToken": "csrf_token"
   }
   ```

4. **Token Validation**
   ```
   GET /validate
   ```
   Headers:
   ```
   Authorization: Bearer {access_token}
   ```

5. **Token Refresh**
   ```
   POST /refresh
   ```
   Request body:
   ```json
   {
     "refreshToken": "string",
     "csrfToken": "string"
   }
   ```

6. **User Logout**
   ```
   POST /logout
   ```
   Headers:
   ```
   Authorization: Bearer {access_token}
   X-CSRF-Token: {csrf_token}
   ```

### Password Management

1. **Forgot Password**
   ```
   POST /forgot-password
   ```
   Request body:
   ```json
   {
     "email": "string",
     "csrfToken": "string"
   }
   ```

2. **Reset Password**
   ```
   POST /reset-password
   ```
   Request body:
   ```json
   {
     "token": "string",
     "newPassword": "string",
     "csrfToken": "string"
   }
   ```

### System

1. **Health Check**
   ```
   GET /health
   ```

## Security Features

- **JWT Tokens**: Secure authentication with HS512 algorithm
- **Password Hashing**: BCrypt+SHA512 with configurable rounds
- **CSRF Protection**: Token-based protection for state-changing operations
- **Rate Limiting**: Prevents brute force attacks
- **Input Validation**: Sanitization and validation of all user inputs
- **Audit Logging**: Records authentication events
- **Secure Headers**: HTTP security headers implementation

## Configuration

The application is configured through environment variables. Key configuration options include:

| Variable | Description | Default |
|----------|-------------|---------|
| PORT | Server port | 8000 |
| JWT_SECRET | Secret for JWT signing | Required |
| DB_USER | Database username | Required |
| DB_PASSWORD | Database password | Required |
| DB_NAME | Database name | Required |
| DB_HOST | Database host | localhost |
| REDIS_HOST | Redis host | localhost |
| BCRYPT_ROUNDS | Password hashing rounds | 12 |

See `.envrc` for a complete list of configuration options.

## Testing

The project includes comprehensive end-to-end tests in the `actions/` directory:

- `test_complete_workflow.sh`: Tests the complete user authentication flow
- `test_password_reset.sh`: Tests the password reset functionality
- `test_rate_limiting.sh`: Tests rate limiting features
- `test_server_health.sh`: Tests server health endpoints
- `test_input_validation.sh`: Tests input validation
- `test_token_validation.sh`: Tests token validation endpoint
- `test_csrf_expiration.sh`: Tests CSRF token expiration and reuse
- `test_refresh_token_edge_cases.sh`: Tests refresh token edge cases
- `test_logout_edge_cases.sh`: Tests logout edge cases
- `test_password_reset_edge_cases.sh`: Tests password reset edge cases
- `test_security_headers.sh`: Tests security and CORS headers
- `test_audit_logging.sh`: Tests audit logging functionality
- `run_all_tests.sh`: Dynamic test runner that executes all tests

To run individual tests:
```bash
cd actions
chmod +x *.sh
./test_complete_workflow.sh
```

To run all tests at once:
```bash
cd actions
chmod +x *.sh
./run_all_tests.sh
```

The `run_all_tests.sh` script automatically discovers and runs all other test scripts in the directory, making it easy to execute the entire test suite without hardcoding script names.

## Database Schema

The service automatically creates the following tables:

1. **users**: User accounts
2. **csrf_tokens**: CSRF protection tokens
3. **password_resets**: Password reset tokens
4. **audit_log**: Authentication events log

## Deployment

For production deployment:

1. Set strong environment variables
2. Use a production database
3. Configure HTTPS
4. Set appropriate logging levels
5. Monitor health endpoints

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request