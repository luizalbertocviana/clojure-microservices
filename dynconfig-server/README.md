# DynConfig Server

DynConfig is a centralized, secure configuration management system designed as a key-value store that supports real-time configuration updates and propagation to consuming services without requiring restarts. It uses a RESTful HTTP API with WebSocket-based change notifications and enforces strict access control using JSON Web Tokens (JWTs).

## Overview

DynConfig enables:
- **Dynamic Updates**: Producers (e.g., admin services) register or update key-value pairs via HTTP.
- **Real-Time Propagation**: Consumers (e.g., application services) receive updates via WebSockets, updating in-memory configurations without restarts.
- **Security**: Per-key access control lists (ACLs) restrict read/write access to authorized entities, authenticated via JWTs.
- **Scalability and Reliability**: Built with Clojure, PostgreSQL for persistent storage, and Redis for caching and event propagation.

### Key Principles
- **Immutability of Metadata**: Key metadata (e.g., ACLs) is immutable after creation unless updated by admins.
- **Eventual Consistency**: Updates are atomic per key, with propagation delays typically under 1 second.
- **Data Model**:
  - **Key**: Unique string identifier (e.g., `app.feature-toggle.enabled`), supporting hierarchical paths (e.g., `namespace/app/key`).
  - **Value**: JSON-serializable data (e.g., string, boolean, number), max 1MB.
  - **Metadata**: Includes TTL (optional), version (for concurrency), ACLs (read/write lists), and last-modified timestamp.
  - **Entities**: Identified by JWT `sub` claim (user/service ID).

## Features

### Core Functionality
- **Write Operations**:
  - Register new keys with values and ACLs.
  - Update key values (metadata updates restricted to admins).
  - Delete keys (soft-delete with versioning).
- **Read Operations**:
  - Fetch a single key’s value.
  - List keys by namespace or permissions.
  - Subscribe to key changes via WebSockets.
- **Propagation**:
  - Consumers use WebSockets (`/keys/{key}/watch`) for real-time updates.
  - Client libraries handle in-memory updates via callbacks.

### API Endpoints
Served at `https://dynconfig.example.com/api/v1`. All requests require `Authorization: Bearer <jwt>`.

| Method | Endpoint | Description | Request Body | Response |
|--------|----------|-------------|--------------|----------|
| POST | `/keys/{key}` | Register a key | `{ "value": "true", "ttl": 3600, "acls": { "read": ["serviceA"], "write": ["admin"] } }` | `{ "key": "app.feature-toggle.enabled", "version": 1, "lastModified": "2025-09-10T20:03:00-03:00" }` |
| PUT | `/keys/{key}` | Update key value | `{ "value": "false" }` | `{ "key": "app.feature-toggle.enabled", "version": 2, "lastModified": "2025-09-10T20:03:00-03:00" }` |
| GET | `/keys/{key}` | Fetch key value | None | `{ "key": "app.feature-toggle.enabled", "value": "true", "version": 2 }` |
| DELETE | `/keys/{key}` | Delete key | None | 204 No Content |
| GET | `/keys` | List keys | Query: `?namespace=app&limit=100` | `{ "keys": ["app.key1", "app.key2"], "total": 2 }` |
| GET | `/keys/{key}/watch` | Watch key (WebSocket) | None | Stream: `{ "event": "update", "key": "app.feature-toggle.enabled", "version": 3, "value": "false" }` |
| GET | `/health` | Check server health | None | `{ "status": "healthy" }` |

- **Error Handling**: HTTP codes with JSON bodies (e.g., `{ "error": "Unauthorized", "message": "Invalid JWT" }`).
- **Rate Limiting**: 1000 req/min per JWT.

## Propagation
- **Mechanism**: WebSockets for real-time updates.
  - Consumers connect to `/keys/{key}/watch` to receive updates (e.g., `{ "event": "update", "key": "app.feature-toggle.enabled", "value": "false" }`).
  - Client libraries handle WebSocket connections and trigger callbacks to update in-memory configs.
- **Fallback**: Consumers can poll `/keys/{key}?since_version={last_known}` (e.g., every 30s) if WebSockets are unavailable.
- **Performance**: Sub-second latency for updates; Redis pub/sub ensures scalability.

## Security
- **Authentication**:
  - JWTs with `sub` (user/service ID) and `scope` (e.g., `dynconfig:write`) claims, validated via a JWKS endpoint.
  - Short-lived tokens (e.g., 1h) with refresh via OAuth.
- **Authorization**:
  - **Per-Key ACLs**: Defined at creation (e.g., `{ "read": ["service:payment-api"], "write": ["role:admin"] }`).
    - Read: Only listed entities can GET/watch.
    - Write: Only listed entities can POST/PUT/DELETE.
    - Namespace-level ACLs (optional) for inherited permissions.
  - **Admin Role**: `role:admin` in JWT allows metadata updates and overrides.
  - **Auditing**: All operations logged (who, what, when) to a secure store (e.g., PostgreSQL audit table).
- **Protections**:
  - **Encryption**: Values encrypted at rest (AES-256) and in transit (TLS 1.3).
  - **Validation**: Keys/values sanitized to prevent injection.
  - **Secrets**: Sensitive values support TTL and auto-rotation.
  - **Monitoring**: Rate limiting, IP whitelisting, anomaly detection (e.g., alert on excessive reads).

## Implementation
DynConfig is implemented in **Clojure** for functional programming benefits, leveraging immutability and concurrency primitives, with **PostgreSQL** for persistent storage and **Redis** for caching and event propagation.

### Tech Stack
- **API Server**: Clojure with Ring and Compojure for HTTP and WebSocket handling.
- **Storage**:
  - PostgreSQL: Stores keys, values (JSONB), metadata, and versions.
  - Schema: Table `configs` (`key TEXT PRIMARY KEY`, `value JSONB`, `metadata JSONB`, `version INT`, `created_by TEXT`, `last_modified TIMESTAMP`).
- **Propagation**: Redis pub/sub for event distribution; WebSocket connections for consumer updates.
- **Auth**: JWT validation via JWKS endpoint using `buddy-auth` library.
- **Deployment**: Dockerized, deployed with NGINX for TLS and load balancing.

### Key Dependencies
- `ring`: HTTP server interface.
- `compojure`: Routing for API endpoints.
- `http-kit`: WebSocket support for real-time updates.
- `honey.sql`: SQL query generation for PostgreSQL.
- `clj-redis`: Redis client for caching and pub/sub.
- `buddy-auth`: JWT validation and security.

### Deployment Notes
- Use a JWKS endpoint for JWT validation.
- Configure PostgreSQL and Redis for persistence and event handling.
- Deploy via Docker with NGINX for TLS and rate limiting.
- Monitor metrics (e.g., update latency, WebSocket connections) and audit logs.

## Contributing
Feedback on the specification or implementation is welcome. Submit issues or pull requests to refine the API, security, or propagation logic.

## License
MIT
