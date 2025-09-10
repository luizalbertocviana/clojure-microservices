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
- **Consistency Model**:
  - Updates are **atomic per key**.
  - Each update increments a **monotonic version number** for the key.
  - Consumers achieve **eventual consistency**, with propagation delays typically under 1 second.
- **Data Model**:
  - **Key**: Unique string identifier (e.g., `app.feature-toggle.enabled`), supporting hierarchical paths (e.g., `namespace/app/key`).
  - **Value**: JSON-serializable data (string, boolean, number), max 1MB.
  - **Metadata**: Includes TTL (optional), version, ACLs (read/write lists or wildcards), and last-modified timestamp.
  - **Entities**: Identified by JWT `sub` claim (user/service ID).

## Features

### Core Functionality
- **Write Operations**:
  - `PUT` a key with value + metadata (create or replace).
  - `PATCH` value only (no metadata updates unless admin).
  - `DELETE` a key (soft-delete with version increment).
- **Read Operations**:
  - Fetch a single key’s value.
  - List keys by namespace or ACLs.
  - Subscribe to changes via WebSockets.
- **Propagation**:
  - Consumers subscribe via WebSocket (`/watch`) with one connection handling multiple keys/namespaces.
  - Client libraries update in-memory configs via callbacks.

### API Endpoints
All requests require `Authorization: Bearer <jwt>`.

| Method | Endpoint | Description | Request Body | Response |
|--------|----------|-------------|--------------|----------|
| PUT | `/keys/{key}` | Create or replace key | `{ "value": "true", "ttl": 3600, "acls": { "read": ["*"], "write": ["role:admin"] } }` | `{ "key": "app.feature-toggle.enabled", "version": 1, "lastModified": "2025-09-10T20:03:00Z" }` |
| PATCH | `/keys/{key}` | Update key value only | `{ "value": "false" }` | `{ "key": "app.feature-toggle.enabled", "version": 2, "lastModified": "2025-09-10T20:05:00Z" }` |
| GET | `/keys/{key}` | Fetch key value | None | `{ "key": "app.feature-toggle.enabled", "value": "false", "version": 2 }` |
| DELETE | `/keys/{key}` | Delete key (soft-delete) | None | 204 No Content |
| GET | `/keys` | List keys | Query: `?namespace=app&limit=100` | `{ "keys": ["app.key1", "app.key2"], "total": 2 }` |
| GET | `/watch` | Watch multiple keys/namespaces (WebSocket) | Initial message: `{ "subscribe": ["app.*", "system.logging.level"] }` | Stream of updates: `{ "event": "update", "key": "app.feature-toggle.enabled", "version": 3, "value": "true" }` |
| GET | `/health` | Check server health | None | `{ "status": "healthy" }` |

- **Error Handling**: JSON with HTTP status codes (e.g., `{ "error": "Unauthorized", "message": "Invalid JWT" }`).
- **Rate Limiting**: 1000 req/min per JWT.

## Propagation
- **Mechanism**: WebSockets with Redis pub/sub for distribution.
- **Multiplexing**: One connection can watch many keys/namespaces.
- **Fallback**: Consumers may poll with `?since_version={last_known}`.
- **Performance**: Sub-second latency expected under normal conditions.

## Security
- **Authentication**:
  - JWTs validated via a JWKS endpoint.
  - `sub` (entity ID), `scope` (e.g., `dynconfig:write`).
  - Tokens are short-lived (e.g., 1h).
- **Authorization**:
  - Per-key ACLs defined at creation:

        {
          "read": ["service:payment-api", "role:ops"],
          "write": ["role:admin"]
        }

  - Wildcards allowed (`"read": ["*"]`).
  - Namespace-level ACLs optional for inheritance.
  - `role:admin` may update metadata and override.
- **Auditing**:
  - All operations logged (who, what, when).
  - Logs persisted in PostgreSQL; optionally streamed to Kafka/ELK.
- **Protections**:
  - Values encrypted at rest (AES-256) and in transit (TLS 1.3).
  - Input validation and sanitization.
  - Secrets can have TTLs with auto-expiry and rotation.
  - Monitoring with Prometheus metrics and anomaly alerts.

## TTL & Expiry
- Expired keys are marked as deleted and removed from queries.
- Consumers watching an expired key receive an `expired` event:

      {
        "event": "expired",
        "key": "app.session.token",
        "version": 5
      }

- Stale values are not returned via GET once expired.

## Failure Handling
- **Redis outage**: Updates queue in Postgres; propagation continues once Redis recovers.
- **Consumer disconnect**: Clients may reconnect with `?since_version` to catch up.
- **Service crash**: State is recoverable from Postgres.

## Implementation
DynConfig is implemented in **Clojure**, leveraging immutability and concurrency primitives, with **PostgreSQL** for persistence and **Redis** for caching and event propagation.

### Tech Stack
- **API Server**: Clojure with Ring + Compojure.
- **WebSockets**: `http-kit` for async, multiplexed connections.
- **Storage**: PostgreSQL (`configs` table with JSONB + versioning).
- **Cache/Events**: Redis pub/sub.
- **Auth**: `buddy-auth` for JWT validation.
- **Deployment**: Dockerized, fronted by NGINX for TLS and load balancing.

### Key Dependencies
- `ring` — HTTP server.
- `compojure` — routing.
- `http-kit` — WebSockets.
- `honey.sql` — SQL builder for Postgres.
- `clj-redis` — Redis client.
- `buddy-auth` — JWT handling.

### Deployment Notes
- Validate JWTs against a JWKS endpoint.
- Configure PostgreSQL for durability and Redis for event distribution.
- Deploy in Docker/Kubernetes with NGINX for TLS and throttling.
- Export Prometheus metrics (latency, error rates, connection counts).
- Audit logs replicated to a secure system.

## Contributing
Feedback and contributions are welcome! Please submit issues or PRs to refine the API, security model, or propagation logic.

## License
MIT
