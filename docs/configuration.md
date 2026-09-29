# Configuration

The API is configured entirely through environment variables. Locally, copy
`.env.example` to `.env`; in deployed environments, inject the variables
through your platform's secret manager.

## Startup validation

Every variable below is validated against a single schema
(`environmentSchema` in `src/config/env.validation.ts`) at the very start of
`bootstrap()` in `src/main.ts`, before any Nest module is constructed or any
database, Redis or queue connection is opened.

If validation fails, the process prints every failing variable at once and
exits with code `1`:

```text
Invalid environment configuration (3 problems):
  - DATABASE_URL: is required but was not set
  - PORT: must be a valid number
  - NODE_ENV: must be one of: development, test, production
Fix the variables above (see .env.example and docs/configuration.md) and restart.
```

The message never includes the rejected values, so secrets cannot leak into
logs through a misconfiguration.

Each configuration slice (`src/config/*.config.ts`) still validates its own
subset when Nest loads it, so the typed `ConfigService` namespaces keep their
guarantees in tests and tools that construct modules without going through
`main.ts`.

### Adding a variable

1. Add it to the relevant slice schema in `src/config/env.validation.ts`. The
   slice schemas are merged into `environmentSchema`, so it is validated at
   startup automatically.
2. Document it in the tables below. A unit test fails if a validated variable
   is missing from this file.
3. Add it to `.env.example` if developers need to set it locally. A unit test
   checks that `.env.example` itself passes validation.

## Required variables

These have no default. The application will not start without them.

| Variable | Description |
| --- | --- |
| `DATABASE_URL` | PostgreSQL connection string used by Prisma. |
| `JWT_ACCESS_SECRET` | Signing secret for access tokens. At least 16 characters. |
| `JWT_REFRESH_SECRET` | Signing secret for refresh tokens. At least 16 characters. In production it must differ from `JWT_ACCESS_SECRET`. |
| `AI_PROVIDER_KEY` | API key for the AI provider. |

### Additional production requirements

When `NODE_ENV=production`, values that are acceptable for local development
are rejected:

| Variable | Rule |
| --- | --- |
| `ENCRYPTION_KEY` | Must be set explicitly. The built-in development default is publicly known and is rejected. |
| `JWT_REFRESH_SECRET` | Must differ from `JWT_ACCESS_SECRET`. |

## Optional variables

### Application

| Variable | Default | Description |
| --- | --- | --- |
| `NODE_ENV` | `development` | One of `development`, `test`, `production`. |
| `APP_NAME` | `astroid-api` | Service name. |
| `PORT` | `3000` | HTTP port. Positive integer. |
| `API_PREFIX` | `api/v1` | Global route prefix. |
| `LOG_LEVEL` | `info` | One of `fatal`, `error`, `warn`, `info`, `debug`, `trace`, `silent`. |
| `CORS_ORIGINS` | `*` | Comma-separated list of allowed origins. |

### Database

| Variable | Default | Description |
| --- | --- | --- |
| `DATABASE_CONNECTION_LIMIT` | `10` | Prisma `connection_limit` for the API pool. |
| `DATABASE_WORKER_CONNECTION_LIMIT` | `3` | Connection limit for the background worker pool. |
| `DATABASE_POOL_TIMEOUT_MS` | `5000` | Time to wait for a free connection. `0` waits indefinitely. |
| `DATABASE_QUERY_TIMEOUT_MS` | `5000` | Client-side query timeout for the API pool. `0` disables it. |
| `DATABASE_STATEMENT_TIMEOUT_MS` | `10000` | Server-side `statement_timeout`. `0` disables it. |
| `DATABASE_WORKER_QUERY_TIMEOUT_MS` | `60000` | Client-side query timeout for the worker pool. `0` disables it. |
| `DATABASE_SLOW_QUERY_THRESHOLD_MS` | `1000` | Queries slower than this are logged as slow queries. |
| `DATABASE_CONNECT_RETRY_ATTEMPTS` | `5` | Connection attempts before giving up on startup. |
| `DATABASE_CONNECT_RETRY_DELAY_MS` | `1000` | Delay between connection retry attempts. |

### Redis

| Variable | Default | Description |
| --- | --- | --- |
| `REDIS_HOST` | `localhost` | Redis host. |
| `REDIS_PORT` | `6379` | Redis port. Positive integer. |
| `REDIS_PASSWORD` | _(empty)_ | Redis password. |
| `REDIS_DB` | `0` | Redis database index. |

### Authentication

| Variable | Default | Description |
| --- | --- | --- |
| `JWT_ACCESS_TTL` | `900` | Access-token lifetime in seconds. |
| `JWT_REFRESH_TTL` | `1209600` | Refresh-token lifetime in seconds. |
| `PASSKEY_RP_ID` | `localhost` | WebAuthn relying-party ID. |
| `PASSKEY_RP_NAME` | `Astroid` | WebAuthn relying-party display name. |
| `PASSKEY_ORIGIN` | `http://localhost:3001` | Expected WebAuthn origin. |

### Stellar

| Variable | Default | Description |
| --- | --- | --- |
| `STELLAR_NETWORK` | `testnet` | One of `testnet`, `public`, `futurenet`. |
| `STELLAR_HORIZON_URL` | `https://horizon-testnet.stellar.org` | Horizon endpoint. |
| `STELLAR_SOROBAN_RPC_URL` | `https://soroban-testnet.stellar.org` | Soroban RPC endpoint. |
| `STELLAR_REGISTRY_CONTRACT_ID` | _(empty)_ | Agent registry contract ID. |
| `STELLAR_USE_MOCK` | `true` | `true` or `false`. Use the mock Stellar client. |

### Storage (S3-compatible)

| Variable | Default | Description |
| --- | --- | --- |
| `STORAGE_ENDPOINT` | `http://localhost:9000` | Object storage endpoint. |
| `STORAGE_REGION` | `us-east-1` | Storage region. |
| `STORAGE_BUCKET` | `astroid` | Bucket name. |
| `STORAGE_ACCESS_KEY` | `astroid` | Access key. |
| `STORAGE_SECRET_KEY` | `astroid-secret` | Secret key. |

### Queues (BullMQ)

| Variable | Default | Description |
| --- | --- | --- |
| `QUEUE_PREFIX` | `astroid` | Key prefix for BullMQ queues. |
| `QUEUE_CONCURRENCY` | `5` | Default worker concurrency. |

### Rate limiting

| Variable | Default | Description |
| --- | --- | --- |
| `THROTTLE_AUTH_LIMIT` | `10` | Requests per window on the `auth` tier. |
| `THROTTLE_API_LIMIT` | `120` | Requests per window on the `api` tier. |
| `THROTTLE_TTL` | `60` | Throttler window in seconds. |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Sliding-window size for the Redis rate-limiter guard. |
| `RATE_LIMIT_MAX_REQUESTS` | `120` | Requests allowed per client per sliding window. |
| `PUBLIC_RATE_LIMIT_ENABLED` | `true` | Enables the IP-based limiter for unauthenticated (`@Public()`) routes. |
| `PUBLIC_RATE_LIMIT_MAX_REQUESTS` | `60` | Requests allowed per client per sliding window on public routes. Per-route overrides use the `@PublicRateLimit(max, windowSeconds)` decorator. |
| `PUBLIC_RATE_LIMIT_WINDOW_SECONDS` | `60` | Sliding-window size for the public-route rate limiter. |
| `PUBLIC_RATE_LIMIT_TRUST_PROXY` | `false` | Reads client IP from `X-Forwarded-For`. Only enable behind a trusted reverse proxy. |
| `PUBLIC_RATE_LIMIT_CLIENT_IDENTIFIERS` | _(empty)_ | Comma-separated extra client identifiers folded into the public rate-limit bucket. `apiKey` tracks holders of an `x-api-key` (or `ApiKey`/`Bearer ak_…` Authorization header) separately from their shared IP. Optional and unvalidated (read via `process.env`). |

### Metrics

| Variable | Default | Description |
| --- | --- | --- |
| `METRICS_ALLOWED_IPS` | loopback and RFC 1918 ranges | Comma-separated CIDR ranges allowed to scrape `GET /metrics`. |

### AI provider

| Variable | Default | Description |
| --- | --- | --- |
| `AI_PROVIDER` | `nvidia` | Provider name. |
| `AI_BASE_URL` | `https://integrate.api.nvidia.com/v1` | Provider API base URL. |
| `AI_MODEL` | `meta/llama-3.1-70b-instruct` | Model identifier. |

### Encryption

| Variable | Default | Description |
| --- | --- | --- |
| `ENCRYPTION_KEY` | development-only key | 32-byte key: 64 hex characters, 32 raw bytes, or base64 of 32 bytes. Required in production. |
| `ENCRYPTION_ALGORITHM` | `aes-256-gcm` | Cipher algorithm. |
