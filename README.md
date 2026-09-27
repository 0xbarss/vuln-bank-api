# VulnBank Core API Sandbox

VulnBank is a target banking API designed for automated security scanning, contract conformance checks, and latency profiling with API Trace.

## Features

- **OpenAPI 3.0 specification** served at `/openapi.json` and `/api-docs/openapi.json`.
- **In-memory data store** seeded with realistic users, checking accounts, transactions, and cards.
- **OWASP API Security Top 10 vulnerabilities**:
  - **BOLA / IDOR**: Account detail route (`GET /api/v1/accounts/:id`) allows any authenticated customer to read cross-tenant account records.
  - **Mass assignment / tampering**: Balance update route (`PUT /api/v1/accounts/:id/balance`) accepts arbitrary balances and limits.
  - **Sensitive data leakage**: Card query route (`GET /api/v1/cards`) returns unmasked PAN and CVV numbers.
  - **SQL injection signal**: Audit search route (`GET /api/v1/audit/search?query=...`) returns detailed database error traces when injected.
  - **Missing rate limit**: Transfer endpoint (`POST /api/v1/transfers`) allows rapid high-frequency requests.
  - **Unauthenticated information disclosure**: Cluster telemetry exposed at `GET /api/v1/system/metrics`.

## Running the Sandbox

```bash
# Install dependencies
pnpm install

# Build TypeScript
pnpm run build

# Start server on port 4000
pnpm start

# Run test suite
pnpm test
```

Default port is `4000` (override via `PORT` environment variable).
