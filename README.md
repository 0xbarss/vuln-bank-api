# VulnBank Core API Sandbox

[![Node.js](https://img.shields.io/badge/node.js-v22%2B-brightgreen.svg)](https://nodejs.org)
[![Database](https://img.shields.io/badge/database-node%3Asqlite-blue.svg)](https://nodejs.org/api/sqlite.html)
[![Auth](https://img.shields.io/badge/auth-HMAC--SHA256%20JWT%20%2B%20scrypt-blueviolet.svg)](https://nodejs.org/api/crypto.html)
[![Tests](https://img.shields.io/badge/tests-vitest-orange.svg)](https://vitest.dev)
[![OpenAPI](https://img.shields.io/badge/spec-OpenAPI%203.0-green.svg)](/openapi.json)

**VulnBank** is a high-fidelity vulnerable banking API designed specifically as an automated security scanning, performance profiling, and contract validation sandbox for [**API Trace**](https://github.com/0xbarss/api-trace).

It models a realistic multi-tenant banking platform backed by a real relational **SQLite** database (`node:sqlite`) and cryptographic authentication (`node:crypto`), embedding intentional **OWASP API Security Top 10 (2023)** vulnerabilities, contract drift points, and latency anomalies.

---

## 1. Architectural Highlights

- **Zero External Database Drivers**: Utilizes Node.js built-in `node:sqlite` (`DatabaseSync`) for ACID transactions, foreign keys (`ON DELETE CASCADE`), indexes, and authentic SQL execution.
- **Native Cryptographic Security**:
  - **Password Hashing**: Salted `scryptSync` with unique 16-byte random salts and constant-time verification (`timingSafeEqual`).
  - **JSON Web Tokens (JWT)**: Compact RFC 7519 HMAC-SHA256 signed tokens (`header.payload.signature`) with expiry enforcement.
- **OpenAPI 3.0 Conformance**: Full machine-readable specification served at `/openapi.json` and `/api-docs/openapi.json`.
- **Dual-Mode Persistence**: Configurable database file (`data/vuln-bank.sqlite`) or fast `:memory:` execution for automated testing.

---

## 2. Quickstart

### Prerequisites
- Node.js `v22.0.0` or higher (tested on Node `v26.8.2`)
- pnpm `v9+` or npm / yarn

### Installation & Execution

```bash
# 1. Install dependencies
pnpm install

# 2. Build TypeScript distribution
pnpm run build

# 3. Seed SQLite database with initial banking records
pnpm run seed

# 4. Start the server (default port: 4000)
pnpm start

# 5. Execute internal test suite (13 passing tests)
pnpm test
```

To run in development mode with hot-reloading:
```bash
pnpm run dev
```

---

## 3. Seed Dataset & Seed Files

VulnBank includes reproducible seed datasets containing realistic banking customers, enterprise entities, checking/savings accounts, cards, wire transfers, and audit logs.

### Seed Execution Options
- **CLI TypeScript Runner**: `pnpm run seed:ts` (direct via `tsx`)
- **CLI Production Runner**: `pnpm run seed` (via compiled `dist/seed.js`)
- **Pure SQL Seed File**: [`sql/seed.sql`](file:///mnt/data6/MyFiles/Projects/vuln-bank-api/sql/seed.sql) (executable directly via `sqlite3 data/vuln-bank.sqlite < sql/seed.sql`)

### Seeded Credentials & Personas

| Username | Plaintext Password | Role | Primary Account ID | Pre-Seeded Token |
| :--- | :--- | :--- | :--- | :--- |
| `alice` | `password123` | `customer` | `acc-alice-chk` | `vbnk_token_alice_sec_9941` |
| `bob` | `securePass789` | `customer` | `acc-bob-chk` | `vbnk_token_bob_sec_5512` |
| `charlie` | `CharlieVance!2026` | `customer` | `acc-charlie-chk` | `vbnk_token_charlie_sec_3389` |
| `diana` | `EnterpriseCapital#99` | `customer` | `acc-diana-biz` | `vbnk_token_diana_corp_7721` |
| `admin` | `AdminSecret2026!` | `admin` | N/A | `vbnk_token_admin_super_9999` |
| `auditor` | `AuditReadonly2026!` | `admin` | N/A | `vbnk_token_auditor_view_8842` |

> [!NOTE]
> All passwords are cryptographically hashed upon seeding using salted `scryptSync(plain, salt, 64)`. Authentication accepts newly issued signed JWTs from `POST /api/v1/auth/login` as well as pre-seeded tokens.

---

## 4. Vulnerability Catalog for API Trace Detection

The following intentional security flaws, error signals, and performance anomalies are built into the API to evaluate automated detection engines in **API Trace**:

| Vulnerability / Flaw | OWASP Category | Target Route | Detection Engine in API Trace |
| :--- | :--- | :--- | :--- |
| **BOLA / IDOR** | `API1:2023` | `GET /api/v1/accounts/:id` | Security Engine (Dual-Tenant Probe) |
| **Broken Authentication** | `API2:2023` | `POST /api/v1/auth/login`, all auth routes | Security Engine (Token Tampering & Forgery) |
| **Mass Assignment** | `API3:2023` | `PUT /api/v1/accounts/:id/balance` | Security Engine (Field Mutation Probe) |
| **Missing Rate Limiting** | `API4:2023` | `POST /api/v1/transfers` | Performance Engine (High-Concurrency Spike) |
| **Function Level Auth Bypass** | `API5:2023` | `GET /api/v1/audit/search` | Security Engine (Privilege Elevation Check) |
| **Business Flow Manipulation** | `API6:2023` | `POST /api/v1/transfers` | Contract & Security Engine (State Injection) |
| **SQL Injection Signal** | `API7:2023` | `GET /api/v1/audit/search?query=...` | Security Engine (SQL Syntax & Error Disclosure) |
| **Stack Trace Disclosure** | `API8:2023` | `GET /api/v1/audit/search` | Security Engine (Error Pattern Matcher) |
| **Improper Inventory / Metrics Leak** | `API9:2023` | `GET /api/v1/system/metrics` | Discovery Engine (Unauthenticated Route Ingestion) |
| **Sensitive Data Exposure (PCI-DSS)** | `API10:2023` | `GET /api/v1/cards` | Security Engine (Regex Card Pattern Matcher) |
| **Synthetic Latency Spike** | Performance | `GET /api/v1/audit/search` | Performance Engine (p90/p99 Latency Outlier) |

---

### Detailed Vulnerability Breakdown & Trigger Examples

#### 1. Broken Object Level Authorization (BOLA / IDOR) — `API1:2023`
- **Route**: `GET /api/v1/accounts/:id`
- **Flaw**: The route validates that the request has an `Authorization` header, but fails to check that `account.userId === req.user.id`. Any authenticated user can view any other user's balance, account number, and overdraft limits.
- **Attack Payload**:
  ```bash
  # Authenticated as Alice, requesting Bob's account:
  curl -X GET http://localhost:4000/api/v1/accounts/acc-bob-chk \
    -H "Authorization: Bearer <ALICE_JWT_TOKEN>"
  ```
- **Detection**: API Trace Dual-Tenant BOLA probe provisions two tenant contexts and observes unauthorized cross-tenant object disclosure (`HTTP 200` with Bob's data).

#### 2. Mass Assignment / Direct Balance Tampering — `API3:2023`
- **Route**: `PUT /api/v1/accounts/:id/balance`
- **Flaw**: The endpoint accepts arbitrary `balance` and `overdraftLimit` fields directly in the JSON body and applies them immediately to the SQLite database record without ledger transactions.
- **Attack Payload**:
  ```bash
  curl -X PUT http://localhost:4000/api/v1/accounts/acc-alice-chk/balance \
    -H "Authorization: Bearer <ALICE_JWT_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{"balance": 999999.00, "overdraftLimit": 50000.00}'
  ```
- **Detection**: API Trace mutates sensitive fields that are not in normal customer workflows and flags unauthorized parameter updates.

#### 3. SQL Injection & Database Error Disclosure — `API7:2023` / `API8:2023`
- **Route**: `GET /api/v1/audit/search?query=...`
- **Flaw**: Query parameter is interpolated directly into an SQL statement:
  ```sql
  SELECT * FROM audit_logs WHERE (message LIKE '%<QUERY>%') AND level = 'info'
  ```
  When invalid SQL or unclosed quote strings are provided, the SQLite engine throws a real `SqliteError`, which the server returns in the HTTP 500 response alongside full stack traces.
- **Attack Payload**:
  ```bash
  curl -X GET "http://localhost:4000/api/v1/audit/search?query=1'+OR+1=1--"
  ```
- **Response**:
  ```json
  {
    "error": "Internal Server Error",
    "message": "SQL syntax error near '1'+OR+1=1--': syntax error in SQL statement...",
    "statusCode": 500,
    "trace": "SqliteError: near \"OR\": syntax error\n    at StatementSync.all..."
  }
  ```
- **Detection**: API Trace Error Pattern Matcher scans response bodies for `SqliteError`, `syntax error`, and stack trace signatures.

#### 4. Sensitive Payment Data Leakage (PCI-DSS) — `API10:2023`
- **Route**: `GET /api/v1/cards`
- **Flaw**: Returns raw 16-digit Primary Account Numbers (PANs) and 3-digit CVV security codes in plaintext JSON without masking.
- **Attack Payload**:
  ```bash
  curl -X GET http://localhost:4000/api/v1/cards \
    -H "Authorization: Bearer <ALICE_JWT_TOKEN>"
  ```
- **Response**:
  ```json
  [
    {
      "id": "crd-alice-visa",
      "accountId": "acc-alice-chk",
      "pan": "4532889912345678",
      "cvv": "891",
      "expiration": "12/28",
      "isActive": true
    }
  ]
  ```
- **Detection**: API Trace Sensitive Data Regex matcher captures unmasked credit card numbers (`pan`) and CVV tokens in response bodies.

#### 5. Unauthenticated Telemetry & Information Disclosure — `API9:2023`
- **Route**: `GET /api/v1/system/metrics`
- **Flaw**: Provides internal cluster memory usage, uptime, active SQLite connections, and transaction counts without requiring any authentication.
- **Attack Payload**:
  ```bash
  curl -X GET http://localhost:4000/api/v1/system/metrics
  ```
- **Detection**: API Trace unauthenticated probe accesses administrative health routes and detects information exposure.

#### 6. Business Logic Flaw / State Override — `API6:2023`
- **Route**: `POST /api/v1/transfers`
- **Flaw**: The client can force arbitrary transaction statuses (e.g. `status: "completed"`, `status: "cleared"`) directly in the request payload.
- **Attack Payload**:
  ```bash
  curl -X POST http://localhost:4000/api/v1/transfers \
    -H "Authorization: Bearer <ALICE_JWT_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{
      "sourceAccountId": "acc-alice-chk",
      "destinationAccountId": "acc-bob-chk",
      "amount": 100.00,
      "status": "force_approved_by_attacker"
    }'
  ```

---

## 5. API Routes Specification

| Method | Path | Auth Required | Description |
| :--- | :--- | :---: | :--- |
| `GET` | `/health` | No | Service health check |
| `GET` | `/openapi.json` | No | OpenAPI 3.0 specification |
| `POST` | `/api/v1/auth/register` | No | Register new customer (returns JWT + checking account) |
| `POST` | `/api/v1/auth/login` | No | Authenticate user (returns JWT) |
| `GET` | `/api/v1/accounts` | Yes | List authenticated user accounts |
| `GET` | `/api/v1/accounts/:id` | Yes | Retrieve account details (*BOLA vulnerable*) |
| `PUT` | `/api/v1/accounts/:id/balance` | Yes | Update account balance (*Mass assignment*) |
| `POST` | `/api/v1/transfers` | Yes | Execute wire transfer (*Rate limit & logic flaw*) |
| `GET` | `/api/v1/transactions` | Yes | Query transaction ledger |
| `GET` | `/api/v1/cards` | Yes | List issued debit/credit cards (*Data leak*) |
| `POST` | `/api/v1/cards` | Yes | Issue new card |
| `GET` | `/api/v1/audit/search` | No | Audit log search (*SQL injection & latency*) |
| `GET` | `/api/v1/system/metrics` | No | Internal system telemetry (*Info disclosure*) |

---

## 6. Testing

The sandbox is backed by an automated **Vitest** test suite covering all routes, database persistence, authentication verification, and vulnerability triggers:

```bash
# Run all tests
pnpm test

# Run tests in watch mode
pnpm test -- --watch
```

---

## 7. License

MIT License. Designed strictly for ethical security testing, benchmarking, and educational research with API Trace.
