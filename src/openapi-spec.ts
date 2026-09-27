export const openApiSpec = {
  openapi: "3.0.3",
  info: {
    title: "VulnBank Core API Sandbox",
    description: "Realistic vulnerable banking API sandbox for automated security audits, contract conformance verification, and latency profiling.",
    version: "1.0.0",
    contact: {
      name: "Security Engineering Sandbox",
      email: "security@vulnbank.local",
    },
  },
  servers: [
    {
      url: "http://127.0.0.1:4000",
      description: "Local Sandbox Server",
    },
  ],
  paths: {
    "/health": {
      get: {
        operationId: "getHealthStatus",
        summary: "Check service health",
        responses: {
          "200": {
            description: "Service is healthy",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    status: { type: "string", example: "ok" },
                    timestamp: { type: "string", format: "date-time" },
                  },
                  required: ["status", "timestamp"],
                },
              },
            },
          },
        },
      },
    },
    "/api/v1/auth/register": {
      post: {
        operationId: "registerUser",
        summary: "Register new customer account",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  username: { type: "string", minLength: 3 },
                  email: { type: "string", format: "email" },
                  password: { type: "string", minLength: 6 },
                },
                required: ["username", "email", "password"],
              },
            },
          },
        },
        responses: {
          "201": {
            description: "Customer registered successfully",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    userId: { type: "string" },
                    username: { type: "string" },
                    email: { type: "string" },
                    token: { type: "string" },
                  },
                  required: ["userId", "username", "email", "token"],
                },
              },
            },
          },
          "400": {
            description: "Invalid customer payload",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
    },
    "/api/v1/auth/login": {
      post: {
        operationId: "loginUser",
        summary: "Authenticate customer and issue session token",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  username: { type: "string" },
                  password: { type: "string" },
                },
                required: ["username", "password"],
              },
            },
          },
        },
        responses: {
          "200": {
            description: "Authentication successful",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    userId: { type: "string" },
                    token: { type: "string" },
                    role: { type: "string" },
                  },
                  required: ["userId", "token"],
                },
              },
            },
          },
          "401": {
            description: "Invalid credentials",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
    },
    "/api/v1/accounts": {
      get: {
        operationId: "listAccounts",
        summary: "List bank accounts for authenticated customer",
        security: [{ BearerAuth: [] }],
        responses: {
          "200": {
            description: "Accounts list retrieved",
            content: {
              "application/json": {
                schema: {
                  type: "array",
                  items: { $ref: "#/components/schemas/Account" },
                },
              },
            },
          },
          "401": {
            description: "Unauthorized",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
      post: {
        operationId: "createAccount",
        summary: "Open new bank account",
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  accountType: { type: "string", enum: ["checking", "savings"] },
                  currency: { type: "string", example: "USD" },
                  initialDeposit: { type: "number", minimum: 0 },
                },
                required: ["accountType", "currency"],
              },
            },
          },
        },
        responses: {
          "201": {
            description: "Account created",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/Account" },
              },
            },
          },
        },
      },
    },
    "/api/v1/accounts/{id}": {
      get: {
        operationId: "getAccountById",
        summary: "Retrieve bank account details by ID (BOLA/IDOR target)",
        security: [{ BearerAuth: [] }],
        parameters: [
          {
            name: "id",
            in: "path",
            required: true,
            schema: { type: "string" },
            description: "Unique Account Identifier",
          },
        ],
        responses: {
          "200": {
            description: "Account details",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/Account" },
              },
            },
          },
          "404": {
            description: "Account not found",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
    },
    "/api/v1/accounts/{id}/balance": {
      put: {
        operationId: "updateAccountBalance",
        summary: "Update account balance directly (Mass Assignment / Tampering)",
        security: [{ BearerAuth: [] }],
        parameters: [
          {
            name: "id",
            in: "path",
            required: true,
            schema: { type: "string" },
          },
        ],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  balance: { type: "number" },
                  overdraftLimit: { type: "number" },
                },
                required: ["balance"],
              },
            },
          },
        },
        responses: {
          "200": {
            description: "Balance updated",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/Account" },
              },
            },
          },
        },
      },
    },
    "/api/v1/transfers": {
      post: {
        operationId: "createTransfer",
        summary: "Execute funds transfer between accounts (Missing rate limiting / status tampering)",
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  sourceAccountId: { type: "string" },
                  destinationAccountId: { type: "string" },
                  amount: { type: "number", minimum: 0.01 },
                  memo: { type: "string" },
                  status: { type: "string", description: "Vulnerable to client mass assignment" },
                },
                required: ["sourceAccountId", "destinationAccountId", "amount"],
              },
            },
          },
        },
        responses: {
          "200": {
            description: "Transfer processed",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/Transaction" },
              },
            },
          },
          "400": {
            description: "Insufficient funds or invalid accounts",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
    },
    "/api/v1/transactions": {
      get: {
        operationId: "listTransactions",
        summary: "Query transaction records",
        security: [{ BearerAuth: [] }],
        parameters: [
          {
            name: "accountId",
            in: "query",
            required: false,
            schema: { type: "string" },
          },
          {
            name: "limit",
            in: "query",
            required: false,
            schema: { type: "integer", default: 20 },
          },
        ],
        responses: {
          "200": {
            description: "Transactions list",
            content: {
              "application/json": {
                schema: {
                  type: "array",
                  items: { $ref: "#/components/schemas/Transaction" },
                },
              },
            },
          },
        },
      },
    },
    "/api/v1/cards": {
      get: {
        operationId: "listCards",
        summary: "Retrieve payment cards (Sensitive data leak: plain CVV and PAN returned)",
        security: [{ BearerAuth: [] }],
        responses: {
          "200": {
            description: "List of issued payment cards",
            content: {
              "application/json": {
                schema: {
                  type: "array",
                  items: { $ref: "#/components/schemas/Card" },
                },
              },
            },
          },
        },
      },
      post: {
        operationId: "issueCard",
        summary: "Issue new debit or credit card",
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  accountId: { type: "string" },
                  cardType: { type: "string", enum: ["debit", "credit"] },
                },
                required: ["accountId", "cardType"],
              },
            },
          },
        },
        responses: {
          "201": {
            description: "Card successfully issued",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/Card" },
              },
            },
          },
        },
      },
    },
    "/api/v1/audit/search": {
      get: {
        operationId: "searchAuditLogs",
        summary: "Search system audit events (SQL injection signal, high latency, unauthenticated)",
        parameters: [
          {
            name: "query",
            in: "query",
            required: false,
            schema: { type: "string" },
            description: "Filter search query string",
          },
        ],
        responses: {
          "200": {
            description: "Matching audit logs",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    query: { type: "string" },
                    matchesCount: { type: "integer" },
                    logs: {
                      type: "array",
                      items: { type: "string" },
                    },
                  },
                  required: ["query", "matchesCount", "logs"],
                },
              },
            },
          },
          "500": {
            description: "Database query syntax failure (SQL injection error trace)",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
    },
    "/api/v1/system/metrics": {
      get: {
        operationId: "getSystemMetrics",
        summary: "Internal cluster metrics (Unauthenticated information disclosure)",
        responses: {
          "200": {
            description: "Internal cluster telemetry",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    uptimeSec: { type: "number" },
                    memoryUsageMb: { type: "number" },
                    activeDbConnections: { type: "integer" },
                    totalTransfersCount: { type: "integer" },
                  },
                  required: ["uptimeSec", "memoryUsageMb", "activeDbConnections"],
                },
              },
            },
          },
        },
      },
    },
  },
  components: {
    securitySchemes: {
      BearerAuth: {
        type: "http",
        scheme: "bearer",
        bearerFormat: "JWT",
      },
    },
    schemas: {
      Account: {
        type: "object",
        properties: {
          id: { type: "string", example: "acc-101" },
          userId: { type: "string", example: "usr-42" },
          accountNumber: { type: "string", example: "450912348877" },
          accountType: { type: "string", enum: ["checking", "savings"] },
          currency: { type: "string", example: "USD" },
          balance: { type: "number", example: 12500.5 },
          overdraftLimit: { type: "number", example: 2500.0 },
          createdAt: { type: "string", format: "date-time" },
        },
        required: ["id", "userId", "accountNumber", "accountType", "currency", "balance"],
      },
      Transaction: {
        type: "object",
        properties: {
          id: { type: "string", example: "tx-883" },
          sourceAccountId: { type: "string" },
          destinationAccountId: { type: "string" },
          amount: { type: "number" },
          currency: { type: "string", example: "USD" },
          status: { type: "string", example: "completed" },
          memo: { type: "string" },
          timestamp: { type: "string", format: "date-time" },
        },
        required: ["id", "sourceAccountId", "destinationAccountId", "amount", "status"],
      },
      Card: {
        type: "object",
        properties: {
          id: { type: "string", example: "crd-007" },
          accountId: { type: "string" },
          cardType: { type: "string", enum: ["debit", "credit"] },
          pan: { type: "string", example: "4532889912345678", description: "Leaked PAN in plain text" },
          cvv: { type: "string", example: "891", description: "Leaked CVV in plain text" },
          expiration: { type: "string", example: "12/28" },
          isActive: { type: "boolean", example: true },
        },
        required: ["id", "accountId", "cardType", "pan", "expiration", "isActive"],
      },
      ErrorResponse: {
        type: "object",
        properties: {
          error: { type: "string" },
          message: { type: "string" },
          statusCode: { type: "integer" },
          trace: { type: "string", description: "Verbose stack trace leak" },
        },
        required: ["error", "message", "statusCode"],
      },
    },
  },
};
