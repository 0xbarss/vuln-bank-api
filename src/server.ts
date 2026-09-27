import fastify, { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import cors from "@fastify/cors";
import { openApiSpec } from "./openapi-spec.js";
import { store, User, BankAccount, Transaction, Card } from "./store.js";

export function buildServer(): FastifyInstance {
  const app = fastify({
    logger: false,
  });

  void app.register(cors, {
    origin: true,
  });

  // Serve OpenAPI specification
  const serveSpec = (_req: FastifyRequest, reply: FastifyReply) => {
    return reply.header("Content-Type", "application/json").send(openApiSpec);
  };
  app.get("/openapi.json", serveSpec);
  app.get("/api-docs/openapi.json", serveSpec);

  // Health endpoint
  app.get("/health", async (_req, reply) => {
    return reply.status(200).send({
      status: "ok",
      timestamp: new Date().toISOString(),
    });
  });

  // Auth Helper
  const extractUser = (req: FastifyRequest): User | null => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return null;
    const parts = authHeader.split(" ");
    const token = parts.length === 2 ? parts[1] : parts[0];
    return store.getUserByToken(token) || null;
  };

  // 1. Auth Register
  app.post("/api/v1/auth/register", async (req: FastifyRequest<{
    Body: { username?: string; email?: string; password?: string };
  }>, reply) => {
    const { username, email, password } = req.body || {};
    if (!username || !email || !password) {
      return reply.status(400).send({
        error: "Bad Request",
        message: "Missing required fields: username, email, password",
        statusCode: 400,
      });
    }

    const userId = `usr-${Date.now().toString(36)}`;
    const token = `vbnk_token_${username}_${Date.now()}`;
    const newUser: User = {
      id: userId,
      username,
      email,
      passwordHash: password,
      role: "customer",
      token,
    };
    store.users.set(userId, newUser);

    // Create default checking account for user
    const accId = `acc-${Date.now().toString(36)}`;
    const newAccount: BankAccount = {
      id: accId,
      userId,
      accountNumber: `4509${Math.floor(10000000 + Math.random() * 90000000)}`,
      accountType: "checking",
      currency: "USD",
      balance: 1000.0,
      overdraftLimit: 500.0,
      createdAt: new Date().toISOString(),
    };
    store.accounts.set(accId, newAccount);

    return reply.status(201).send({
      userId,
      username,
      email,
      token,
    });
  });

  // 2. Auth Login
  app.post("/api/v1/auth/login", async (req: FastifyRequest<{
    Body: { username?: string; password?: string };
  }>, reply) => {
    const { username, password } = req.body || {};
    const user = Array.from(store.users.values()).find(
      (u) => u.username === username && u.passwordHash === password
    );

    if (!user) {
      return reply.status(401).send({
        error: "Unauthorized",
        message: "Invalid username or password",
        statusCode: 401,
      });
    }

    return reply.status(200).send({
      userId: user.id,
      token: user.token,
      role: user.role,
    });
  });

  // 3. Accounts List (Requires Auth)
  app.get("/api/v1/accounts", async (req, reply) => {
    const user = extractUser(req);
    if (!user) {
      return reply.status(401).send({
        error: "Unauthorized",
        message: "Authentication token missing or invalid",
        statusCode: 401,
      });
    }

    const userAccounts = Array.from(store.accounts.values()).filter(
      (a) => a.userId === user.id
    );
    return reply.status(200).send(userAccounts);
  });

  // 4. Account Details by ID (VULNERABILITY: BOLA / IDOR)
  // Any authenticated user can read ANY account without ownership verification!
  app.get("/api/v1/accounts/:id", async (req: FastifyRequest<{
    Params: { id: string };
  }>, reply) => {
    const user = extractUser(req);
    if (!user) {
      return reply.status(401).send({
        error: "Unauthorized",
        message: "Bearer token required",
        statusCode: 401,
      });
    }

    const account = store.accounts.get(req.params.id);
    if (!account) {
      return reply.status(404).send({
        error: "Not Found",
        message: `Account with ID '${req.params.id}' not found`,
        statusCode: 404,
      });
    }

    // BOLA FLAW: Deliberately returning account even if account.userId !== user.id
    return reply.status(200).send(account);
  });

  // 5. Account Balance Direct Update (VULNERABILITY: Mass Assignment / Privilege Escalation)
  app.put("/api/v1/accounts/:id/balance", async (req: FastifyRequest<{
    Params: { id: string };
    Body: { balance?: number; overdraftLimit?: number };
  }>, reply) => {
    const user = extractUser(req);
    if (!user) {
      return reply.status(401).send({
        error: "Unauthorized",
        message: "Bearer token required",
        statusCode: 401,
      });
    }

    const account = store.accounts.get(req.params.id);
    if (!account) {
      return reply.status(404).send({
        error: "Not Found",
        message: "Account not found",
        statusCode: 404,
      });
    }

    if (typeof req.body?.balance === "number") {
      account.balance = req.body.balance;
    }
    if (typeof req.body?.overdraftLimit === "number") {
      account.overdraftLimit = req.body.overdraftLimit;
    }

    return reply.status(200).send(account);
  });

  // 6. Transfers (VULNERABILITIES: Missing rate limit + client status override)
  app.post("/api/v1/transfers", async (req: FastifyRequest<{
    Body: {
      sourceAccountId?: string;
      destinationAccountId?: string;
      amount?: number;
      memo?: string;
      status?: string;
    };
  }>, reply) => {
    const user = extractUser(req);
    if (!user) {
      return reply.status(401).send({
        error: "Unauthorized",
        message: "Bearer token required",
        statusCode: 401,
      });
    }

    const { sourceAccountId, destinationAccountId, amount, memo, status } = req.body || {};
    if (!sourceAccountId || !destinationAccountId || typeof amount !== "number" || amount <= 0) {
      return reply.status(400).send({
        error: "Bad Request",
        message: "sourceAccountId, destinationAccountId, and positive amount are required",
        statusCode: 400,
      });
    }

    const source = store.accounts.get(sourceAccountId);
    const dest = store.accounts.get(destinationAccountId);

    if (!source) {
      return reply.status(400).send({
        error: "Bad Request",
        message: `Source account '${sourceAccountId}' does not exist`,
        statusCode: 400,
      });
    }
    if (!dest) {
      return reply.status(400).send({
        error: "Bad Request",
        message: `Destination account '${destinationAccountId}' does not exist`,
        statusCode: 400,
      });
    }

    if (source.balance < amount) {
      return reply.status(400).send({
        error: "Bad Request",
        message: "Insufficient account balance",
        statusCode: 400,
      });
    }

    source.balance -= amount;
    dest.balance += amount;

    const tx: Transaction = {
      id: `tx-${Date.now().toString(36)}`,
      sourceAccountId,
      destinationAccountId,
      amount,
      currency: source.currency,
      // VULNERABILITY: client can force status to whatever it sends
      status: status || "completed",
      memo,
      timestamp: new Date().toISOString(),
    };

    store.transactions.push(tx);
    return reply.status(200).send(tx);
  });

  // 7. Transactions Query
  app.get("/api/v1/transactions", async (req: FastifyRequest<{
    Querystring: { accountId?: string; limit?: number };
  }>, reply) => {
    const user = extractUser(req);
    if (!user) {
      return reply.status(401).send({
        error: "Unauthorized",
        message: "Bearer token required",
        statusCode: 401,
      });
    }

    const { accountId, limit } = req.query;
    let list = store.transactions;
    if (accountId) {
      list = list.filter(
        (t) => t.sourceAccountId === accountId || t.destinationAccountId === accountId
      );
    }

    const maxItems = Number(limit) || 20;
    return reply.status(200).send(list.slice(0, maxItems));
  });

  // 8. Cards List (VULNERABILITY: Sensitive Data Leakage - Plain PAN and CVV)
  app.get("/api/v1/cards", async (req, reply) => {
    const user = extractUser(req);
    if (!user) {
      return reply.status(401).send({
        error: "Unauthorized",
        message: "Bearer token required",
        statusCode: 401,
      });
    }

    const cards = Array.from(store.cards.values()).filter((c) => c.userId === user.id);
    // VULNERABILITY: Returns raw pan and cvv in plain text!
    return reply.status(200).send(cards);
  });

  // 9. Card Issuance
  app.post("/api/v1/cards", async (req: FastifyRequest<{
    Body: { accountId?: string; cardType?: "debit" | "credit" };
  }>, reply) => {
    const user = extractUser(req);
    if (!user) {
      return reply.status(401).send({
        error: "Unauthorized",
        message: "Bearer token required",
        statusCode: 401,
      });
    }

    const { accountId, cardType } = req.body || {};
    if (!accountId || !cardType) {
      return reply.status(400).send({
        error: "Bad Request",
        message: "accountId and cardType are required",
        statusCode: 400,
      });
    }

    const cardId = `crd-${Date.now().toString(36)}`;
    const newCard: Card = {
      id: cardId,
      accountId,
      userId: user.id,
      cardType,
      pan: `4532${Math.floor(100000000000 + Math.random() * 900000000000)}`,
      cvv: `${Math.floor(100 + Math.random() * 900)}`,
      expiration: "12/29",
      isActive: true,
    };
    store.cards.set(cardId, newCard);

    return reply.status(201).send(newCard);
  });

  // 10. Audit Search (VULNERABILITY: SQL Injection Signal + High Latency + Unauthenticated)
  app.get("/api/v1/audit/search", async (req: FastifyRequest<{
    Querystring: { query?: string };
  }>, reply) => {
    const { query = "" } = req.query;

    // Simulate database lookup latency (180ms - 220ms)
    await new Promise((resolve) => setTimeout(resolve, 180));

    // SQL Injection detection signal
    if (/['";]|--|\/\*|select|union|drop|insert/i.test(query)) {
      return reply.status(500).send({
        error: "Internal Server Error",
        message: `SQL syntax error near '${query}': syntax error in SQL statement SELECT * FROM audit_logs WHERE message LIKE '%${query}%'`,
        statusCode: 500,
        trace: `SqliteError: syntax error at QueryContext.execute (/app/src/db/sqlite.ts:42:15)\n    at searchAuditLogs (/app/src/routes/audit.ts:18:22)`,
      });
    }

    return reply.status(200).send({
      query,
      matchesCount: 2,
      logs: [
        `[2026-09-27T10:00:00Z] System integrity check executed for cluster`,
        `[2026-09-27T12:00:00Z] Automated backup archive created for database`,
      ],
    });
  });

  // 11. System Metrics (VULNERABILITY: Unauthenticated Info Disclosure)
  app.get("/api/v1/system/metrics", async (_req, reply) => {
    return reply.status(200).send({
      uptimeSec: process.uptime(),
      memoryUsageMb: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
      activeDbConnections: 4,
      totalTransfersCount: store.transactions.length,
    });
  });

  return app;
}
