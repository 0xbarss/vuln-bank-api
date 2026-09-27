import fastify, { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import cors from "@fastify/cors";
import { openApiSpec } from "./openapi-spec.js";
import { store, User, BankAccount, Transaction, Card } from "./store.js";
import { hashPassword, verifyPassword, createJwtToken, verifyJwtToken } from "./auth.js";

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

  // Auth Helper: verifies JWT signature or falls back to seeded token
  const extractUser = (req: FastifyRequest): User | null => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return null;
    const parts = authHeader.split(" ");
    const token = parts.length === 2 ? parts[1] : parts[0];
    if (!token) return null;

    // 1. Try verifying as signed JWT
    const payload = verifyJwtToken(token);
    if (payload?.sub) {
      const user = store.getUserById(payload.sub);
      if (user) return user;
    }

    // 2. Direct token lookup fallback for seeded tokens
    return store.getUserByToken(token) || null;
  };

  // 1. Auth Register (Real salted scrypt password hashing + signed JWT issuance)
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

    const existing = store.getUserByUsername(username);
    if (existing) {
      return reply.status(409).send({
        error: "Conflict",
        message: "Username already exists",
        statusCode: 409,
      });
    }

    const userId = `usr-${Date.now().toString(36)}`;
    const { hash, salt } = hashPassword(password);
    const token = createJwtToken({
      sub: userId,
      username,
      role: "customer",
    });

    const newUser: User = {
      id: userId,
      username,
      email,
      passwordHash: hash,
      salt,
      role: "customer",
      token,
    };
    store.createUser(newUser);

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
    store.createAccount(newAccount);

    return reply.status(201).send({
      userId,
      username,
      email,
      token,
    });
  });

  // 2. Auth Login (Real password verification + signed JWT issuance)
  app.post("/api/v1/auth/login", async (req: FastifyRequest<{
    Body: { username?: string; password?: string };
  }>, reply) => {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return reply.status(400).send({
        error: "Bad Request",
        message: "Username and password are required",
        statusCode: 400,
      });
    }

    const user = store.getUserByUsername(username);
    if (!user || !verifyPassword(password, user.passwordHash, user.salt)) {
      return reply.status(401).send({
        error: "Unauthorized",
        message: "Invalid username or password",
        statusCode: 401,
      });
    }

    // Issue a freshly signed JWT token
    const token = createJwtToken({
      sub: user.id,
      username: user.username,
      role: user.role,
    });

    return reply.status(200).send({
      userId: user.id,
      token,
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

    const userAccounts = store.listAccountsByUserId(user.id);
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

    const account = store.getAccountById(req.params.id);
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

    const account = store.getAccountById(req.params.id);
    if (!account) {
      return reply.status(404).send({
        error: "Not Found",
        message: "Account not found",
        statusCode: 404,
      });
    }

    const updated = store.updateAccountBalance(
      req.params.id,
      typeof req.body?.balance === "number" ? req.body.balance : undefined,
      typeof req.body?.overdraftLimit === "number" ? req.body.overdraftLimit : undefined
    );

    return reply.status(200).send(updated ?? account);
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

    const source = store.getAccountById(sourceAccountId);
    const dest = store.getAccountById(destinationAccountId);

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

    store.updateAccountBalance(sourceAccountId, source.balance - amount);
    store.updateAccountBalance(destinationAccountId, dest.balance + amount);

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

    store.createTransaction(tx);
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
    const maxItems = Number(limit) || 20;
    const list = store.listTransactions(accountId, maxItems);
    return reply.status(200).send(list);
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

    const cards = store.listCardsByUserId(user.id);
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
    store.createCard(newCard);

    return reply.status(201).send(newCard);
  });

  // 10. Audit Search (VULNERABILITY: Real SQLite SQL Injection Signal + Latency + Unauthenticated)
  app.get("/api/v1/audit/search", async (req: FastifyRequest<{
    Querystring: { query?: string };
  }>, reply) => {
    const { query = "" } = req.query;

    // Simulate database lookup latency (180ms - 220ms)
    await new Promise((resolve) => setTimeout(resolve, 180));

    try {
      const logs = store.searchAuditLogs(query);
      return reply.status(200).send({
        query,
        matchesCount: logs.length,
        logs,
      });
    } catch (err: unknown) {
      const errorObj = err as Error;
      return reply.status(500).send({
        error: "Internal Server Error",
        message: `SQL syntax error near '${query}': syntax error in SQL statement SELECT * FROM audit_logs WHERE (message LIKE '%${query}%') AND level = 'info'`,
        statusCode: 500,
        trace: `SqliteError: ${errorObj.message}\n${errorObj.stack || ""}`,
      });
    }
  });

  // 11. System Metrics (VULNERABILITY: Unauthenticated Info Disclosure)
  app.get("/api/v1/system/metrics", async (_req, reply) => {
    return reply.status(200).send({
      uptimeSec: process.uptime(),
      memoryUsageMb: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
      activeDbConnections: 4,
      totalTransfersCount: store.getTransactionsCount(),
    });
  });

  return app;
}
