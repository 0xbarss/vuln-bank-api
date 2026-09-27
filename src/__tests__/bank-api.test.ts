import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { buildServer } from "../server.js";
import { store } from "../store.js";
import type { FastifyInstance } from "fastify";

describe("VulnBank API Sandbox", () => {
  let app: FastifyInstance;

  beforeEach(async () => {
    store.reset();
    app = buildServer();
    await app.ready();
  });

  afterAll(async () => {
    if (app) await app.close();
  });

  it("serves health status", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/health",
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.status).toBe("ok");
    expect(body.timestamp).toBeDefined();
  });

  it("serves standard OpenAPI 3.0 specification", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/openapi.json",
    });

    expect(res.statusCode).toBe(200);
    const spec = JSON.parse(res.body);
    expect(spec.openapi).toBe("3.0.3");
    expect(spec.info.title).toContain("VulnBank");
    expect(spec.paths["/api/v1/accounts"]).toBeDefined();
    expect(spec.paths["/api/v1/transfers"]).toBeDefined();
    expect(spec.paths["/api/v1/cards"]).toBeDefined();
  });

  it("authenticates registered user and returns bearer token", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/auth/login",
      payload: {
        username: "alice",
        password: "password123",
      },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.token).toBeDefined();
    expect(body.userId).toBe("usr-alice-101");
  });

  it("enforces authentication on accounts endpoint", async () => {
    const unauth = await app.inject({
      method: "GET",
      url: "/api/v1/accounts",
    });
    expect(unauth.statusCode).toBe(401);

    const auth = await app.inject({
      method: "GET",
      url: "/api/v1/accounts",
      headers: {
        authorization: "Bearer vbnk_token_alice_sec_9941",
      },
    });
    expect(auth.statusCode).toBe(200);
    const accounts = JSON.parse(auth.body);
    expect(Array.isArray(accounts)).toBe(true);
    expect(accounts[0].userId).toBe("usr-alice-101");
  });

  it("demonstrates BOLA / IDOR vulnerability on account detail endpoint", async () => {
    // Alice requests Bob's checking account directly
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/accounts/acc-bob-chk",
      headers: {
        authorization: "Bearer vbnk_token_alice_sec_9941", // Alice's token
      },
    });

    expect(res.statusCode).toBe(200);
    const bobAccount = JSON.parse(res.body);
    expect(bobAccount.id).toBe("acc-bob-chk");
    expect(bobAccount.userId).toBe("usr-bob-202"); // Cross-tenant data accessed!
  });

  it("demonstrates Mass Assignment vulnerability on balance update", async () => {
    const res = await app.inject({
      method: "PUT",
      url: "/api/v1/accounts/acc-alice-chk/balance",
      headers: {
        authorization: "Bearer vbnk_token_alice_sec_9941",
      },
      payload: {
        balance: 999999.0,
        overdraftLimit: 50000.0,
      },
    });

    expect(res.statusCode).toBe(200);
    const updated = JSON.parse(res.body);
    expect(updated.balance).toBe(999999.0);
    expect(updated.overdraftLimit).toBe(50000.0);
  });

  it("demonstrates sensitive payment data leakage on cards endpoint", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/cards",
      headers: {
        authorization: "Bearer vbnk_token_alice_sec_9941",
      },
    });

    expect(res.statusCode).toBe(200);
    const cards = JSON.parse(res.body);
    expect(cards.length).toBeGreaterThan(0);
    // Plain PAN and CVV leaked in JSON!
    expect(cards[0].pan).toBe("4532889912345678");
    expect(cards[0].cvv).toBe("891");
  });

  it("demonstrates SQL injection signal on audit search", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/audit/search?query=1'+OR+1=1--",
    });

    expect(res.statusCode).toBe(500);
    const body = JSON.parse(res.body);
    expect(body.error).toBe("Internal Server Error");
    expect(body.message).toContain("SQL syntax error");
    expect(body.trace).toContain("SqliteError");
  });

  it("allows unauthenticated access to internal metrics endpoint", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/system/metrics",
    });

    expect(res.statusCode).toBe(200);
    const metrics = JSON.parse(res.body);
    expect(metrics.uptimeSec).toBeDefined();
    expect(metrics.memoryUsageMb).toBeDefined();
    expect(metrics.activeDbConnections).toBe(4);
  });

  it("registers new user with salted scrypt hash in sqlite and issues signed JWT", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/auth/register",
      payload: {
        username: "testuser_99",
        email: "testuser@vulnbank.local",
        password: "MySuperSecretPassword#123",
      },
    });

    expect(res.statusCode).toBe(201);
    const body = JSON.parse(res.body);
    expect(body.userId).toBeDefined();
    expect(body.token).toBeDefined();

    // Verify token is a valid compact JWT (3 dot-separated parts)
    const parts = body.token.split(".");
    expect(parts.length).toBe(3);

    // Verify user is persisted in real SQLite with salted scrypt hash, NOT plaintext
    const dbUser = store.getUserById(body.userId);
    expect(dbUser).toBeDefined();
    expect(dbUser?.username).toBe("testuser_99");
    expect(dbUser?.passwordHash).not.toBe("MySuperSecretPassword#123");
    expect(dbUser?.passwordHash.length).toBe(128); // 64 bytes hex
    expect(dbUser?.salt).toBeDefined();

    // Verify default checking account created in SQLite
    const accounts = store.listAccountsByUserId(body.userId);
    expect(accounts.length).toBe(1);
    expect(accounts[0].balance).toBe(1000.0);
  });

  it("verifies password and issues signed JWT on login, rejecting invalid passwords", async () => {
    // 1. Invalid password rejection
    const failRes = await app.inject({
      method: "POST",
      url: "/api/v1/auth/login",
      payload: {
        username: "alice",
        password: "WrongPassword123!",
      },
    });
    expect(failRes.statusCode).toBe(401);

    // 2. Successful login with correct password
    const successRes = await app.inject({
      method: "POST",
      url: "/api/v1/auth/login",
      payload: {
        username: "alice",
        password: "password123",
      },
    });
    expect(successRes.statusCode).toBe(200);
    const body = JSON.parse(successRes.body);
    expect(body.token).toBeDefined();

    // 3. Authenticate with newly issued JWT
    const authRes = await app.inject({
      method: "GET",
      url: "/api/v1/accounts",
      headers: {
        authorization: `Bearer ${body.token}`,
      },
    });
    expect(authRes.statusCode).toBe(200);
    const accounts = JSON.parse(authRes.body);
    expect(accounts.length).toBe(2); // Alice's checking and savings
  });

  it("rejects tampered or forged JWT tokens", async () => {
    // Login to get a valid token
    const loginRes = await app.inject({
      method: "POST",
      url: "/api/v1/auth/login",
      payload: {
        username: "bob",
        password: "securePass789",
      },
    });
    const { token } = JSON.parse(loginRes.body);

    // Tamper with the signature portion
    const parts = token.split(".");
    const tamperedSig = parts[2].slice(0, -4) + "XXXX";
    const forgedToken = `${parts[0]}.${parts[1]}.${tamperedSig}`;

    const res = await app.inject({
      method: "GET",
      url: "/api/v1/accounts",
      headers: {
        authorization: `Bearer ${forgedToken}`,
      },
    });
    expect(res.statusCode).toBe(401);
  });

  it("executes wire transfer and persists updated balances to sqlite", async () => {
    const initialAlice = store.getAccountById("acc-alice-chk");
    const initialBob = store.getAccountById("acc-bob-chk");
    expect(initialAlice).toBeDefined();
    expect(initialBob).toBeDefined();

    const transferAmount = 500.0;
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/transfers",
      headers: {
        authorization: "Bearer vbnk_token_alice_sec_9941",
      },
      payload: {
        sourceAccountId: "acc-alice-chk",
        destinationAccountId: "acc-bob-chk",
        amount: transferAmount,
        memo: "Rent reimbursement",
      },
    });

    expect(res.statusCode).toBe(200);
    const tx = JSON.parse(res.body);
    expect(tx.id).toBeDefined();
    expect(tx.amount).toBe(500.0);

    // Verify persisted SQLite balances
    const updatedAlice = store.getAccountById("acc-alice-chk");
    const updatedBob = store.getAccountById("acc-bob-chk");
    expect(updatedAlice?.balance).toBe(initialAlice!.balance - transferAmount);
    expect(updatedBob?.balance).toBe(initialBob!.balance + transferAmount);
  });
});

