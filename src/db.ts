import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { hashPassword } from "./auth.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function getDatabasePath(): string {
  if (process.env.VULN_BANK_DB_PATH) {
    return process.env.VULN_BANK_DB_PATH;
  }
  const projectRoot = path.resolve(__dirname, "..");
  const dataDir = path.join(projectRoot, "data");
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
  return path.join(dataDir, "vuln-bank.sqlite");
}

export function initSchema(db: DatabaseSync): void {
  db.exec("PRAGMA foreign_keys = ON;");

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      role TEXT NOT NULL,
      token TEXT
    );

    CREATE TABLE IF NOT EXISTS accounts (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      account_number TEXT UNIQUE NOT NULL,
      account_type TEXT NOT NULL,
      currency TEXT NOT NULL,
      balance REAL NOT NULL,
      overdraft_limit REAL NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id TEXT PRIMARY KEY,
      source_account_id TEXT NOT NULL,
      destination_account_id TEXT NOT NULL,
      amount REAL NOT NULL,
      currency TEXT NOT NULL,
      status TEXT NOT NULL,
      memo TEXT,
      timestamp TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS cards (
      id TEXT PRIMARY KEY,
      account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      card_type TEXT NOT NULL,
      pan TEXT NOT NULL,
      cvv TEXT NOT NULL,
      expiration TEXT NOT NULL,
      is_active INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      message TEXT NOT NULL,
      level TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_accounts_user_id ON accounts(user_id);
    CREATE INDEX IF NOT EXISTS idx_transactions_source ON transactions(source_account_id);
    CREATE INDEX IF NOT EXISTS idx_transactions_dest ON transactions(destination_account_id);
    CREATE INDEX IF NOT EXISTS idx_cards_user_id ON cards(user_id);
    CREATE INDEX IF NOT EXISTS idx_cards_account_id ON cards(account_id);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
  `);
}

export function seedDatabase(db: DatabaseSync): void {
  const userCount = (db.prepare("SELECT count(*) as cnt FROM users").get() as { cnt: number }).cnt;
  if (userCount > 0) {
    return;
  }

  // 1. Seed Users with real salted scrypt hashes
  const insertUser = db.prepare(`
    INSERT INTO users (id, username, email, password_hash, salt, role, token)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  const users = [
    {
      id: "usr-alice-101",
      username: "alice",
      email: "alice@vulnbank.local",
      plain: "password123",
      role: "customer",
      token: "vbnk_token_alice_sec_9941",
    },
    {
      id: "usr-bob-202",
      username: "bob",
      email: "bob@vulnbank.local",
      plain: "securePass789",
      role: "customer",
      token: "vbnk_token_bob_sec_5512",
    },
    {
      id: "usr-charlie-303",
      username: "charlie",
      email: "charlie@vulnbank.local",
      plain: "CharlieVance!2026",
      role: "customer",
      token: "vbnk_token_charlie_sec_3389",
    },
    {
      id: "usr-diana-404",
      username: "diana",
      email: "diana.prince@enterprise-corp.com",
      plain: "EnterpriseCapital#99",
      role: "customer",
      token: "vbnk_token_diana_corp_7721",
    },
    {
      id: "usr-admin-001",
      username: "admin",
      email: "admin@vulnbank.local",
      plain: "AdminSecret2026!",
      role: "admin",
      token: "vbnk_token_admin_super_9999",
    },
    {
      id: "usr-auditor-002",
      username: "auditor",
      email: "compliance@vulnbank.local",
      plain: "AuditReadonly2026!",
      role: "admin",
      token: "vbnk_token_auditor_view_8842",
    },
  ];

  for (const u of users) {
    const { hash, salt } = hashPassword(u.plain);
    insertUser.run(u.id, u.username, u.email, hash, salt, u.role, u.token);
  }

  // 2. Seed Accounts
  const insertAccount = db.prepare(`
    INSERT INTO accounts (id, user_id, account_number, account_type, currency, balance, overdraft_limit, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const accounts = [
    {
      id: "acc-alice-chk",
      userId: "usr-alice-101",
      accountNumber: "450912348877",
      accountType: "checking",
      currency: "USD",
      balance: 14500.5,
      overdraftLimit: 2000,
      createdAt: "2026-01-10T12:00:00.000Z",
    },
    {
      id: "acc-alice-sav",
      userId: "usr-alice-101",
      accountNumber: "450912348899",
      accountType: "savings",
      currency: "USD",
      balance: 48250.0,
      overdraftLimit: 0,
      createdAt: "2026-01-15T09:00:00.000Z",
    },
    {
      id: "acc-bob-chk",
      userId: "usr-bob-202",
      accountNumber: "450998761122",
      accountType: "checking",
      currency: "USD",
      balance: 3250.0,
      overdraftLimit: 500,
      createdAt: "2026-02-14T09:30:00.000Z",
    },
    {
      id: "acc-bob-sav",
      userId: "usr-bob-202",
      accountNumber: "450998761133",
      accountType: "savings",
      currency: "USD",
      balance: 1540.25,
      overdraftLimit: 0,
      createdAt: "2026-02-20T11:15:00.000Z",
    },
    {
      id: "acc-charlie-chk",
      userId: "usr-charlie-303",
      accountNumber: "450955443322",
      accountType: "checking",
      currency: "EUR",
      balance: 8920.75,
      overdraftLimit: 1000,
      createdAt: "2026-03-01T08:00:00.000Z",
    },
    {
      id: "acc-diana-biz",
      userId: "usr-diana-404",
      accountNumber: "450977889900",
      accountType: "checking",
      currency: "USD",
      balance: 245000.0,
      overdraftLimit: 50000,
      createdAt: "2026-03-05T14:20:00.000Z",
    },
    {
      id: "acc-diana-payroll",
      userId: "usr-diana-404",
      accountNumber: "450977889911",
      accountType: "checking",
      currency: "USD",
      balance: 85000.0,
      overdraftLimit: 25000,
      createdAt: "2026-03-10T16:45:00.000Z",
    },
  ];

  for (const a of accounts) {
    insertAccount.run(
      a.id,
      a.userId,
      a.accountNumber,
      a.accountType,
      a.currency,
      a.balance,
      a.overdraftLimit,
      a.createdAt
    );
  }

  // 3. Seed Cards
  const insertCard = db.prepare(`
    INSERT INTO cards (id, account_id, user_id, card_type, pan, cvv, expiration, is_active)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const cards = [
    {
      id: "crd-alice-visa",
      accountId: "acc-alice-chk",
      userId: "usr-alice-101",
      cardType: "debit",
      pan: "4532889912345678",
      cvv: "891",
      expiration: "12/28",
      isActive: 1,
    },
    {
      id: "crd-alice-mc",
      accountId: "acc-alice-chk",
      userId: "usr-alice-101",
      cardType: "credit",
      pan: "5412750098234411",
      cvv: "342",
      expiration: "08/29",
      isActive: 1,
    },
    {
      id: "crd-bob-visa",
      accountId: "acc-bob-chk",
      userId: "usr-bob-202",
      cardType: "debit",
      pan: "4532109844556677",
      cvv: "519",
      expiration: "04/27",
      isActive: 1,
    },
    {
      id: "crd-charlie-debit",
      accountId: "acc-charlie-chk",
      userId: "usr-charlie-303",
      cardType: "debit",
      pan: "4916300011223344",
      cvv: "773",
      expiration: "11/27",
      isActive: 1,
    },
    {
      id: "crd-diana-corp",
      accountId: "acc-diana-biz",
      userId: "usr-diana-404",
      cardType: "credit",
      pan: "5521400099881234",
      cvv: "990",
      expiration: "06/30",
      isActive: 1,
    },
  ];

  for (const c of cards) {
    insertCard.run(c.id, c.accountId, c.userId, c.cardType, c.pan, c.cvv, c.expiration, c.isActive);
  }

  // 4. Seed Transactions
  const insertTx = db.prepare(`
    INSERT INTO transactions (id, source_account_id, destination_account_id, amount, currency, status, memo, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const transactions = [
    {
      id: "tx-init-101",
      sourceAccountId: "acc-external",
      destinationAccountId: "acc-alice-chk",
      amount: 14500.5,
      currency: "USD",
      status: "completed",
      memo: "Initial payroll deposit",
      timestamp: "2026-01-10T12:05:00.000Z",
    },
    {
      id: "tx-transfer-102",
      sourceAccountId: "acc-alice-chk",
      destinationAccountId: "acc-alice-sav",
      amount: 3000.0,
      currency: "USD",
      status: "completed",
      memo: "Automatic savings sweep",
      timestamp: "2026-01-16T08:30:00.000Z",
    },
    {
      id: "tx-purchase-103",
      sourceAccountId: "acc-alice-chk",
      destinationAccountId: "merchant-tech-supplies",
      amount: 249.99,
      currency: "USD",
      status: "completed",
      memo: "Hardware store purchase",
      timestamp: "2026-02-01T15:22:10.000Z",
    },
    {
      id: "tx-init-201",
      sourceAccountId: "acc-external",
      destinationAccountId: "acc-bob-chk",
      amount: 3500.0,
      currency: "USD",
      status: "completed",
      memo: "Consulting stipend",
      timestamp: "2026-02-14T09:40:00.000Z",
    },
    {
      id: "tx-transfer-202",
      sourceAccountId: "acc-bob-chk",
      destinationAccountId: "acc-bob-sav",
      amount: 250.0,
      currency: "USD",
      status: "completed",
      memo: "Personal emergency fund",
      timestamp: "2026-02-21T10:00:00.000Z",
    },
    {
      id: "tx-init-301",
      sourceAccountId: "acc-external-eu",
      destinationAccountId: "acc-charlie-chk",
      amount: 8920.75,
      currency: "EUR",
      status: "completed",
      memo: "SEPA wire transfer",
      timestamp: "2026-03-01T08:15:00.000Z",
    },
    {
      id: "tx-corp-401",
      sourceAccountId: "acc-external-treasury",
      destinationAccountId: "acc-diana-biz",
      amount: 250000.0,
      currency: "USD",
      status: "completed",
      memo: "Q1 Capitalization funding",
      timestamp: "2026-03-05T14:30:00.000Z",
    },
    {
      id: "tx-corp-402",
      sourceAccountId: "acc-diana-biz",
      destinationAccountId: "acc-diana-payroll",
      amount: 5000.0,
      currency: "USD",
      status: "completed",
      memo: "Payroll account funding transfer",
      timestamp: "2026-03-12T11:00:00.000Z",
    },
    {
      id: "tx-vendor-403",
      sourceAccountId: "acc-diana-biz",
      destinationAccountId: "vendor-cloud-infrastructure",
      amount: 12500.0,
      currency: "USD",
      status: "pending",
      memo: "Monthly server cluster billing",
      timestamp: "2026-03-20T09:15:00.000Z",
    },
    {
      id: "tx-atm-501",
      sourceAccountId: "acc-bob-chk",
      destinationAccountId: "atm-metro-branch-4",
      amount: 100.0,
      currency: "USD",
      status: "completed",
      memo: "ATM Cash Withdrawal",
      timestamp: "2026-03-22T17:45:00.000Z",
    },
  ];

  for (const t of transactions) {
    insertTx.run(
      t.id,
      t.sourceAccountId,
      t.destinationAccountId,
      t.amount,
      t.currency,
      t.status,
      t.memo,
      t.timestamp
    );
  }

  // 5. Seed Audit Logs
  const insertAudit = db.prepare(`
    INSERT INTO audit_logs (id, message, level, created_at)
    VALUES (?, ?, ?, ?)
  `);

  const auditLogs = [
    {
      id: "log-001",
      message: "[2026-09-27T10:00:00Z] System integrity check executed for cluster",
      level: "info",
      createdAt: "2026-09-27T10:00:00.000Z",
    },
    {
      id: "log-002",
      message: "[2026-09-27T12:00:00Z] Automated backup archive created for database",
      level: "info",
      createdAt: "2026-09-27T12:00:00.000Z",
    },
    {
      id: "log-003",
      message: "[2026-09-27T14:15:22Z] User authentication granted for usr-alice-101",
      level: "info",
      createdAt: "2026-09-27T14:15:22.000Z",
    },
    {
      id: "log-004",
      message: "[2026-09-27T15:30:10Z] Inter-account wire transfer completed from acc-alice-chk to acc-alice-sav",
      level: "info",
      createdAt: "2026-09-27T15:30:10.000Z",
    },
    {
      id: "log-005",
      message: "[2026-09-27T16:00:00Z] Security audit scan completed with zero critical anomalies",
      level: "info",
      createdAt: "2026-09-27T16:00:00.000Z",
    },
  ];

  for (const log of auditLogs) {
    insertAudit.run(log.id, log.message, log.level, log.createdAt);
  }
}

export function resetDatabase(db: DatabaseSync): void {
  db.exec("PRAGMA foreign_keys = OFF;");
  db.exec(`
    DROP TABLE IF EXISTS audit_logs;
    DROP TABLE IF EXISTS cards;
    DROP TABLE IF EXISTS transactions;
    DROP TABLE IF EXISTS accounts;
    DROP TABLE IF EXISTS users;
  `);
  initSchema(db);
  seedDatabase(db);
}

export function createDatabase(dbPath?: string): DatabaseSync {
  const targetPath = dbPath ?? getDatabasePath();
  const db = new DatabaseSync(targetPath);
  initSchema(db);
  seedDatabase(db);
  return db;
}
