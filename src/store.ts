import { DatabaseSync } from "node:sqlite";
import { createDatabase, resetDatabase } from "./db.js";

export interface User {
  id: string;
  username: string;
  email: string;
  passwordHash: string;
  salt: string;
  role: "customer" | "admin";
  token: string;
}

export interface BankAccount {
  id: string;
  userId: string;
  accountNumber: string;
  accountType: "checking" | "savings";
  currency: string;
  balance: number;
  overdraftLimit: number;
  createdAt: string;
}

export interface Transaction {
  id: string;
  sourceAccountId: string;
  destinationAccountId: string;
  amount: number;
  currency: string;
  status: string;
  memo?: string;
  timestamp: string;
}

export interface Card {
  id: string;
  accountId: string;
  userId: string;
  cardType: "debit" | "credit";
  pan: string;
  cvv: string;
  expiration: string;
  isActive: boolean;
}

export interface AuditLog {
  id: string;
  message: string;
  level: string;
  createdAt: string;
}

export class BankDataStore {
  public db: DatabaseSync;

  constructor(db?: DatabaseSync) {
    this.db = db ?? createDatabase();
  }

  public reset(): void {
    resetDatabase(this.db);
  }

  // --- Users ---
  public getUserById(id: string): User | undefined {
    const row = this.db.prepare("SELECT * FROM users WHERE id = ?").get(id) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    return this.mapUser(row);
  }

  public getUserByUsername(username: string): User | undefined {
    const row = this.db.prepare("SELECT * FROM users WHERE username = ?").get(username) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    return this.mapUser(row);
  }

  public getUserByToken(token: string): User | undefined {
    const row = this.db.prepare("SELECT * FROM users WHERE token = ?").get(token) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    return this.mapUser(row);
  }

  public createUser(user: User): void {
    this.db.prepare(`
      INSERT INTO users (id, username, email, password_hash, salt, role, token)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(user.id, user.username, user.email, user.passwordHash, user.salt, user.role, user.token);
  }

  public listUsers(): User[] {
    const rows = this.db.prepare("SELECT * FROM users").all() as Record<string, unknown>[];
    return rows.map((r) => this.mapUser(r));
  }

  // --- Accounts ---
  public getAccountById(id: string): BankAccount | undefined {
    const row = this.db.prepare("SELECT * FROM accounts WHERE id = ?").get(id) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    return this.mapAccount(row);
  }

  public listAccountsByUserId(userId: string): BankAccount[] {
    const rows = this.db.prepare("SELECT * FROM accounts WHERE user_id = ?").all(userId) as Record<string, unknown>[];
    return rows.map((r) => this.mapAccount(r));
  }

  public createAccount(account: BankAccount): void {
    this.db.prepare(`
      INSERT INTO accounts (id, user_id, account_number, account_type, currency, balance, overdraft_limit, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      account.id,
      account.userId,
      account.accountNumber,
      account.accountType,
      account.currency,
      account.balance,
      account.overdraftLimit,
      account.createdAt
    );
  }

  public updateAccountBalance(id: string, balance?: number, overdraftLimit?: number): BankAccount | undefined {
    const current = this.getAccountById(id);
    if (!current) return undefined;
    const newBalance = typeof balance === "number" ? balance : current.balance;
    const newOverdraft = typeof overdraftLimit === "number" ? overdraftLimit : current.overdraftLimit;
    this.db.prepare(`
      UPDATE accounts SET balance = ?, overdraft_limit = ? WHERE id = ?
    `).run(newBalance, newOverdraft, id);
    return this.getAccountById(id);
  }

  // --- Cards ---
  public listCardsByUserId(userId: string): Card[] {
    const rows = this.db.prepare("SELECT * FROM cards WHERE user_id = ?").all(userId) as Record<string, unknown>[];
    return rows.map((r) => this.mapCard(r));
  }

  public createCard(card: Card): void {
    this.db.prepare(`
      INSERT INTO cards (id, account_id, user_id, card_type, pan, cvv, expiration, is_active)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      card.id,
      card.accountId,
      card.userId,
      card.cardType,
      card.pan,
      card.cvv,
      card.expiration,
      card.isActive ? 1 : 0
    );
  }

  // --- Transactions ---
  public createTransaction(tx: Transaction): void {
    this.db.prepare(`
      INSERT INTO transactions (id, source_account_id, destination_account_id, amount, currency, status, memo, timestamp)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      tx.id,
      tx.sourceAccountId,
      tx.destinationAccountId,
      tx.amount,
      tx.currency,
      tx.status,
      tx.memo ?? null,
      tx.timestamp
    );
  }

  public listTransactions(accountId?: string, limit: number = 20): Transaction[] {
    let rows: Record<string, unknown>[];
    if (accountId) {
      rows = this.db.prepare(`
        SELECT * FROM transactions
        WHERE source_account_id = ? OR destination_account_id = ?
        ORDER BY timestamp DESC
        LIMIT ?
      `).all(accountId, accountId, limit) as Record<string, unknown>[];
    } else {
      rows = this.db.prepare(`
        SELECT * FROM transactions
        ORDER BY timestamp DESC
        LIMIT ?
      `).all(limit) as Record<string, unknown>[];
    }
    return rows.map((r) => this.mapTransaction(r));
  }

  public getTransactionsCount(): number {
    const row = this.db.prepare("SELECT count(*) as cnt FROM transactions").get() as { cnt: number };
    return row.cnt;
  }

  // --- Audit Search (Raw SQL execution for authentic SQL injection signal) ---
  public searchAuditLogs(query: string): string[] {
    const sql = `SELECT * FROM audit_logs WHERE (message LIKE '%${query}%') AND level = 'info'`;
    const rows = this.db.prepare(sql).all() as Array<{ message: string }>;
    return rows.map((r) => r.message);
  }

  // --- Backward Compatibility Proxies ---
  public get users() {
    return {
      set: (_id: string, user: User) => this.createUser(user),
      get: (id: string) => this.getUserById(id),
      values: () => {
        const rows = this.db.prepare("SELECT * FROM users").all() as Record<string, unknown>[];
        return rows.map((r) => this.mapUser(r))[Symbol.iterator]();
      },
    };
  }

  public get accounts() {
    return {
      set: (_id: string, account: BankAccount) => this.createAccount(account),
      get: (id: string) => this.getAccountById(id),
      values: () => {
        const rows = this.db.prepare("SELECT * FROM accounts").all() as Record<string, unknown>[];
        return rows.map((r) => this.mapAccount(r))[Symbol.iterator]();
      },
    };
  }

  public get cards() {
    return {
      set: (_id: string, card: Card) => this.createCard(card),
      values: () => {
        const rows = this.db.prepare("SELECT * FROM cards").all() as Record<string, unknown>[];
        return rows.map((r) => this.mapCard(r))[Symbol.iterator]();
      },
    };
  }

  public get transactions(): Transaction[] & { push: (tx: Transaction) => number } {
    const all = this.listTransactions(undefined, 1000);
    return Object.assign(all, {
      push: (tx: Transaction) => {
        this.createTransaction(tx);
        return 1;
      },
    });
  }

  private mapUser(row: Record<string, unknown>): User {
    return {
      id: String(row.id),
      username: String(row.username),
      email: String(row.email),
      passwordHash: String(row.password_hash),
      salt: String(row.salt),
      role: row.role as "customer" | "admin",
      token: String(row.token ?? ""),
    };
  }

  private mapAccount(row: Record<string, unknown>): BankAccount {
    return {
      id: String(row.id),
      userId: String(row.user_id),
      accountNumber: String(row.account_number),
      accountType: row.account_type as "checking" | "savings",
      currency: String(row.currency),
      balance: Number(row.balance),
      overdraftLimit: Number(row.overdraft_limit),
      createdAt: String(row.created_at),
    };
  }

  private mapCard(row: Record<string, unknown>): Card {
    return {
      id: String(row.id),
      accountId: String(row.account_id),
      userId: String(row.user_id),
      cardType: row.card_type as "debit" | "credit",
      pan: String(row.pan),
      cvv: String(row.cvv),
      expiration: String(row.expiration),
      isActive: Boolean(row.is_active),
    };
  }

  private mapTransaction(row: Record<string, unknown>): Transaction {
    return {
      id: String(row.id),
      sourceAccountId: String(row.source_account_id),
      destinationAccountId: String(row.destination_account_id),
      amount: Number(row.amount),
      currency: String(row.currency),
      status: String(row.status),
      memo: row.memo ? String(row.memo) : undefined,
      timestamp: String(row.timestamp),
    };
  }
}

export const store = new BankDataStore();
