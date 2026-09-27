export interface User {
  id: string;
  username: string;
  email: string;
  passwordHash: string;
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

export class BankDataStore {
  public users: Map<string, User> = new Map();
  public accounts: Map<string, BankAccount> = new Map();
  public transactions: Transaction[] = [];
  public cards: Map<string, Card> = new Map();

  constructor() {
    this.reset();
  }

  public reset(): void {
    this.users.clear();
    this.accounts.clear();
    this.transactions = [];
    this.cards.clear();

    // Seed Users
    const alice: User = {
      id: "usr-alice-101",
      username: "alice",
      email: "alice@vulnbank.local",
      passwordHash: "password123",
      role: "customer",
      token: "vbnk_token_alice_sec_9941",
    };

    const bob: User = {
      id: "usr-bob-202",
      username: "bob",
      email: "bob@vulnbank.local",
      passwordHash: "securePass789",
      role: "customer",
      token: "vbnk_token_bob_sec_5512",
    };

    const admin: User = {
      id: "usr-admin-001",
      username: "admin",
      email: "admin@vulnbank.local",
      passwordHash: "AdminSecret2026!",
      role: "admin",
      token: "vbnk_token_admin_super_9999",
    };

    this.users.set(alice.id, alice);
    this.users.set(bob.id, bob);
    this.users.set(admin.id, admin);

    // Seed Accounts
    const aliceChecking: BankAccount = {
      id: "acc-alice-chk",
      userId: alice.id,
      accountNumber: "450912348877",
      accountType: "checking",
      currency: "USD",
      balance: 14500.5,
      overdraftLimit: 2000,
      createdAt: "2026-01-10T12:00:00.000Z",
    };

    const bobChecking: BankAccount = {
      id: "acc-bob-chk",
      userId: bob.id,
      accountNumber: "450998761122",
      accountType: "checking",
      currency: "USD",
      balance: 3250.0,
      overdraftLimit: 500,
      createdAt: "2026-02-14T09:30:00.000Z",
    };

    this.accounts.set(aliceChecking.id, aliceChecking);
    this.accounts.set(bobChecking.id, bobChecking);

    // Seed Cards
    const aliceCard: Card = {
      id: "crd-alice-visa",
      accountId: aliceChecking.id,
      userId: alice.id,
      cardType: "debit",
      pan: "4532889912345678",
      cvv: "891",
      expiration: "12/28",
      isActive: true,
    };

    this.cards.set(aliceCard.id, aliceCard);

    // Seed Transactions
    this.transactions.push({
      id: "tx-init-101",
      sourceAccountId: "acc-external",
      destinationAccountId: aliceChecking.id,
      amount: 14500.5,
      currency: "USD",
      status: "completed",
      memo: "Initial payroll deposit",
      timestamp: "2026-01-10T12:05:00.000Z",
    });
  }

  public getUserByToken(token: string): User | undefined {
    return Array.from(this.users.values()).find((u) => u.token === token);
  }
}

export const store = new BankDataStore();
