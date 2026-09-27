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

    // 1. Seed Users
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

    const charlie: User = {
      id: "usr-charlie-303",
      username: "charlie",
      email: "charlie@vulnbank.local",
      passwordHash: "CharlieVance!2026",
      role: "customer",
      token: "vbnk_token_charlie_sec_3389",
    };

    const diana: User = {
      id: "usr-diana-404",
      username: "diana",
      email: "diana.prince@enterprise-corp.com",
      passwordHash: "EnterpriseCapital#99",
      role: "customer",
      token: "vbnk_token_diana_corp_7721",
    };

    const admin: User = {
      id: "usr-admin-001",
      username: "admin",
      email: "admin@vulnbank.local",
      passwordHash: "AdminSecret2026!",
      role: "admin",
      token: "vbnk_token_admin_super_9999",
    };

    const auditor: User = {
      id: "usr-auditor-002",
      username: "auditor",
      email: "compliance@vulnbank.local",
      passwordHash: "AuditReadonly2026!",
      role: "admin",
      token: "vbnk_token_auditor_view_8842",
    };

    this.users.set(alice.id, alice);
    this.users.set(bob.id, bob);
    this.users.set(charlie.id, charlie);
    this.users.set(diana.id, diana);
    this.users.set(admin.id, admin);
    this.users.set(auditor.id, auditor);

    // 2. Seed Bank Accounts
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

    const aliceSavings: BankAccount = {
      id: "acc-alice-sav",
      userId: alice.id,
      accountNumber: "450912348899",
      accountType: "savings",
      currency: "USD",
      balance: 48250.0,
      overdraftLimit: 0,
      createdAt: "2026-01-15T09:00:00.000Z",
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

    const bobSavings: BankAccount = {
      id: "acc-bob-sav",
      userId: bob.id,
      accountNumber: "450998761133",
      accountType: "savings",
      currency: "USD",
      balance: 1540.25,
      overdraftLimit: 0,
      createdAt: "2026-02-20T11:15:00.000Z",
    };

    const charlieChecking: BankAccount = {
      id: "acc-charlie-chk",
      userId: charlie.id,
      accountNumber: "450955443322",
      accountType: "checking",
      currency: "EUR",
      balance: 8920.75,
      overdraftLimit: 1000,
      createdAt: "2026-03-01T08:00:00.000Z",
    };

    const dianaCorporate: BankAccount = {
      id: "acc-diana-biz",
      userId: diana.id,
      accountNumber: "450977889900",
      accountType: "checking",
      currency: "USD",
      balance: 245000.0,
      overdraftLimit: 50000,
      createdAt: "2026-03-05T14:20:00.000Z",
    };

    const dianaPayroll: BankAccount = {
      id: "acc-diana-payroll",
      userId: diana.id,
      accountNumber: "450977889911",
      accountType: "checking",
      currency: "USD",
      balance: 85000.0,
      overdraftLimit: 25000,
      createdAt: "2026-03-10T16:45:00.000Z",
    };

    this.accounts.set(aliceChecking.id, aliceChecking);
    this.accounts.set(aliceSavings.id, aliceSavings);
    this.accounts.set(bobChecking.id, bobChecking);
    this.accounts.set(bobSavings.id, bobSavings);
    this.accounts.set(charlieChecking.id, charlieChecking);
    this.accounts.set(dianaCorporate.id, dianaCorporate);
    this.accounts.set(dianaPayroll.id, dianaPayroll);

    // 3. Seed Cards
    const aliceCardVisa: Card = {
      id: "crd-alice-visa",
      accountId: aliceChecking.id,
      userId: alice.id,
      cardType: "debit",
      pan: "4532889912345678",
      cvv: "891",
      expiration: "12/28",
      isActive: true,
    };

    const aliceCardMC: Card = {
      id: "crd-alice-mc",
      accountId: aliceChecking.id,
      userId: alice.id,
      cardType: "credit",
      pan: "5412750098234411",
      cvv: "342",
      expiration: "08/29",
      isActive: true,
    };

    const bobCardVisa: Card = {
      id: "crd-bob-visa",
      accountId: bobChecking.id,
      userId: bob.id,
      cardType: "debit",
      pan: "4532109844556677",
      cvv: "519",
      expiration: "04/27",
      isActive: true,
    };

    const charlieCardDebit: Card = {
      id: "crd-charlie-debit",
      accountId: charlieChecking.id,
      userId: charlie.id,
      cardType: "debit",
      pan: "4916300011223344",
      cvv: "773",
      expiration: "11/27",
      isActive: true,
    };

    const dianaCardCorp: Card = {
      id: "crd-diana-corp",
      accountId: dianaCorporate.id,
      userId: diana.id,
      cardType: "credit",
      pan: "5521400099881234",
      cvv: "990",
      expiration: "06/30",
      isActive: true,
    };

    this.cards.set(aliceCardVisa.id, aliceCardVisa);
    this.cards.set(aliceCardMC.id, aliceCardMC);
    this.cards.set(bobCardVisa.id, bobCardVisa);
    this.cards.set(charlieCardDebit.id, charlieCardDebit);
    this.cards.set(dianaCardCorp.id, dianaCardCorp);

    // 4. Seed Diverse Transactions
    this.transactions.push(
      {
        id: "tx-init-101",
        sourceAccountId: "acc-external",
        destinationAccountId: aliceChecking.id,
        amount: 14500.5,
        currency: "USD",
        status: "completed",
        memo: "Initial payroll deposit",
        timestamp: "2026-01-10T12:05:00.000Z",
      },
      {
        id: "tx-transfer-102",
        sourceAccountId: aliceChecking.id,
        destinationAccountId: aliceSavings.id,
        amount: 3000.0,
        currency: "USD",
        status: "completed",
        memo: "Automatic savings sweep",
        timestamp: "2026-01-16T08:30:00.000Z",
      },
      {
        id: "tx-purchase-103",
        sourceAccountId: aliceChecking.id,
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
        destinationAccountId: bobChecking.id,
        amount: 3500.0,
        currency: "USD",
        status: "completed",
        memo: "Consulting stipend",
        timestamp: "2026-02-14T09:40:00.000Z",
      },
      {
        id: "tx-transfer-202",
        sourceAccountId: bobChecking.id,
        destinationAccountId: bobSavings.id,
        amount: 250.0,
        currency: "USD",
        status: "completed",
        memo: "Personal emergency fund",
        timestamp: "2026-02-21T10:00:00.000Z",
      },
      {
        id: "tx-init-301",
        sourceAccountId: "acc-external-eu",
        destinationAccountId: charlieChecking.id,
        amount: 8920.75,
        currency: "EUR",
        status: "completed",
        memo: "SEPA wire transfer",
        timestamp: "2026-03-01T08:15:00.000Z",
      },
      {
        id: "tx-corp-401",
        sourceAccountId: "acc-external-treasury",
        destinationAccountId: dianaCorporate.id,
        amount: 250000.0,
        currency: "USD",
        status: "completed",
        memo: "Q1 Capitalization funding",
        timestamp: "2026-03-05T14:30:00.000Z",
      },
      {
        id: "tx-corp-402",
        sourceAccountId: dianaCorporate.id,
        destinationAccountId: dianaPayroll.id,
        amount: 5000.0,
        currency: "USD",
        status: "completed",
        memo: "Payroll account funding transfer",
        timestamp: "2026-03-12T11:00:00.000Z",
      },
      {
        id: "tx-vendor-403",
        sourceAccountId: dianaCorporate.id,
        destinationAccountId: "vendor-cloud-infrastructure",
        amount: 12500.0,
        currency: "USD",
        status: "pending",
        memo: "Monthly server cluster billing",
        timestamp: "2026-03-20T09:15:00.000Z",
      },
      {
        id: "tx-atm-501",
        sourceAccountId: bobChecking.id,
        destinationAccountId: "atm-metro-branch-4",
        amount: 100.0,
        currency: "USD",
        status: "completed",
        memo: "ATM Cash Withdrawal",
        timestamp: "2026-03-22T17:45:00.000Z",
      }
    );
  }

  public getUserByToken(token: string): User | undefined {
    return Array.from(this.users.values()).find((u) => u.token === token);
  }
}

export const store = new BankDataStore();
