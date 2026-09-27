-- VulnBank Core Database Schema and Initial Seed Dataset
-- Engine: SQLite 3

PRAGMA foreign_keys = OFF;

DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS cards;
DROP TABLE IF EXISTS transactions;
DROP TABLE IF EXISTS accounts;
DROP TABLE IF EXISTS users;

PRAGMA foreign_keys = ON;

-- 1. Users Table
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  role TEXT NOT NULL,
  token TEXT
);

-- 2. Accounts Table
CREATE TABLE accounts (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  account_number TEXT UNIQUE NOT NULL,
  account_type TEXT NOT NULL,
  currency TEXT NOT NULL,
  balance REAL NOT NULL,
  overdraft_limit REAL NOT NULL,
  created_at TEXT NOT NULL
);

-- 3. Transactions Table
CREATE TABLE transactions (
  id TEXT PRIMARY KEY,
  source_account_id TEXT NOT NULL,
  destination_account_id TEXT NOT NULL,
  amount REAL NOT NULL,
  currency TEXT NOT NULL,
  status TEXT NOT NULL,
  memo TEXT,
  timestamp TEXT NOT NULL
);

-- 4. Cards Table (VULNERABILITY: Plain PAN and CVV storage)
CREATE TABLE cards (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  card_type TEXT NOT NULL,
  pan TEXT NOT NULL,
  cvv TEXT NOT NULL,
  expiration TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1
);

-- 5. Audit Logs Table (VULNERABILITY: Raw SQL query target for injection)
CREATE TABLE audit_logs (
  id TEXT PRIMARY KEY,
  message TEXT NOT NULL,
  level TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-- Indexes
CREATE INDEX idx_accounts_user_id ON accounts(user_id);
CREATE INDEX idx_transactions_source ON transactions(source_account_id);
CREATE INDEX idx_transactions_dest ON transactions(destination_account_id);
CREATE INDEX idx_cards_user_id ON cards(user_id);
CREATE INDEX idx_cards_account_id ON cards(account_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);

-- ============================================================================
-- Seed Data
-- ============================================================================

-- Users: Passwords are salted scrypt hashes (node:crypto scryptSync(plain, salt, 64))
-- Alice:    password123
-- Bob:      securePass789
-- Charlie:  CharlieVance!2026
-- Diana:    EnterpriseCapital#99
-- Admin:    AdminSecret2026!
-- Auditor:  AuditReadonly2026!

INSERT INTO users (id, username, email, password_hash, salt, role, token) VALUES
  ('usr-alice-101', 'alice', 'alice@vulnbank.local', 'f4495b596dd27a0c510cb8cc119bedbbdb874c2f7028572b5d1e00da105e41e7c81447d652d75f8ba803c66810c608a0447896340de3f44187b68152f6a6315b', 'c52f044216b67a09680e78c55e4d1735', 'customer', 'vbnk_token_alice_sec_9941'),
  ('usr-bob-202', 'bob', 'bob@vulnbank.local', 'e56efb9daaf24f907fac1872cf00146f05b63d1d6ef88ced2c63efc45943536dea58c6ff3df440721fce8e72d96d1df01cc0d4eb79243c4265948c9dad47c929', 'e6270b3898eb0f9f31b6e5f8e761075c', 'customer', 'vbnk_token_bob_sec_5512'),
  ('usr-charlie-303', 'charlie', 'charlie@vulnbank.local', '916f754edcb851d366d26e26d6f424efcb9dd30986e7c0b4f2913adcea5d5bec0412654180be11beba7cc30ed5f8162ba27e9e8283a49206bb0e9ad596558990', '7266a604f9579938a72b0496f7e54e4b', 'customer', 'vbnk_token_charlie_sec_3389'),
  ('usr-diana-404', 'diana', 'diana.prince@enterprise-corp.com', 'b2a8e6f18220658f4907792b42f524d714256f93e37aabc7e96fdb834b2d1e785bf3873be769959a95a27d675ad2ec3ff2d8cf4fcfdb0d270727afb905600589', 'c31079829f4980afcd8054171be0a747', 'customer', 'vbnk_token_diana_corp_7721'),
  ('usr-admin-001', 'admin', 'admin@vulnbank.local', '286ce16dd86f926a19685b2aacb10afe95ee525aafa8e39e6e0fff73782269da40b9b153907119a81e6cb74b531822f1b003eb53e5ace978ce0c95db222c1c0d', 'bca0b6ee54a7211070df70dfbf5f50a9', 'admin', 'vbnk_token_admin_super_9999'),
  ('usr-auditor-002', 'auditor', 'compliance@vulnbank.local', 'f901aaacac4f4ba2394aab23f9a69102e7e784911984f325c547273a5326c01dd333389e376d6710721aab67cc98c433f3a1fbf6db9b9c460810b454912ed52e', '3f76a53e9dcbc02f3ef3e9983723547a', 'admin', 'vbnk_token_auditor_view_8842');

-- Accounts
INSERT INTO accounts (id, user_id, account_number, account_type, currency, balance, overdraft_limit, created_at) VALUES
  ('acc-alice-chk', 'usr-alice-101', '450912348877', 'checking', 'USD', 14500.50, 2000.0, '2026-01-10T12:00:00.000Z'),
  ('acc-alice-sav', 'usr-alice-101', '450912348899', 'savings', 'USD', 48250.00, 0.0, '2026-01-15T09:00:00.000Z'),
  ('acc-bob-chk', 'usr-bob-202', '450998761122', 'checking', 'USD', 3250.00, 500.0, '2026-02-14T09:30:00.000Z'),
  ('acc-bob-sav', 'usr-bob-202', '450998761133', 'savings', 'USD', 1540.25, 0.0, '2026-02-20T11:15:00.000Z'),
  ('acc-charlie-chk', 'usr-charlie-303', '450955443322', 'checking', 'EUR', 8920.75, 1000.0, '2026-03-01T08:00:00.000Z'),
  ('acc-diana-biz', 'usr-diana-404', '450977889900', 'checking', 'USD', 245000.00, 50000.0, '2026-03-05T14:20:00.000Z'),
  ('acc-diana-payroll', 'usr-diana-404', '450977889911', 'checking', 'USD', 85000.00, 25000.0, '2026-03-10T16:45:00.000Z');

-- Cards
INSERT INTO cards (id, account_id, user_id, card_type, pan, cvv, expiration, is_active) VALUES
  ('crd-alice-visa', 'acc-alice-chk', 'usr-alice-101', 'debit', '4532889912345678', '891', '12/28', 1),
  ('crd-alice-mc', 'acc-alice-chk', 'usr-alice-101', 'credit', '5412750098234411', '342', '08/29', 1),
  ('crd-bob-visa', 'acc-bob-chk', 'usr-bob-202', 'debit', '4532109844556677', '519', '04/27', 1),
  ('crd-charlie-debit', 'acc-charlie-chk', 'usr-charlie-303', 'debit', '4916300011223344', '773', '11/27', 1),
  ('crd-diana-corp', 'acc-diana-biz', 'usr-diana-404', 'credit', '5521400099881234', '990', '06/30', 1);

-- Transactions
INSERT INTO transactions (id, source_account_id, destination_account_id, amount, currency, status, memo, timestamp) VALUES
  ('tx-init-101', 'acc-external', 'acc-alice-chk', 14500.50, 'USD', 'completed', 'Initial payroll deposit', '2026-01-10T12:05:00.000Z'),
  ('tx-transfer-102', 'acc-alice-chk', 'acc-alice-sav', 3000.00, 'USD', 'completed', 'Automatic savings sweep', '2026-01-16T08:30:00.000Z'),
  ('tx-purchase-103', 'acc-alice-chk', 'merchant-tech-supplies', 249.99, 'USD', 'completed', 'Hardware store purchase', '2026-02-01T15:22:10.000Z'),
  ('tx-init-201', 'acc-external', 'acc-bob-chk', 3500.00, 'USD', 'completed', 'Consulting stipend', '2026-02-14T09:40:00.000Z'),
  ('tx-transfer-202', 'acc-bob-chk', 'acc-bob-sav', 250.00, 'USD', 'completed', 'Personal emergency fund', '2026-02-21T10:00:00.000Z'),
  ('tx-init-301', 'acc-external-eu', 'acc-charlie-chk', 8920.75, 'EUR', 'completed', 'SEPA wire transfer', '2026-03-01T08:15:00.000Z'),
  ('tx-corp-401', 'acc-external-treasury', 'acc-diana-biz', 250000.00, 'USD', 'completed', 'Q1 Capitalization funding', '2026-03-05T14:30:00.000Z'),
  ('tx-corp-402', 'acc-diana-biz', 'acc-diana-payroll', 5000.00, 'USD', 'completed', 'Payroll account funding transfer', '2026-03-12T11:00:00.000Z'),
  ('tx-vendor-403', 'acc-diana-biz', 'vendor-cloud-infrastructure', 12500.00, 'USD', 'pending', 'Monthly server cluster billing', '2026-03-20T09:15:00.000Z'),
  ('tx-atm-501', 'acc-bob-chk', 'atm-metro-branch-4', 100.00, 'USD', 'completed', 'ATM Cash Withdrawal', '2026-03-22T17:45:00.000Z');

-- Audit Logs
INSERT INTO audit_logs (id, message, level, created_at) VALUES
  ('log-001', '[2026-09-27T10:00:00Z] System integrity check executed for cluster', 'info', '2026-09-27T10:00:00.000Z'),
  ('log-002', '[2026-09-27T12:00:00Z] Automated backup archive created for database', 'info', '2026-09-27T12:00:00.000Z'),
  ('log-003', '[2026-09-27T14:15:22Z] User authentication granted for usr-alice-101', 'info', '2026-09-27T14:15:22.000Z'),
  ('log-004', '[2026-09-27T15:30:10Z] Inter-account wire transfer completed from acc-alice-chk to acc-alice-sav', 'info', '2026-09-27T15:30:10.000Z'),
  ('log-005', '[2026-09-27T16:00:00Z] Security audit scan completed with zero critical anomalies', 'info', '2026-09-27T16:00:00.000Z');
