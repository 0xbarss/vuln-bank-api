import { getDatabasePath, createDatabase, resetDatabase } from "./db.js";

export function runSeed(): void {
  const dbPath = getDatabasePath();
  console.log(`[VulnBank Seed] Initializing SQLite database at: ${dbPath}`);

  const db = createDatabase(dbPath);
  resetDatabase(db);

  const userCount = (db.prepare("SELECT count(*) as cnt FROM users").get() as { cnt: number }).cnt;
  const accountCount = (db.prepare("SELECT count(*) as cnt FROM accounts").get() as { cnt: number }).cnt;
  const cardCount = (db.prepare("SELECT count(*) as cnt FROM cards").get() as { cnt: number }).cnt;
  const txCount = (db.prepare("SELECT count(*) as cnt FROM transactions").get() as { cnt: number }).cnt;
  const auditCount = (db.prepare("SELECT count(*) as cnt FROM audit_logs").get() as { cnt: number }).cnt;

  console.log(`[VulnBank Seed] Database successfully seeded:`);
  console.log(`  - Users:        ${userCount}`);
  console.log(`  - Accounts:     ${accountCount}`);
  console.log(`  - Cards:        ${cardCount}`);
  console.log(`  - Transactions: ${txCount}`);
  console.log(`  - Audit Logs:   ${auditCount}`);
}

// Auto-run if executed directly
if (process.argv[1]?.endsWith("seed.js") || process.argv[1]?.endsWith("seed.ts")) {
  runSeed();
}
