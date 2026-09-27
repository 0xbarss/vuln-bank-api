import { buildServer } from "./server.js";

const PORT = Number(process.env.PORT) || 4000;
const HOST = process.env.HOST || "0.0.0.0";

async function start() {
  const app = buildServer();
  try {
    const address = await app.listen({ port: PORT, host: HOST });
    console.log(`VulnBank Core API Sandbox is running at: ${address}`);
    console.log(`OpenAPI 3.0 specification available at: ${address}/openapi.json`);
  } catch (err) {
    console.error("Failed to start VulnBank Sandbox:", err);
    process.exit(1);
  }
}

void start();
