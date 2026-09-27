import { randomBytes, scryptSync, timingSafeEqual, createHmac } from "node:crypto";

export interface JwtPayload {
  sub: string;
  username: string;
  role: "customer" | "admin";
  iat: number;
  exp: number;
}

const JWT_SECRET = process.env.JWT_SECRET || "vulnbank-super-secret-jwt-key-2026";

/**
 * Hashes a plaintext password using node:crypto scrypt with a unique 16-byte cryptographic salt.
 */
export function hashPassword(password: string): { hash: string; salt: string } {
  const salt = randomBytes(16).toString("hex");
  const hash = scryptSync(password, salt, 64).toString("hex");
  return { hash, salt };
}

/**
 * Verifies a plaintext password against a stored scrypt hash and salt in constant time.
 */
export function verifyPassword(password: string, storedHash: string, salt: string): boolean {
  try {
    const computedHash = scryptSync(password, salt, 64).toString("hex");
    return timingSafeEqual(Buffer.from(computedHash, "hex"), Buffer.from(storedHash, "hex"));
  } catch {
    return false;
  }
}

/**
 * Generates an HMAC-SHA256 signed JSON Web Token (JWT) adhering to RFC 7519.
 */
export function createJwtToken(
  payload: Omit<JwtPayload, "iat" | "exp">,
  expiresInSeconds: number = 86400
): string {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const fullPayload: JwtPayload = {
    ...payload,
    iat: now,
    exp: now + expiresInSeconds,
  };

  const headerEncoded = Buffer.from(JSON.stringify(header)).toString("base64url");
  const payloadEncoded = Buffer.from(JSON.stringify(fullPayload)).toString("base64url");
  const signingInput = `${headerEncoded}.${payloadEncoded}`;

  const signature = createHmac("sha256", JWT_SECRET).update(signingInput).digest("base64url");
  return `${signingInput}.${signature}`;
}

/**
 * Verifies the cryptographic HMAC-SHA256 signature and expiration of a JWT.
 */
export function verifyJwtToken(token: string): JwtPayload | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const [headerEncoded, payloadEncoded, signature] = parts;
    const signingInput = `${headerEncoded}.${payloadEncoded}`;
    const expectedSignature = createHmac("sha256", JWT_SECRET)
      .update(signingInput)
      .digest("base64url");

    if (signature.length !== expectedSignature.length) return null;
    if (!timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature))) {
      return null;
    }

    const payload = JSON.parse(Buffer.from(payloadEncoded, "base64url").toString("utf8")) as JwtPayload;
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}
