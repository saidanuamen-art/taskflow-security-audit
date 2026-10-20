import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { pool } from "../common/db";

// ATTENTION : secret JWT en dur pour simplifier le playground.
// (voir docs/sujet_stage_playground.md — c'est un des points à challenger)
const JWT_SECRET = process.env.JWT_SECRET as string;
if (!JWT_SECRET || JWT_SECRET.length === 0) {
  throw new Error("JWT_SECRET environment variable is required but not set");
}

const ACCESS_TOKEN_TTL = "15m";
const REFRESH_TOKEN_TTL_DAYS = 7;

export async function login(email: string, password: string) {
  // Au login, le tenant n'est pas encore connu : la policy RLS de `users` ne
  // laisserait rien passer. La recherche passe donc par une fonction SECURITY
  // DEFINER dédiée (db/init.sql), limitée à cette seule requête par email.
  const result = await pool.query(
    `SELECT id, tenant_id, password_hash, role_name, priority FROM auth_find_user_by_email($1)`,
    [email]
  );

  const user = result.rows[0];
  if (!user) throw new Error("INVALID_CREDENTIALS");

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) throw new Error("INVALID_CREDENTIALS");

  const accessToken = jwt.sign(
    { 
      sub: user.id, 
      tenantId: user.tenant_id, 
      role: user.role_name, 
      priority: user.priority,
      type: "access"
    },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_TTL }
  );

  const refreshToken = jwt.sign(
    { sub: user.id, type: "refresh" },
    JWT_SECRET,
    {
      expiresIn: `${REFRESH_TOKEN_TTL_DAYS}d`,
    }
  );

  const tokenHash = await bcrypt.hash(refreshToken, 10);
  await pool.query(
    `INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
     VALUES ($1, $2, now() + interval '${REFRESH_TOKEN_TTL_DAYS} days')`,
    [user.id, tokenHash]
  );

  return { accessToken, refreshToken };
}

export function verifyAccessToken(token: string) {
  const payload = jwt.verify(token, JWT_SECRET) as {
    sub: string;
    tenantId: string;
    role: string;
    priority: number;
    type: string;
  };
  
  if (payload.type !== "access") {
    throw new Error("Invalid token type - access token required");
  }
  
  return payload;
}
