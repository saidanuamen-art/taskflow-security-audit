import jwt from 'jsonwebtoken';
import request from 'supertest';
import { Express } from 'express';
import { Pool, PoolClient } from 'pg';
import { pool } from '../../src/common/db';

/**
 * Connexion ADMIN (rôle `taskflow`, superutilisateur, non soumis au RLS).
 * Sert uniquement à préparer la base et à lire la « vérité » de référence.
 * Le comportement testé, lui, passe par `pool` (rôle `taskflow_app`, soumis au RLS).
 */
export const adminPool = new Pool({ connectionString: process.env.ADMIN_DATABASE_URL });

/**
 * Identifiants de test pré-configurés dans db/init.sql
 */
export const TEST_USERS = {
  ALPHA_OWNER: {
    email: 'owner@alpha.test',
    password: 'Password123!',
    tenantId: '11111111-1111-1111-1111-111111111111',
    role: 'OWNER',
    priority: 100,
  },
  ALPHA_MEMBER: {
    email: 'member@alpha.test',
    password: 'Password123!',
    tenantId: '11111111-1111-1111-1111-111111111111',
    role: 'MEMBER',
    priority: 50,
  },
  BETA_OWNER: {
    email: 'owner@beta.test',
    password: 'Password123!',
    tenantId: '22222222-2222-2222-2222-222222222222',
    role: 'OWNER',
    priority: 100,
  },
  BETA_MEMBER: {
    email: 'member@beta.test',
    password: 'Password123!',
    tenantId: '22222222-2222-2222-2222-222222222222',
    role: 'MEMBER',
    priority: 50,
  },
};

export interface LoginResponse {
  accessToken: string;
  refreshToken: string;
}

export interface AuthenticatedUser {
  email: string;
  accessToken: string;
  tenantId: string;
  role: string;
  userId?: string;
}

/**
 * Authentifie un utilisateur et retourne son token
 */
export async function loginAsUser(
  app: Express,
  userConfig: typeof TEST_USERS[keyof typeof TEST_USERS]
): Promise<AuthenticatedUser> {
  const response = await request(app)
    .post('/auth/login')
    .send({
      email: userConfig.email,
      password: userConfig.password,
    })
    .expect(200);

  const { accessToken } = response.body as LoginResponse;

  // Décoder le token pour obtenir le userId
  const decoded = jwt.decode(accessToken) as any;

  return {
    email: userConfig.email,
    accessToken,
    tenantId: userConfig.tenantId,
    role: userConfig.role,
    userId: decoded?.sub,
  };
}

/**
 * Crée un token JWT forgé avec un secret personnalisé
 * (utilisé pour tester VULN-04)
 */
export function createForgedToken(
  payload: {
    sub: string;
    tenantId: string;
    role: string;
    priority: number;
    type: string;
  },
  secret: string,
  expiresIn: string | number = '1h'
): string {
  const jwt = require('jsonwebtoken');
  return jwt.sign(payload, secret, { expiresIn });
}

/**
 * Attend un peu (utile pour les tests de timing)
 */
export function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Extrait le userId d'un token JWT
 */
export function extractUserIdFromToken(token: string): string {
  const decoded = jwt.decode(token) as any;
  return decoded?.sub || '';
}

/**
 * Remet les rôles d'origine de db/init.sql (owner@* = OWNER, member@* = MEMBER).
 * Indispensable pour les tests qui modifient des rôles : sans ça, un test qui
 * promeut un MEMBER fausse tous les tests suivants (et les lancements futurs).
 */
export async function resetSeedRoles(): Promise<void> {
  await adminPool.query(`
    UPDATE users u SET role_id = r.id FROM roles r
    WHERE (u.email LIKE 'owner@%.test'  AND r.name = 'OWNER')
       OR (u.email LIKE 'member@%.test' AND r.name = 'MEMBER')`);
}

/**
 * Rôle actuel d'un utilisateur, lu directement en base (source de vérité).
 */
export async function getUserRole(email: string): Promise<string> {
  const result = await adminPool.query(
    `SELECT r.name FROM users u JOIN roles r ON r.id = u.role_id WHERE u.email = $1`,
    [email]
  );
  return result.rows[0]?.name;
}

/**
 * Exécute des requêtes SQL avec le rôle APPLICATIF, dans le contexte RLS d'un tenant
 * (comme le fait tenantMiddleware). Le tenant est fixé pour la transaction uniquement.
 */
export async function withTenant<T>(tenantId: string, fn: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SELECT set_config('app.current_tenant_id', $1, true)`, [tenantId]);
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Ids des documents d'un tenant, lus directement en base sans passer par l'API.
 * Permet de comparer ce que l'API renvoie à ce qui existe réellement.
 */
export async function getDocumentIdsInDb(tenantId: string): Promise<string[]> {
  const result = await adminPool.query(`SELECT id FROM documents WHERE tenant_id = $1`, [tenantId]);
  return result.rows.map((row) => row.id);
}

/**
 * Supprime les documents créés pendant un test, pour ne pas polluer la base de dev.
 */
export async function deleteDocuments(tenantId: string, ids: string[]): Promise<void> {
  if (ids.length === 0) return;
  await withTenant(tenantId, (client) =>
    client.query(`DELETE FROM documents WHERE id = ANY($1::uuid[])`, [ids])
  );
}

/**
 * Génère un UUID v4 aléatoire pour les tests
 */
export function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}
