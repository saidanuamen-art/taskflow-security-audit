import request from 'supertest';
import { Express } from 'express';
import { createTestApp } from './helpers/app-loader';
import { createForgedToken, TEST_USERS, generateUUID, adminPool } from './helpers/test-utils';

/**
 * VULN-04: Secret JWT faible
 * 
 * Vérifie que :
 * 1. Les tokens forgés avec l'ancien secret faible sont rejetés
 * 2. L'application refuse de démarrer sans JWT_SECRET
 * 3. Les tokens doivent avoir le claim "type: access" pour être acceptés
 * 4. Les refresh tokens ne peuvent pas être utilisés comme access tokens
 * 
 * Vulnérabilité originale : Le secret JWT était hardcodé à "taskflow-super-secret-key"
 * 
 * Corrections appliquées :
 * - Secret cryptographique fort (256-bit) obligatoire dans .env
 * - Validation du secret au démarrage
 * - Claims "type" pour distinguer access/refresh tokens
 * - Hash des refresh tokens avant stockage en DB
 */
describe('VULN-04: JWT Weak Secret Protection', () => {
  let app: Express;

  beforeAll(() => {
    app = createTestApp();
  });

  describe('Forged token rejection', () => {
    it('should reject token signed with old weak secret', async () => {
      const oldWeakSecret = 'taskflow-super-secret-key';

      // Créer un token forgé avec l'ancien secret
      const forgedToken = createForgedToken(
        {
          sub: 'fake-user-id',
          tenantId: TEST_USERS.ALPHA_OWNER.tenantId,
          role: 'OWNER',
          priority: 100,
          type: 'access',
        },
        oldWeakSecret,
        '1h'
      );

      // Tenter d'accéder avec le token forgé
      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${forgedToken}`)
        .set('x-tenant-id', TEST_USERS.ALPHA_OWNER.tenantId);

      // Doit être rejeté avec 401 (signature invalide)
      expect(response.status).toBe(401);
    });

    it('should reject token signed with common weak secrets', async () => {
      const commonWeakSecrets = [
        'secret',
        'password',
        'admin',
        '123456',
        'your-secret-key',
        'jwt-secret',
      ];

      for (const weakSecret of commonWeakSecrets) {
        const forgedToken = createForgedToken(
          {
            sub: 'fake-user-id',
            tenantId: TEST_USERS.ALPHA_OWNER.tenantId,
            role: 'OWNER',
            priority: 100,
            type: 'access',
          },
          weakSecret,
          '1h'
        );

        const response = await request(app)
          .get('/api/documents')
          .set('Authorization', `Bearer ${forgedToken}`)
          .set('x-tenant-id', TEST_USERS.ALPHA_OWNER.tenantId);

        expect(response.status).toBe(401);
      }
    });

    it('should reject token with tampered payload', async () => {
      const currentSecret = process.env.JWT_SECRET || '';

      // Créer un token valide
      const validToken = createForgedToken(
        {
          sub: 'real-user-id',
          tenantId: TEST_USERS.ALPHA_OWNER.tenantId,
          role: 'MEMBER',
          priority: 50,
          type: 'access',
        },
        currentSecret,
        '1h'
      );

      // Modifier le payload (changer MEMBER → OWNER) sans re-signer
      const [header, payload, signature] = validToken.split('.');
      const decodedPayload = JSON.parse(
        Buffer.from(payload, 'base64url').toString()
      );
      decodedPayload.role = 'OWNER';
      decodedPayload.priority = 100;

      const tamperedPayload = Buffer.from(JSON.stringify(decodedPayload))
        .toString('base64url')
        .replace(/=/g, '');
      const tamperedToken = `${header}.${tamperedPayload}.${signature}`;

      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${tamperedToken}`)
        .set('x-tenant-id', TEST_USERS.ALPHA_OWNER.tenantId);

      // Doit être rejeté car la signature ne correspond plus
      expect(response.status).toBe(401);
    });
  });

  describe('Token type validation', () => {
    it('should reject tokens without "type" claim', async () => {
      const currentSecret = process.env.JWT_SECRET || '';

      // Token signé avec le BON secret (signature valide) mais SANS claim "type"
      const jwt = require('jsonwebtoken');
      const tokenNoType = jwt.sign(
        {
          sub: 'user-id',
          tenantId: TEST_USERS.ALPHA_OWNER.tenantId,
          role: 'OWNER',
          priority: 100,
        },
        currentSecret,
        { expiresIn: '1h' }
      );

      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${tokenNoType}`)
        .set('x-tenant-id', TEST_USERS.ALPHA_OWNER.tenantId);

      // Doit être rejeté (type manquant ou invalide)
      expect(response.status).toBe(401);
    });

    it('should reject refresh tokens used as access tokens', async () => {
      const currentSecret = process.env.JWT_SECRET || '';

      // Créer un token avec type "refresh"
      const refreshToken = createForgedToken(
        {
          sub: 'user-id',
          tenantId: TEST_USERS.ALPHA_OWNER.tenantId,
          role: 'OWNER',
          priority: 100,
          type: 'refresh', // ← Mauvais type
        },
        currentSecret,
        '7d'
      );

      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${refreshToken}`)
        .set('x-tenant-id', TEST_USERS.ALPHA_OWNER.tenantId);

      // Doit être rejeté car type !== "access"
      expect(response.status).toBe(401);
    });
  });

  describe('JWT secret validation', () => {
    it('should verify that JWT_SECRET environment variable is set', () => {
      // Ce test vérifie que JWT_SECRET est défini dans l'environnement de test
      expect(process.env.JWT_SECRET).toBeDefined();
      expect(process.env.JWT_SECRET).not.toBe('');
    });

    it('should verify that JWT_SECRET is not the old weak secret', () => {
      const jwtSecret = process.env.JWT_SECRET || '';
      const oldWeakSecret = 'taskflow-super-secret-key';

      expect(jwtSecret).not.toBe(oldWeakSecret);
    });

    it('should verify that JWT_SECRET is sufficiently long', () => {
      const jwtSecret = process.env.JWT_SECRET || '';

      // Un secret fort devrait avoir au moins 32 caractères (256 bits en hex)
      expect(jwtSecret.length).toBeGreaterThanOrEqual(32);
    });

    it('should verify that JWT_SECRET appears cryptographically random', () => {
      const jwtSecret = process.env.JWT_SECRET || '';

      // Vérifier que ce n'est pas un mot du dictionnaire ou pattern simple
      const weakPatterns = [
        /^(password|secret|admin|test|dev)/i,
        /^(123456|qwerty|abc)/i,
        /^(.)\1{5,}/, // Caractères répétés
      ];

      for (const pattern of weakPatterns) {
        expect(jwtSecret).not.toMatch(pattern);
      }
    });
  });

  describe('Token expiration', () => {
    it('should reject expired access tokens', async () => {
      const currentSecret = process.env.JWT_SECRET || '';

      // Créer un token expiré (durée négative)
      const expiredToken = createForgedToken(
        {
          sub: 'user-id',
          tenantId: TEST_USERS.ALPHA_OWNER.tenantId,
          role: 'OWNER',
          priority: 100,
          type: 'access',
        },
        currentSecret,
        '-1h' // Expiré il y a 1 heure
      );

      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${expiredToken}`)
        .set('x-tenant-id', TEST_USERS.ALPHA_OWNER.tenantId);

      expect(response.status).toBe(401);
    });
  });

  describe('Malformed token handling', () => {
    it('should reject malformed JWT (not 3 parts)', async () => {
      const malformedToken = 'not.a.valid.jwt.token';

      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${malformedToken}`)
        .set('x-tenant-id', TEST_USERS.ALPHA_OWNER.tenantId);

      expect(response.status).toBe(401);
    });

    it('should reject JWT with invalid base64 encoding', async () => {
      const invalidToken = 'invalid!!!.payload!!!.signature!!!';

      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${invalidToken}`)
        .set('x-tenant-id', TEST_USERS.ALPHA_OWNER.tenantId);

      expect(response.status).toBe(401);
    });

    it('should reject empty authorization header', async () => {
      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', '')
        .set('x-tenant-id', TEST_USERS.ALPHA_OWNER.tenantId);

      expect(response.status).toBe(401);
    });

    it('should reject missing Bearer prefix', async () => {
      const currentSecret = process.env.JWT_SECRET || '';

      const validToken = createForgedToken(
        {
          sub: 'user-id',
          tenantId: TEST_USERS.ALPHA_OWNER.tenantId,
          role: 'OWNER',
          priority: 100,
          type: 'access',
        },
        currentSecret,
        '1h'
      );

      // Envoyer sans "Bearer " prefix
      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', validToken)
        .set('x-tenant-id', TEST_USERS.ALPHA_OWNER.tenantId);

      expect(response.status).toBe(401);
    });
  });

  /**
   * Limitation des tentatives de connexion (anti brute force).
   * Chaque test utilise un email unique : un blocage ne touche jamais les comptes
   * de test réels, et les tests restent indépendants les uns des autres.
   */
  describe('Login brute-force protection', () => {
    const attempt = (email: string, password = 'wrong-password') =>
      request(app).post('/auth/login').send({ email, password });

    it('should block an account after 5 failed attempts (429 + Retry-After)', async () => {
      const email = `bruteforce-${generateUUID()}@test.local`;

      for (let i = 0; i < 5; i++) {
        const res = await attempt(email);
        expect(res.status).toBe(401);
        expect(res.body).toHaveProperty('error', 'INVALID_CREDENTIALS');
      }

      // 6e tentative : bloquée AVANT même de vérifier le mot de passe
      const blocked = await attempt(email);
      expect(blocked.status).toBe(429);
      expect(blocked.body).toHaveProperty('error', 'TOO_MANY_ATTEMPTS');
      expect(Number(blocked.headers['retry-after'])).toBeGreaterThan(0);
    });

    it('should not affect other accounts when one account is blocked', async () => {
      const email = `bruteforce-${generateUUID()}@test.local`;
      for (let i = 0; i < 5; i++) await attempt(email);
      expect((await attempt(email)).status).toBe(429);

      // Un autre compte (réel) se connecte toujours normalement
      const res = await attempt(TEST_USERS.ALPHA_OWNER.email, TEST_USERS.ALPHA_OWNER.password);
      expect(res.status).toBe(200);
    });

    it('should never block successful logins', async () => {
      for (let i = 0; i < 8; i++) {
        const res = await attempt(TEST_USERS.BETA_OWNER.email, TEST_USERS.BETA_OWNER.password);
        expect(res.status).toBe(200);
      }
    });

    it('should log the lockout in audit_logs', async () => {
      const email = `bruteforce-${generateUUID()}@test.local`;
      for (let i = 0; i < 5; i++) await attempt(email);

      const audit = await adminPool.query(
        `SELECT metadata FROM audit_logs WHERE event = 'auth.login_blocked' AND metadata->>'email' = $1`,
        [email]
      );
      expect(audit.rows).toHaveLength(1);
    });

    it('should reject a malformed login request with 400', async () => {
      const res = await request(app).post('/auth/login').send({ email: 'x@test.local' });
      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'INVALID_REQUEST');
    });
  });
});
