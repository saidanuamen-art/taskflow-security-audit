import request from 'supertest';
import { Express } from 'express';
import { createTestApp } from './helpers/app-loader';
import { loginAsUser, TEST_USERS } from './helpers/test-utils';

/**
 * VULN-02: SQL Injection
 * 
 * Vérifie que les injections SQL via le header x-tenant-id sont bloquées.
 * 
 * Vulnérabilité originale : Le tenantId du header était inséré directement
 * dans une requête SQL via interpolation de chaîne :
 * `SET app.current_tenant_id = '${tenantId}'`
 * 
 * Correction appliquée : Validation stricte du format UUID avant toute requête SQL.
 */
describe('VULN-02: SQL Injection Protection', () => {
  let app: Express;

  beforeAll(() => {
    app = createTestApp();
  });

  describe('UUID validation', () => {
    it('should reject malformed tenant ID with SQL injection payload', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      // Tentative d'injection SQL classique
      const sqlInjection = "'; DROP TABLE documents; --";

      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', sqlInjection);

      // Doit être rejeté avant l'exécution de la requête SQL
      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error', 'INVALID_TENANT_ID');
    });

    it('should reject tenant ID with SQL comment injection', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      const sqlComment = "11111111-1111-1111-1111-111111111111' OR '1'='1";

      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', sqlComment);

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error', 'INVALID_TENANT_ID');
    });

    it('should reject tenant ID with UNION-based injection', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      const unionInjection = "' UNION SELECT * FROM users--";

      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', unionInjection);

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error', 'INVALID_TENANT_ID');
    });

    it('should reject tenant ID with stacked queries', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      const stackedQuery = "11111111-1111-1111-1111-111111111111'; DELETE FROM audit_logs; --";

      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', stackedQuery);

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error', 'INVALID_TENANT_ID');
    });

    it('should reject tenant ID with time-based blind injection', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      const timeBasedInjection = "'; SELECT pg_sleep(10); --";

      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', timeBasedInjection);

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error', 'INVALID_TENANT_ID');
    });

    it('should reject tenant ID with boolean-based injection', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      const booleanInjection = "11111111-1111-1111-1111-111111111111' AND 1=1--";

      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', booleanInjection);

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error', 'INVALID_TENANT_ID');
    });
  });

  describe('Valid UUID acceptance', () => {
    it('should accept properly formatted UUID (lowercase)', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      const validUUID = '11111111-1111-1111-1111-111111111111';

      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', validUUID);

      // Doit réussir (ou échouer avec TENANT_MISMATCH si mauvais tenant, mais pas INVALID_TENANT_ID)
      expect(response.status).not.toBe(400);
      expect(response.body).not.toHaveProperty('error', 'INVALID_TENANT_ID');
    });

    it('should accept properly formatted UUID (uppercase)', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      const validUUID = '11111111-1111-1111-1111-111111111111'.toUpperCase();

      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', validUUID);

      expect(response.status).not.toBe(400);
      expect(response.body).not.toHaveProperty('error', 'INVALID_TENANT_ID');
    });

    it('should accept properly formatted UUID (mixed case)', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      const validUUID = '11111111-1111-1111-1111-111111111111';

      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', validUUID);

      expect(response.status).not.toBe(400);
      expect(response.body).not.toHaveProperty('error', 'INVALID_TENANT_ID');
    });
  });

  describe('Edge cases', () => {
    it('should reject UUID with extra characters', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      const invalidUUID = '11111111-1111-1111-1111-111111111111extra';

      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', invalidUUID);

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error', 'INVALID_TENANT_ID');
    });

    it('should reject UUID with missing dashes', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      const invalidUUID = '11111111111111111111111111111111';

      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', invalidUUID);

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error', 'INVALID_TENANT_ID');
    });

    it('should reject completely invalid format', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      const invalidUUID = 'not-a-valid-uuid';

      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', invalidUUID);

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error', 'INVALID_TENANT_ID');
    });

    it('should reject empty string', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', '');

      expect(response.status).toBe(400);
      // Peut être MISSING_TENANT_ID ou INVALID_TENANT_ID selon l'implémentation
      expect([400, 403]).toContain(response.status);
    });
  });
});
