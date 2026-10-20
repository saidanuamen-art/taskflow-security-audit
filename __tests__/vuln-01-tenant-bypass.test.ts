import request from 'supertest';
import { Express } from 'express';
import { createTestApp } from './helpers/app-loader';
import { loginAsUser, TEST_USERS, withTenant } from './helpers/test-utils';

/**
 * VULN-01: Bypass d'isolation tenant
 * 
 * Vérifie qu'un utilisateur ne peut PAS accéder aux données d'un autre tenant
 * en modifiant le header x-tenant-id.
 * 
 * Correction appliquée : tenant.middleware.ts vérifie que le tenantId du header
 * correspond au tenantId du JWT.
 */
describe('VULN-01: Tenant Bypass Protection', () => {
  let app: Express;

  beforeAll(() => {
    app = createTestApp();
  });

  describe('Tenant isolation enforcement', () => {
    it('should reject request when x-tenant-id header does not match JWT tenantId', async () => {
      // Login en tant qu'utilisateur Tenant Alpha
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      // Tenter d'accéder avec le tenantId du Tenant Beta dans le header
      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', TEST_USERS.BETA_OWNER.tenantId); // ← Tentative de bypass

      // La requête doit être rejetée avec 403 TENANT_MISMATCH
      expect(response.status).toBe(403);
      expect(response.body).toHaveProperty('error', 'TENANT_MISMATCH');
    });

    it('should allow request when x-tenant-id matches JWT tenantId', async () => {
      // Login en tant qu'utilisateur Tenant Alpha
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      // Accéder avec le bon tenantId
      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', alphaUser.tenantId); // ← Bon tenant

      // La requête doit réussir
      expect(response.status).toBe(200);
      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should prevent cross-tenant data access via document creation', async () => {
      // Login en tant qu'utilisateur Tenant Alpha
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      // Tenter de créer un document en se faisant passer pour Tenant Beta
      const response = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', TEST_USERS.BETA_OWNER.tenantId)
        .send({
          title: 'Malicious Document',
          content: 'Trying to inject data into another tenant',
        });

      // La requête doit être rejetée
      expect(response.status).toBe(403);
      expect(response.body).toHaveProperty('error', 'TENANT_MISMATCH');

      // Et aucun document n'a été créé dans le tenant Beta
      const betaDocs = await withTenant(TEST_USERS.BETA_OWNER.tenantId, (client) =>
        client.query(`SELECT 1 FROM documents WHERE title = 'Malicious Document'`)
      );
      expect(betaDocs.rows).toHaveLength(0);
    });

    it('should reject request with missing x-tenant-id header', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${alphaUser.accessToken}`);
      // ← Pas de header x-tenant-id

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error', 'MISSING_TENANT_ID');
    });
  });

  describe('Multi-tenant isolation verification', () => {
    it('should ensure Tenant Alpha user cannot access Tenant Beta resources', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);
      const betaUser = await loginAsUser(app, TEST_USERS.BETA_OWNER);

      // Récupérer les documents de Beta avec son propre token
      const betaDocsResponse = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${betaUser.accessToken}`)
        .set('x-tenant-id', betaUser.tenantId);

      expect(betaDocsResponse.status).toBe(200);
      const betaDocs = betaDocsResponse.body;

      // Pré-requis : il faut au moins un document Beta, sinon le test ne prouve rien
      expect(betaDocs.length).toBeGreaterThan(0);
      const betaDocId = betaDocs[0].id;

      // Tenter d'accéder à ce document depuis Alpha avec header Beta
      const crossTenantAttempt = await request(app)
        .get(`/api/documents/${betaDocId}`)
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', TEST_USERS.BETA_OWNER.tenantId);

      // Doit être bloqué par TENANT_MISMATCH
      expect(crossTenantAttempt.status).toBe(403);
      expect(crossTenantAttempt.body).toHaveProperty('error', 'TENANT_MISMATCH');
    });

    it('should ensure each tenant only sees their own documents', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);
      const betaUser = await loginAsUser(app, TEST_USERS.BETA_OWNER);

      // Récupérer les documents Alpha
      const alphaResponse = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', alphaUser.tenantId);

      // Récupérer les documents Beta
      const betaResponse = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${betaUser.accessToken}`)
        .set('x-tenant-id', betaUser.tenantId);

      expect(alphaResponse.status).toBe(200);
      expect(betaResponse.status).toBe(200);

      // Vérifier qu'aucun document Beta n'apparaît dans la liste Alpha
      const alphaDocs = alphaResponse.body;
      const betaDocs = betaResponse.body;

      // Pré-requis : les deux tenants ont des documents
      expect(alphaDocs.length).toBeGreaterThan(0);
      expect(betaDocs.length).toBeGreaterThan(0);

      const betaDocIds = betaDocs.map((doc: any) => doc.id);
      const alphaDocIds = alphaDocs.map((doc: any) => doc.id);

      // Aucune intersection ne doit exister
      const intersection = alphaDocIds.filter((id: string) =>
        betaDocIds.includes(id)
      );
      expect(intersection.length).toBe(0);
    });
  });
});
