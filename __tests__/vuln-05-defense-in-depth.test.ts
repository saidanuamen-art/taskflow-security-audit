import request from 'supertest';
import { Express } from 'express';
import { createTestApp } from './helpers/app-loader';
import {
  loginAsUser,
  TEST_USERS,
  getDocumentIdsInDb,
  deleteDocuments,
  withTenant,
  adminPool,
} from './helpers/test-utils';
import { pool } from '../src/common/db';

/**
 * VULN-05: Defense-in-depth manquante
 *
 * Vérifie que l'application ne repose pas UNIQUEMENT sur Row-Level Security (RLS)
 * PostgreSQL pour l'isolation tenant, mais implémente aussi des filtres applicatifs.
 *
 * Vulnérabilité originale : Les requêtes SQL ne filtraient pas explicitement par
 * tenant_id dans la clause WHERE, comptant uniquement sur RLS.
 *
 * Correction appliquée : Ajout de filtres WHERE tenant_id = $1 dans toutes les
 * requêtes de documents.controller.ts (listDocuments, getDocumentById).
 *
 * Les documents créés par ces tests sont supprimés à la fin (afterAll).
 */
describe('VULN-05: Defense-in-depth Protection', () => {
  let app: Express;
  const createdDocIds: string[] = [];

  beforeAll(() => {
    app = createTestApp();
  });

  afterAll(async () => {
    await deleteDocuments(TEST_USERS.ALPHA_OWNER.tenantId, createdDocIds);
  });

  describe('Application-level tenant filtering', () => {
    it('should only return documents belonging to the authenticated user tenant', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);
      const betaUser = await loginAsUser(app, TEST_USERS.BETA_OWNER);

      const alphaResponse = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', alphaUser.tenantId);
      expect(alphaResponse.status).toBe(200);

      const betaResponse = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${betaUser.accessToken}`)
        .set('x-tenant-id', betaUser.tenantId);
      expect(betaResponse.status).toBe(200);

      const alphaIds = alphaResponse.body.map((doc: any) => doc.id);
      const betaIds = betaResponse.body.map((doc: any) => doc.id);

      // Pré-requis : les deux tenants ont des documents, sinon le test ne prouve rien
      expect(alphaIds.length).toBeGreaterThan(0);
      expect(betaIds.length).toBeGreaterThan(0);

      // Les listes ne doivent avoir aucun document en commun
      expect(alphaIds.filter((id: string) => betaIds.includes(id))).toHaveLength(0);
    });

    it('should return exactly the tenant documents stored in the database', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', alphaUser.tenantId);

      expect(response.status).toBe(200);

      // Comparaison avec la base (source de vérité) : ni plus, ni moins
      const apiIds = response.body.map((doc: any) => doc.id).sort();
      const dbIds = (await getDocumentIdsInDb(alphaUser.tenantId)).sort();
      expect(apiIds).toEqual(dbIds);
    });

    it('should prevent access to documents from other tenants by ID', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      // Un vrai document Beta, lu directement en base
      const betaDocIds = await getDocumentIdsInDb(TEST_USERS.BETA_OWNER.tenantId);
      expect(betaDocIds.length).toBeGreaterThan(0);

      // Alpha demande ce document avec SON propre tenant (header valide)
      const crossTenantAttempt = await request(app)
        .get(`/api/documents/${betaDocIds[0]}`)
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', alphaUser.tenantId);

      // 404 grâce au filtre applicatif WHERE tenant_id = $2
      expect(crossTenantAttempt.status).toBe(404);
      expect(crossTenantAttempt.body).toHaveProperty('error', 'NOT_FOUND');
    });
  });

  describe('Layered security verification', () => {
    it('should create a document in the JWT tenant and read it back', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      const createResponse = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', alphaUser.tenantId)
        .send({
          title: 'Test Defense-in-depth',
          content: 'This document should be isolated at multiple layers',
        });

      expect(createResponse.status).toBe(201);
      const docId = createResponse.body.id;
      createdDocIds.push(docId);

      // Le tenant enregistré en base est celui du JWT
      const stored = await withTenant(alphaUser.tenantId, (client) =>
        client.query(`SELECT tenant_id FROM documents WHERE id = $1`, [docId])
      );
      expect(stored.rows).toHaveLength(1);
      expect(stored.rows[0].tenant_id).toBe(alphaUser.tenantId);

      // Alpha peut le relire
      const getResponse = await request(app)
        .get(`/api/documents/${docId}`)
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', alphaUser.tenantId);
      expect(getResponse.status).toBe(200);
      expect(getResponse.body).toHaveProperty('title', 'Test Defense-in-depth');

      // Beta ne peut pas le lire
      const betaUser = await loginAsUser(app, TEST_USERS.BETA_OWNER);
      const betaAttempt = await request(app)
        .get(`/api/documents/${docId}`)
        .set('Authorization', `Bearer ${betaUser.accessToken}`)
        .set('x-tenant-id', betaUser.tenantId);
      expect(betaAttempt.status).toBe(404);
    });

    it('should consistently apply tenant filters across all document endpoints', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);
      const betaUser = await loginAsUser(app, TEST_USERS.BETA_OWNER);

      const alphaListResponse = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', alphaUser.tenantId);
      expect(alphaListResponse.status).toBe(200);

      const betaListResponse = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${betaUser.accessToken}`)
        .set('x-tenant-id', betaUser.tenantId);
      expect(betaListResponse.status).toBe(200);

      const alphaDocs = alphaListResponse.body;
      const betaDocs = betaListResponse.body;
      expect(alphaDocs.length).toBeGreaterThan(0);
      expect(betaDocs.length).toBeGreaterThan(0);

      // Chaque document listé est lisible individuellement par son tenant
      for (const doc of alphaDocs) {
        const individualResponse = await request(app)
          .get(`/api/documents/${doc.id}`)
          .set('Authorization', `Bearer ${alphaUser.accessToken}`)
          .set('x-tenant-id', alphaUser.tenantId);
        expect(individualResponse.status).toBe(200);
      }

      // Aucun document Beta n'est lisible par Alpha
      for (const doc of betaDocs) {
        const crossTenantResponse = await request(app)
          .get(`/api/documents/${doc.id}`)
          .set('Authorization', `Bearer ${alphaUser.accessToken}`)
          .set('x-tenant-id', alphaUser.tenantId);
        expect(crossTenantResponse.status).toBe(404);
      }
    });
  });

  describe('RLS + Application filter redundancy', () => {
    /**
     * Couche RLS : l'app se connecte avec `taskflow`, propriétaire des tables.
     * Sans `FORCE ROW LEVEL SECURITY`, PostgreSQL n'appliquait pas la policy au
     * propriétaire (constat d'audit H0). Ces tests prouvent que la couche RLS
     * filtre maintenant SEULE, sans aucun filtre applicatif dans la requête.
     */
    it('RLS alone should hide other tenants documents (no application filter)', async () => {
      // Pré-requis : des documents Beta existent
      expect((await getDocumentIdsInDb(TEST_USERS.BETA_OWNER.tenantId)).length).toBeGreaterThan(0);

      // Contexte Alpha, requête SANS « WHERE tenant_id » : seul le RLS peut filtrer
      const result = await withTenant(TEST_USERS.ALPHA_OWNER.tenantId, (client) =>
        client.query(`SELECT DISTINCT tenant_id FROM documents`)
      );
      expect(result.rows.map((row) => row.tenant_id)).toEqual([TEST_USERS.ALPHA_OWNER.tenantId]);
    });

    it('RLS on users should hide other tenants users', async () => {
      const result = await withTenant(TEST_USERS.ALPHA_OWNER.tenantId, (client) =>
        client.query(`SELECT DISTINCT tenant_id FROM users`)
      );
      expect(result.rows.map((row) => row.tenant_id)).toEqual([TEST_USERS.ALPHA_OWNER.tenantId]);
    });

    it('RLS should be fail-closed when no tenant is set', async () => {
      // Aucune variable de tenant : aucune ligne visible (et pas d'erreur)
      const result = await pool.query(`SELECT count(*)::int AS n FROM documents`);
      expect(result.rows[0].n).toBe(0);
    });

    it('RLS should block inserting a document into another tenant', async () => {
      // Id réel du propriétaire Beta (lu en admin : en contexte Alpha, le RLS de `users` le cache)
      const betaOwnerId = (
        await adminPool.query(`SELECT id FROM users WHERE email = $1`, [TEST_USERS.BETA_OWNER.email])
      ).rows[0].id;

      // Contexte Alpha, tentative d'INSERT avec tenant_id Beta (policy WITH CHECK)
      await expect(
        withTenant(TEST_USERS.ALPHA_OWNER.tenantId, (client) =>
          client.query(
            `INSERT INTO documents (tenant_id, owner_id, title, content)
             VALUES ($1, $2, 'RLS bypass attempt', 'x')`,
            [TEST_USERS.BETA_OWNER.tenantId, betaOwnerId]
          )
        )
      ).rejects.toThrow(/row-level security/);
    });

    it('should not leak the tenant of a request to the next user of a pooled connection', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      // Plusieurs requêtes API : chacune fixe le tenant Alpha sur une connexion du pool
      for (let i = 0; i < 5; i++) {
        await request(app)
          .get('/api/documents')
          .set('Authorization', `Bearer ${alphaUser.accessToken}`)
          .set('x-tenant-id', alphaUser.tenantId)
          .expect(200);
      }

      // Les connexions rendues au pool ne doivent plus porter de tenant :
      // une requête sans contexte ne voit aucun document
      const results = await Promise.all(
        Array.from({ length: 5 }, () => pool.query(`SELECT count(*)::int AS n FROM documents`))
      );
      for (const result of results) {
        expect(result.rows[0].n).toBe(0);
      }
    });

    it('should keep tenants isolated through the API (application filter + RLS)', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', alphaUser.tenantId);
      expect(response.status).toBe(200);

      // Des documents Beta existent bien en base…
      const betaDbIds = await getDocumentIdsInDb(TEST_USERS.BETA_OWNER.tenantId);
      expect(betaDbIds.length).toBeGreaterThan(0);

      // …mais aucun n'apparaît dans la réponse Alpha
      const apiIds = response.body.map((doc: any) => doc.id);
      expect(apiIds.filter((id: string) => betaDbIds.includes(id))).toHaveLength(0);
    });

    it('should ignore any tenant_id sent in the body on CREATE', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      // Tentative : forcer le tenant Beta via le corps de la requête
      const response = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', alphaUser.tenantId)
        .send({
          title: 'New Document',
          content: 'This should be created with the correct tenant_id',
          tenant_id: TEST_USERS.BETA_OWNER.tenantId,
          tenantId: TEST_USERS.BETA_OWNER.tenantId,
        });

      expect(response.status).toBe(201);
      const docId = response.body.id;
      createdDocIds.push(docId);

      // Le document est enregistré dans le tenant du JWT, pas celui du body
      const stored = await withTenant(alphaUser.tenantId, (client) =>
        client.query(`SELECT tenant_id FROM documents WHERE id = $1`, [docId])
      );
      expect(stored.rows).toHaveLength(1);
      expect(stored.rows[0].tenant_id).toBe(alphaUser.tenantId);
    });
  });

  describe('Query consistency checks', () => {
    // Tenant temporaire sans aucun document, créé puis supprimé par le test
    const GAMMA_TENANT_ID = '33333333-3333-3333-3333-333333333333';
    const GAMMA_EMAIL = 'member@gamma.test';

    beforeAll(async () => {
      await adminPool.query(`INSERT INTO tenants (id, name) VALUES ($1, 'Tenant Gamma (test)') ON CONFLICT DO NOTHING`, [
        GAMMA_TENANT_ID,
      ]);
      // Même mot de passe que les comptes seed (copie du hash)
      await adminPool.query(
        `INSERT INTO users (tenant_id, email, password_hash, role_id)
         SELECT $1, $2, u.password_hash, r.id
         FROM users u, roles r WHERE u.email = $3 AND r.name = 'MEMBER'
         ON CONFLICT DO NOTHING`,
        [GAMMA_TENANT_ID, GAMMA_EMAIL, TEST_USERS.ALPHA_OWNER.email]
      );
    });

    afterAll(async () => {
      await adminPool.query(
        `DELETE FROM refresh_tokens WHERE user_id IN (SELECT id FROM users WHERE tenant_id = $1)`,
        [GAMMA_TENANT_ID]
      );
      await adminPool.query(`DELETE FROM users WHERE tenant_id = $1`, [GAMMA_TENANT_ID]);
      await adminPool.query(`DELETE FROM tenants WHERE id = $1`, [GAMMA_TENANT_ID]);
    });

    it('should return empty array for tenant with no documents', async () => {
      const gammaUser = await loginAsUser(app, {
        ...TEST_USERS.ALPHA_MEMBER,
        email: GAMMA_EMAIL,
        tenantId: GAMMA_TENANT_ID,
      });

      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${gammaUser.accessToken}`)
        .set('x-tenant-id', GAMMA_TENANT_ID);

      // Tenant vide → liste vide (et surtout pas les documents des autres tenants)
      expect(response.status).toBe(200);
      expect(response.body).toEqual([]);
    });

    it('should return 404 for non-existent document in the correct tenant', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      const response = await request(app)
        .get('/api/documents/00000000-0000-0000-0000-000000000000')
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', alphaUser.tenantId);

      expect(response.status).toBe(404);
      expect(response.body).toHaveProperty('error', 'NOT_FOUND');
    });

    it('should handle concurrent requests from different tenants', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);
      const betaUser = await loginAsUser(app, TEST_USERS.BETA_OWNER);

      // Requêtes simultanées : vérifie qu'une connexion ne « garde » pas le tenant d'une autre
      const [alphaResponse, betaResponse] = await Promise.all([
        request(app)
          .get('/api/documents')
          .set('Authorization', `Bearer ${alphaUser.accessToken}`)
          .set('x-tenant-id', alphaUser.tenantId),
        request(app)
          .get('/api/documents')
          .set('Authorization', `Bearer ${betaUser.accessToken}`)
          .set('x-tenant-id', betaUser.tenantId),
      ]);

      expect(alphaResponse.status).toBe(200);
      expect(betaResponse.status).toBe(200);

      const alphaIds = alphaResponse.body.map((doc: any) => doc.id).sort();
      const betaIds = betaResponse.body.map((doc: any) => doc.id).sort();
      expect(alphaIds).toEqual((await getDocumentIdsInDb(alphaUser.tenantId)).sort());
      expect(betaIds).toEqual((await getDocumentIdsInDb(betaUser.tenantId)).sort());
    });
  });

  describe('Data leakage prevention', () => {
    it('should not leak tenant information in error messages', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      // Un VRAI document Beta : le message ne doit pas révéler qu'il existe ailleurs
      const betaDocIds = await getDocumentIdsInDb(TEST_USERS.BETA_OWNER.tenantId);
      expect(betaDocIds.length).toBeGreaterThan(0);

      const response = await request(app)
        .get(`/api/documents/${betaDocIds[0]}`)
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', alphaUser.tenantId);

      expect(response.status).toBe(404);
      // Même réponse qu'un document inexistant : impossible de deviner qu'il existe
      expect(response.body).toEqual({ error: 'NOT_FOUND' });
      const errorMessage = JSON.stringify(response.body);
      expect(errorMessage).not.toContain(TEST_USERS.BETA_OWNER.tenantId);
      expect(errorMessage).not.toContain('tenant_id');
    });

    it('should not expose document count from other tenants', async () => {
      const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      const response = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${alphaUser.accessToken}`)
        .set('x-tenant-id', alphaUser.tenantId);

      expect(response.status).toBe(200);
      // Le nombre renvoyé = nombre de documents Alpha uniquement
      const alphaCount = (await getDocumentIdsInDb(alphaUser.tenantId)).length;
      expect(response.body).toHaveLength(alphaCount);
      // Et aucune donnée de pagination/total globale n'est ajoutée
      expect(Array.isArray(response.body)).toBe(true);
      // Les documents ne contiennent pas le champ tenant_id
      for (const doc of response.body) {
        expect(doc).not.toHaveProperty('tenant_id');
      }
    });
  });
});
