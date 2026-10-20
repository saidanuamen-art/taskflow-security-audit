import request from 'supertest';
import { Express } from 'express';
import { createTestApp } from './helpers/app-loader';
import {
  loginAsUser,
  TEST_USERS,
  extractUserIdFromToken,
  resetSeedRoles,
  getUserRole,
  adminPool,
} from './helpers/test-utils';
import { pool } from '../src/common/db';


/**
 * VULN-03: Escalade de privilèges RBAC
 *
 * Vérifie qu'un utilisateur ne peut pas modifier le rôle d'un utilisateur
 * ayant une priorité supérieure à la sienne.
 *
 * Vulnérabilité originale : Le système vérifiait seulement que l'acteur
 * avait une priorité suffisante pour attribuer LE NOUVEAU rôle, mais ne
 * vérifiait pas la priorité de LA CIBLE de la modification.
 *
 * Correction appliquée : rbac.guard.ts refuse si
 * actor.priority < target.current_priority.
 *
 * Ces tests modifient réellement des rôles en base : les rôles d'origine sont
 * remis avant chaque test et à la fin de la suite (resetSeedRoles).
 */
const CHANGE_ROLE_URL = '/api/users/change-role';

describe('VULN-03: RBAC Privilege Escalation Protection', () => {
  let app: Express;

  beforeAll(() => {
    app = createTestApp();
  });

  beforeEach(async () => {
    await resetSeedRoles();
  });

  afterAll(async () => {
    await resetSeedRoles();
  });

  describe('Self-promotion prevention', () => {
    it('should prevent MEMBER from promoting themselves to OWNER', async () => {
      const memberUser = await loginAsUser(app, TEST_USERS.ALPHA_MEMBER);
      const memberUserId = extractUserIdFromToken(memberUser.accessToken);

      const response = await request(app)
        .post(CHANGE_ROLE_URL)
        .set('Authorization', `Bearer ${memberUser.accessToken}`)
        .set('x-tenant-id', memberUser.tenantId)
        .send({ targetUserId: memberUserId, newRoleName: 'OWNER' });

      // MEMBER (50) ne peut pas attribuer OWNER (100)
      expect(response.status).toBe(403);
      expect(response.body).toHaveProperty('error', 'CANNOT_GRANT_HIGHER_ROLE');
      // Et le rôle n'a pas changé en base
      expect(await getUserRole(TEST_USERS.ALPHA_MEMBER.email)).toBe('MEMBER');
    });

    it('should prevent GUEST from promoting themselves to MEMBER', async () => {
      // Préparation : l'OWNER rétrograde le member en GUEST (cas légitime)
      const ownerUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);
      const memberUserId = extractUserIdFromToken(
        (await loginAsUser(app, TEST_USERS.ALPHA_MEMBER)).accessToken
      );
      await request(app)
        .post(CHANGE_ROLE_URL)
        .set('Authorization', `Bearer ${ownerUser.accessToken}`)
        .set('x-tenant-id', ownerUser.tenantId)
        .send({ targetUserId: memberUserId, newRoleName: 'GUEST' })
        .expect(200);

      // Le GUEST (priorité 10) se reconnecte et tente de se repromouvoir MEMBER
      const guestUser = await loginAsUser(app, TEST_USERS.ALPHA_MEMBER);
      const response = await request(app)
        .post(CHANGE_ROLE_URL)
        .set('Authorization', `Bearer ${guestUser.accessToken}`)
        .set('x-tenant-id', guestUser.tenantId)
        .send({ targetUserId: memberUserId, newRoleName: 'MEMBER' });

      // Bloqué dès la garde requireRole(50)
      expect(response.status).toBe(403);
      expect(response.body).toHaveProperty('error', 'FORBIDDEN');
      expect(await getUserRole(TEST_USERS.ALPHA_MEMBER.email)).toBe('GUEST');
    });
  });

  describe('Cross-user privilege escalation prevention', () => {
    it('should prevent MEMBER from modifying OWNER role', async () => {
      const memberUser = await loginAsUser(app, TEST_USERS.ALPHA_MEMBER);
      const ownerUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);
      const ownerUserId = extractUserIdFromToken(ownerUser.accessToken);

      // MEMBER tente de rétrograder OWNER en GUEST (rôle GUEST < MEMBER : autorisé
      // à attribuer, mais la CIBLE est plus haute que l'acteur → c'est le cœur de VULN-03)
      const response = await request(app)
        .post(CHANGE_ROLE_URL)
        .set('Authorization', `Bearer ${memberUser.accessToken}`)
        .set('x-tenant-id', memberUser.tenantId)
        .send({ targetUserId: ownerUserId, newRoleName: 'GUEST' });

      expect(response.status).toBe(403);
      expect(response.body).toHaveProperty('error', 'CANNOT_MODIFY_HIGHER_PRIORITY_TARGET');
      expect(await getUserRole(TEST_USERS.ALPHA_OWNER.email)).toBe('OWNER');
    });

    it('should prevent MEMBER from promoting another MEMBER to OWNER', async () => {
      const memberUser = await loginAsUser(app, TEST_USERS.ALPHA_MEMBER);
      const anotherMemberId = '99999999-9999-9999-9999-999999999999';

      const response = await request(app)
        .post(CHANGE_ROLE_URL)
        .set('Authorization', `Bearer ${memberUser.accessToken}`)
        .set('x-tenant-id', memberUser.tenantId)
        .send({ targetUserId: anotherMemberId, newRoleName: 'OWNER' });

      // Refusé avant même de chercher la cible
      expect(response.status).toBe(403);
      expect(response.body).toHaveProperty('error', 'CANNOT_GRANT_HIGHER_ROLE');
    });
  });

  describe('Legitimate role changes', () => {
    it('should allow OWNER to change another user role to MEMBER', async () => {
      const ownerUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);
      const memberUser = await loginAsUser(app, TEST_USERS.ALPHA_MEMBER);
      const memberUserId = extractUserIdFromToken(memberUser.accessToken);

      const response = await request(app)
        .post(CHANGE_ROLE_URL)
        .set('Authorization', `Bearer ${ownerUser.accessToken}`)
        .set('x-tenant-id', ownerUser.tenantId)
        .send({ targetUserId: memberUserId, newRoleName: 'MEMBER' });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('ok', true);
      expect(await getUserRole(TEST_USERS.ALPHA_MEMBER.email)).toBe('MEMBER');
    });

    it('should allow OWNER to promote MEMBER to OWNER', async () => {
      const ownerUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);
      const memberUser = await loginAsUser(app, TEST_USERS.ALPHA_MEMBER);
      const memberUserId = extractUserIdFromToken(memberUser.accessToken);

      const response = await request(app)
        .post(CHANGE_ROLE_URL)
        .set('Authorization', `Bearer ${ownerUser.accessToken}`)
        .set('x-tenant-id', ownerUser.tenantId)
        .send({ targetUserId: memberUserId, newRoleName: 'OWNER' });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('ok', true);
      // Le changement est bien appliqué (puis annulé par resetSeedRoles)
      expect(await getUserRole(TEST_USERS.ALPHA_MEMBER.email)).toBe('OWNER');
    });
  });

  describe('Role hierarchy enforcement', () => {
    it('should enforce priority-based access control', async () => {
      const memberUser = await loginAsUser(app, TEST_USERS.ALPHA_MEMBER);
      const ownerUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);
      const ownerUserId = extractUserIdFromToken(ownerUser.accessToken);

      // MEMBER (50) tente de rétrograder OWNER (100) en MEMBER
      const response = await request(app)
        .post(CHANGE_ROLE_URL)
        .set('Authorization', `Bearer ${memberUser.accessToken}`)
        .set('x-tenant-id', memberUser.tenantId)
        .send({ targetUserId: ownerUserId, newRoleName: 'MEMBER' });

      expect(response.status).toBe(403);
      expect(response.body).toHaveProperty('error', 'CANNOT_MODIFY_HIGHER_PRIORITY_TARGET');
      expect(await getUserRole(TEST_USERS.ALPHA_OWNER.email)).toBe('OWNER');
    });

    it('should reject role changes on non-existent users', async () => {
      const ownerUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);

      const response = await request(app)
        .post(CHANGE_ROLE_URL)
        .set('Authorization', `Bearer ${ownerUser.accessToken}`)
        .set('x-tenant-id', ownerUser.tenantId)
        .send({ targetUserId: '00000000-0000-0000-0000-000000000000', newRoleName: 'MEMBER' });

      expect(response.status).toBe(404);
      expect(response.body).toHaveProperty('error', 'TARGET_USER_NOT_FOUND');
    });

    it('should reject role changes with unknown role names', async () => {
      const ownerUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);
      const memberUser = await loginAsUser(app, TEST_USERS.ALPHA_MEMBER);
      const memberUserId = extractUserIdFromToken(memberUser.accessToken);

      const response = await request(app)
        .post(CHANGE_ROLE_URL)
        .set('Authorization', `Bearer ${ownerUser.accessToken}`)
        .set('x-tenant-id', ownerUser.tenantId)
        .send({ targetUserId: memberUserId, newRoleName: 'SUPER_ADMIN' });

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error', 'UNKNOWN_ROLE');
    });
  });

  describe('Cross-tenant role change prevention', () => {
    it('should prevent modifying users from other tenants', async () => {
      const alphaOwner = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);
      const betaMember = await loginAsUser(app, TEST_USERS.BETA_MEMBER);
      const betaMemberUserId = extractUserIdFromToken(betaMember.accessToken);

      const response = await request(app)
        .post(CHANGE_ROLE_URL)
        .set('Authorization', `Bearer ${alphaOwner.accessToken}`)
        .set('x-tenant-id', alphaOwner.tenantId)
        .send({ targetUserId: betaMemberUserId, newRoleName: 'GUEST' });

      // La cible est cherchée uniquement dans le tenant de l'acteur
      expect(response.status).toBe(404);
      expect(response.body).toHaveProperty('error', 'TARGET_USER_NOT_FOUND');
      expect(await getUserRole(TEST_USERS.BETA_MEMBER.email)).toBe('MEMBER');
    });
  });

  describe('Audit logging verification', () => {
    it('should log successful role changes for audit trail', async () => {
      const ownerUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);
      const ownerUserId = extractUserIdFromToken(ownerUser.accessToken);
      const memberUser = await loginAsUser(app, TEST_USERS.ALPHA_MEMBER);
      const memberUserId = extractUserIdFromToken(memberUser.accessToken);
      const startedAt = (await adminPool.query('SELECT clock_timestamp() AS t')).rows[0].t;

      const response = await request(app)
        .post(CHANGE_ROLE_URL)
        .set('Authorization', `Bearer ${ownerUser.accessToken}`)
        .set('x-tenant-id', ownerUser.tenantId)
        .send({ targetUserId: memberUserId, newRoleName: 'GUEST' });

      expect(response.status).toBe(200);

      // Vérifie réellement la table audit_logs
      const audit = await adminPool.query(
        `SELECT tenant_id, actor_user_id, metadata FROM audit_logs
         WHERE event = 'user.role_changed' AND created_at >= $1
           AND metadata->>'targetUserId' = $2
         ORDER BY created_at DESC LIMIT 1`,
        [startedAt, memberUserId]
      );

      expect(audit.rows).toHaveLength(1);
      expect(audit.rows[0].tenant_id).toBe(ownerUser.tenantId);
      expect(audit.rows[0].actor_user_id).toBe(ownerUserId);
      expect(audit.rows[0].metadata).toMatchObject({ newRoleName: 'GUEST', actorRole: 'OWNER' });
    });

    it('should log refused role changes as denied (not as changed)', async () => {
      const memberUser = await loginAsUser(app, TEST_USERS.ALPHA_MEMBER);
      const memberUserId = extractUserIdFromToken(memberUser.accessToken);
      const startedAt = (await adminPool.query('SELECT clock_timestamp() AS t')).rows[0].t;

      await request(app)
        .post(CHANGE_ROLE_URL)
        .set('Authorization', `Bearer ${memberUser.accessToken}`)
        .set('x-tenant-id', memberUser.tenantId)
        .send({ targetUserId: memberUserId, newRoleName: 'OWNER' })
        .expect(403);

      const audit = await adminPool.query(
        `SELECT event, actor_user_id, metadata FROM audit_logs
         WHERE created_at >= $1 AND metadata->>'targetUserId' = $2`,
        [startedAt, memberUserId]
      );
      // Une trace de la tentative refusée, et aucune trace de changement réussi
      expect(audit.rows.map((row) => row.event)).toEqual(['user.role_change_denied']);
      expect(audit.rows[0].actor_user_id).toBe(memberUserId);
      expect(audit.rows[0].metadata).toMatchObject({
        newRoleName: 'OWNER',
        reason: 'CANNOT_GRANT_HIGHER_ROLE',
      });
    });

    it('should log access denied by the role guard (GUEST)', async () => {
      // Préparation : l'OWNER rétrograde le member en GUEST (priorité 10 < 50)
      const ownerUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);
      const memberUserId = extractUserIdFromToken(
        (await loginAsUser(app, TEST_USERS.ALPHA_MEMBER)).accessToken
      );
      await request(app)
        .post(CHANGE_ROLE_URL)
        .set('Authorization', `Bearer ${ownerUser.accessToken}`)
        .set('x-tenant-id', ownerUser.tenantId)
        .send({ targetUserId: memberUserId, newRoleName: 'GUEST' })
        .expect(200);

      const guestUser = await loginAsUser(app, TEST_USERS.ALPHA_MEMBER);
      const startedAt = (await adminPool.query('SELECT clock_timestamp() AS t')).rows[0].t;

      await request(app)
        .post(CHANGE_ROLE_URL)
        .set('Authorization', `Bearer ${guestUser.accessToken}`)
        .set('x-tenant-id', guestUser.tenantId)
        .send({ targetUserId: memberUserId, newRoleName: 'MEMBER' })
        .expect(403);

      const audit = await adminPool.query(
        `SELECT metadata FROM audit_logs
         WHERE event = 'authz.denied' AND created_at >= $1 AND actor_user_id = $2`,
        [startedAt, memberUserId]
      );
      expect(audit.rows).toHaveLength(1);
      expect(audit.rows[0].metadata).toMatchObject({ requiredPriority: 50, actorPriority: 10 });
    });
  });

  describe('Audit log integrity (append-only)', () => {
    it('should forbid the application role from modifying or deleting audit logs', async () => {
      // Rôle applicatif : droits UPDATE/DELETE retirés
      await expect(pool.query(`UPDATE audit_logs SET event = 'tampered'`)).rejects.toThrow(
        /permission denied/
      );
      await expect(pool.query(`DELETE FROM audit_logs`)).rejects.toThrow(/permission denied/);
    });

    it('should forbid even an administrator from modifying or deleting audit logs', async () => {
      // Le trigger s'applique aussi au superutilisateur
      await expect(adminPool.query(`UPDATE audit_logs SET event = 'tampered'`)).rejects.toThrow(
        /ajout seul/
      );
      await expect(adminPool.query(`DELETE FROM audit_logs`)).rejects.toThrow(/ajout seul/);
      await expect(adminPool.query(`TRUNCATE audit_logs`)).rejects.toThrow(/ajout seul/);
    });

    it('should still allow the application to append audit events', async () => {
      // Dans une transaction annulée : le journal étant immuable, une ligne de test
      // insérée pour de bon ne pourrait plus jamais être supprimée.
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const inserted = await client.query(
          `INSERT INTO audit_logs (event, metadata) VALUES ('test.append_only_check', '{}') RETURNING id`
        );
        expect(inserted.rows).toHaveLength(1);
      } finally {
        await client.query('ROLLBACK');
        client.release();
      }
    });
  });
});
