import { pool } from "../common/db";

// AuditService — journalise des événements sensibles.
//
// Note pédagogique : la table audit_logs n'a aucune contrainte d'immutabilité
// (pas de trigger interdisant UPDATE/DELETE), et cette fonction n'est appelée
// que par certains endpoints. Interroge-toi sur ce que ça implique pour la
// valeur probante d'un audit log en cas d'incident.

export async function logEvent(event: string, tenantId: string | null, actorUserId: string | null, metadata: any = {}) {
  await pool.query(
    `INSERT INTO audit_logs (event, tenant_id, actor_user_id, metadata) VALUES ($1, $2, $3, $4)`,
    [event, tenantId, actorUserId, JSON.stringify(metadata)]
  );
}
