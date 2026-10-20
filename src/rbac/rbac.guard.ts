import { Request, Response, NextFunction } from "express";
import { pool } from "../common/db";
import { logEvent } from "../audit/audit.service";

// requireRole : vérifie que l'utilisateur courant a une priorité de rôle
// suffisante pour l'action demandée (anti-escalade).
//
// Usage prévu : un OWNER (priority 100) peut modifier n'importe quel rôle
// en dessous du sien. Un MEMBER (priority 50) ne doit jamais pouvoir
// modifier un rôle OWNER ni s'auto-promouvoir.

export function requireRole(minPriority: number) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = (req as any).user;
    if (!user) return res.status(401).json({ error: "UNAUTHENTICATED" });

    if (user.priority < minPriority) {
      // Refus journalisé : une tentative bloquée reste une information d'audit.
      await logEvent("authz.denied", user.tenantId, user.sub, {
        path: req.originalUrl,
        requiredPriority: minPriority,
        actorPriority: user.priority,
      }).catch((err) => console.error("audit log failed", err)); // le refus reste appliqué
      return res.status(403).json({ error: "FORBIDDEN" });
    }
    next();
  };
}

// Endpoint de changement de rôle — cf docs pour la question à se poser
// sur la cible de la modification, pas seulement sur l'acteur.
export async function changeUserRole(req: Request, res: Response) {
  const actor = (req as any).user;
  const { targetUserId, newRoleName } = req.body;

  // Chaque refus est journalisé (Repudiation) : on garde la trace des tentatives
  // d'escalade, pas seulement des changements réussis.
  const deny = async (status: number, error: string) => {
    await logEvent("user.role_change_denied", actor.tenantId, actor.sub, {
      targetUserId,
      newRoleName,
      actorRole: actor.role,
      reason: error,
    }).catch((err) => console.error("audit log failed", err)); // le refus reste appliqué
    return res.status(status).json({ error });
  };

  const roleResult = await pool.query(`SELECT id, priority FROM roles WHERE name = $1`, [newRoleName]);
  const newRole = roleResult.rows[0];
  if (!newRole) return deny(400, "UNKNOWN_ROLE");

  // Vérifie que l'acteur a une priorité suffisante pour attribuer CE rôle...
  if (actor.priority < newRole.priority) {
    return deny(403, "CANNOT_GRANT_HIGHER_ROLE");
  }

  // Connexion fournie par tenantMiddleware, avec le tenant de l'acteur fixé :
  // la policy RLS de `users` limite donc aussi cette requête au tenant de l'acteur.
  const client = (req as any).dbClient;

  // VULN-03 FIX: Charger la cible pour vérifier sa priorité actuelle
  const targetResult = await client.query(
    `SELECT u.id, r.priority as current_priority
     FROM users u
     JOIN roles r ON r.id = u.role_id
     WHERE u.id = $1 AND u.tenant_id = $2`,
    [targetUserId, actor.tenantId]
  );

  const target = targetResult.rows[0];
  if (!target) {
    return deny(404, "TARGET_USER_NOT_FOUND");
  }

  // VULN-03 FIX: Vérifier que l'acteur peut modifier cette cible
  if (actor.priority < target.current_priority) {
    return deny(403, "CANNOT_MODIFY_HIGHER_PRIORITY_TARGET");
  }

  await client.query(`UPDATE users SET role_id = $1 WHERE id = $2 AND tenant_id = $3`, [
    newRole.id,
    targetUserId,
    actor.tenantId,
  ]);

  // VULN-03 FIX: Logger l'événement pour audit
  await logEvent("user.role_changed", actor.tenantId, actor.sub, {
    targetUserId,
    newRoleName,
    actorRole: actor.role,
  });

  res.json({ ok: true });
}
