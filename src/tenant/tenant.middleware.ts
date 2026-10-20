import { Request, Response, NextFunction } from "express";
import { pool } from "../common/db";

// TenantMiddleware — fixe le tenant courant pour la session Postgres (RLS).
//
// Note pédagogique : ce middleware fonctionne "en apparence". Il passe tous les
// tests fonctionnels basiques (un tenant ne voit que ses documents en usage normal).
// Cela ne veut pas dire qu'il est sûr contre un utilisateur qui contrôle sa requête.

export async function tenantMiddleware(req: Request, res: Response, next: NextFunction) {
  try {
    // Le tenant est lu depuis un header envoyé par le client.
    const tenantId = req.headers["x-tenant-id"] as string;

    if (!tenantId) {
      return res.status(400).json({ error: "MISSING_TENANT_ID" });
    }

    // VULN-02 FIX: Validation stricte du format UUID pour prévenir SQL injection
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(tenantId)) {
      return res.status(400).json({ error: "INVALID_TENANT_ID" });
    }

    // VULN-01 FIX: Vérifier que le tenant du header correspond au tenant du JWT
    const user = (req as any).user;
    if (tenantId !== user.tenantId) {
      return res.status(403).json({ error: "TENANT_MISMATCH" });
    }

    const client = await pool.connect();
    (req as any).dbClient = client;

    // BONUS FIX: Libérer la connexion quand la réponse est terminée (ou interrompue).
    // RLS FIX: effacer le tenant AVANT de rendre la connexion au pool, sinon la
    // prochaine requête qui réutilise cette connexion hériterait de ce tenant.
    let released = false;
    const releaseClient = async () => {
      if (released) return;
      released = true;
      try {
        await client.query(`SELECT set_config('app.current_tenant_id', '', false)`);
        client.release();
      } catch (err) {
        client.release(err as Error); // connexion détruite plutôt que réutilisée
      }
    };
    res.on("finish", releaseClient);
    res.on("close", releaseClient);

    // Fixe la variable de session utilisée par les policies RLS.
    // VULN-02 FIX (défense en profondeur) : paramètre lié via set_config, plus
    // aucune concaténation SQL — la regex UUID ci-dessus n'est plus la seule barrière.
    await client.query(`SELECT set_config('app.current_tenant_id', $1, false)`, [tenantId]);

    (req as any).tenantId = tenantId;
    next();
  } catch (err) {
    next(err);
  }
}
