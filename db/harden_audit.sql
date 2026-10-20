-- Durcissement du journal d'audit (idempotent) : audit_logs en ajout seul.
--
-- Constat : la table audit_logs pouvait être modifiée ou vidée (UPDATE/DELETE),
-- y compris par l'application. Un journal modifiable n'a aucune valeur de preuve.
--
-- Base existante : npm run docker:db:harden
-- (db/init.sql inclut déjà ce durcissement pour les nouvelles installations.)

BEGIN;

-- 1. Le rôle applicatif peut seulement lire et ajouter
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM taskflow_app;

-- 2. Trigger : refuse UPDATE / DELETE / TRUNCATE pour TOUS les rôles,
--    administrateur compris (un superutilisateur n'échappe pas aux triggers).
CREATE OR REPLACE FUNCTION audit_logs_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'audit_logs est en ajout seul : % interdit', TG_OP;
END
$$;

DROP TRIGGER IF EXISTS audit_logs_no_update_delete ON audit_logs;
CREATE TRIGGER audit_logs_no_update_delete
  BEFORE UPDATE OR DELETE ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION audit_logs_append_only();

DROP TRIGGER IF EXISTS audit_logs_no_truncate ON audit_logs;
CREATE TRIGGER audit_logs_no_truncate
  BEFORE TRUNCATE ON audit_logs
  FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_append_only();

COMMIT;
