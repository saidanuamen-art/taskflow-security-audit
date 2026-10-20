-- Durcissement RLS (idempotent) : rendre la Row-Level Security réellement active.
--
-- Constat d'audit (H0) : l'application se connectait avec `taskflow`, qui est
--   * SUPERUSER + BYPASSRLS (rôle créé par POSTGRES_USER dans l'image Docker),
--   * propriétaire des tables.
-- Un superutilisateur ignore TOUTES les policies, même avec FORCE ROW LEVEL SECURITY.
-- Correctif : l'application se connecte avec un rôle dédié `taskflow_app`,
-- sans privilège particulier ; `taskflow` reste réservé à l'administration.
--
-- Base existante : npm run docker:db:harden
-- (db/init.sql inclut déjà ce durcissement pour les nouvelles installations.)

BEGIN;

-- 1. Rôle applicatif sans privilège
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'taskflow_app') THEN
    CREATE ROLE taskflow_app LOGIN PASSWORD 'taskflow_app_dev_pw'
      NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END
$$;

GRANT CONNECT ON DATABASE taskflow TO taskflow_app;
GRANT USAGE ON SCHEMA public TO taskflow_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO taskflow_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO taskflow_app;

-- 2. Policies « fail-closed » : sans tenant fixé (variable absente ou vide),
--    la condition vaut NULL → aucune ligne visible, aucune écriture acceptée.
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_documents ON documents;
CREATE POLICY tenant_isolation_documents ON documents
  USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_users ON users;
CREATE POLICY tenant_isolation_users ON users
  USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- 3. Login : le tenant n'est pas encore connu. Fonction SECURITY DEFINER
--    (exécutée avec les droits de son propriétaire) limitée à la recherche
--    d'UN utilisateur par email — pas d'accès général à la table users.
CREATE OR REPLACE FUNCTION auth_find_user_by_email(p_email TEXT)
RETURNS TABLE (id UUID, tenant_id UUID, password_hash TEXT, role_name TEXT, priority INT)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT u.id, u.tenant_id, u.password_hash, r.name, r.priority
  FROM users u JOIN roles r ON r.id = u.role_id
  WHERE u.email = p_email
$$;

REVOKE ALL ON FUNCTION auth_find_user_by_email(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_find_user_by_email(TEXT) TO taskflow_app;

COMMIT;
