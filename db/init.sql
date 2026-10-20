-- Schéma TaskFlow (playground) — multi-tenant avec Row-Level Security
-- Reproduit le pattern : tenants isolés, rôles à priorité numérique, RLS Postgres.

CREATE TABLE tenants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT UNIQUE NOT NULL,       -- OWNER, MEMBER, GUEST
  priority INT NOT NULL            -- OWNER=100, MEMBER=50, GUEST=10 (anti-escalade)
);

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  email TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role_id UUID NOT NULL REFERENCES roles(id),
  created_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE (tenant_id, email)
);

CREATE TABLE documents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  owner_id UUID NOT NULL REFERENCES users(id),
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE refresh_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id),
  token_hash TEXT NOT NULL,
  revoked BOOLEAN DEFAULT false,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID,
  event TEXT NOT NULL,
  actor_user_id UUID,
  metadata JSONB,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Row-Level Security : voir le bloc « Durcissement RLS » en fin de fichier
-- (rôle applicatif dédié, policies fail-closed, fonction de login).

-- Seed
INSERT INTO roles (name, priority) VALUES
  ('OWNER', 100),
  ('MEMBER', 50),
  ('GUEST', 10);

INSERT INTO tenants (id, name) VALUES
  ('11111111-1111-1111-1111-111111111111', 'Tenant Alpha'),
  ('22222222-2222-2222-2222-222222222222', 'Tenant Beta');

-- mot de passe pour tous les comptes seed : "Password123!"
INSERT INTO users (tenant_id, email, password_hash, role_id)
SELECT '11111111-1111-1111-1111-111111111111', 'owner@alpha.test',
       '$2b$10$T1U0k76FKigenRHFG0hwYe5wp1gppmipX2w65tjbuNzctfxVzHsJ6', id
FROM roles WHERE name = 'OWNER';

INSERT INTO users (tenant_id, email, password_hash, role_id)
SELECT '22222222-2222-2222-2222-222222222222', 'owner@beta.test',
       '$2b$10$T1U0k76FKigenRHFG0hwYe5wp1gppmipX2w65tjbuNzctfxVzHsJ6', id
FROM roles WHERE name = 'OWNER';

-- un second utilisateur MEMBER par tenant, utile pour tester le RBAC / escalade
INSERT INTO users (tenant_id, email, password_hash, role_id)
SELECT '11111111-1111-1111-1111-111111111111', 'member@alpha.test',
       '$2b$10$T1U0k76FKigenRHFG0hwYe5wp1gppmipX2w65tjbuNzctfxVzHsJ6', id
FROM roles WHERE name = 'MEMBER';

INSERT INTO users (tenant_id, email, password_hash, role_id)
SELECT '22222222-2222-2222-2222-222222222222', 'member@beta.test',
       '$2b$10$T1U0k76FKigenRHFG0hwYe5wp1gppmipX2w65tjbuNzctfxVzHsJ6', id
FROM roles WHERE name = 'MEMBER';

INSERT INTO documents (tenant_id, owner_id, title, content)
SELECT '11111111-1111-1111-1111-111111111111', u.id, 'Secret Alpha Doc', 'Contenu confidentiel du tenant Alpha'
FROM users u WHERE u.email = 'owner@alpha.test';

INSERT INTO documents (tenant_id, owner_id, title, content)
SELECT '22222222-2222-2222-2222-222222222222', u.id, 'Secret Beta Doc', 'Contenu confidentiel du tenant Beta'
FROM users u WHERE u.email = 'owner@beta.test';

-- ===================== Durcissement RLS =====================
-- Même contenu que db/harden_rls.sql (à garder synchronisés).
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

-- ===================== Durcissement audit_logs =====================
-- Même contenu que db/harden_audit.sql (à garder synchronisés).
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
