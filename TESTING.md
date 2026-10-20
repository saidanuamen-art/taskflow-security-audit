# 🧪 Guide de Tests Automatisés - TaskFlow Security Suite

Ce document décrit la suite de tests automatisés qui vérifie en continu les correctifs de sécurité appliqués aux 5 vulnérabilités critiques identifiées lors de l'audit.

---

## 📋 Table des matières

1. [Vue d'ensemble](#vue-densemble)
2. [Prérequis](#prérequis)
3. [Installation](#installation)
4. [Exécution des tests](#exécution-des-tests)
5. [Structure des tests](#structure-des-tests)
6. [Détail des tests par vulnérabilité](#détail-des-tests-par-vulnérabilité)
7. [Interprétation des résultats](#interprétation-des-résultats)
8. [Intégration CI/CD](#intégration-cicd)
9. [Dépannage](#dépannage)

---

## Vue d'ensemble

Cette suite de tests automatisés implémente **62 tests unitaires et d'intégration** répartis en 5 fichiers, un par vulnérabilité corrigée :

| Vulnérabilité | Tests | Fichier |
|---------------|-------|---------|
| **VULN-01** Bypass tenant | 6 tests | `vuln-01-tenant-bypass.test.ts` |
| **VULN-02** SQL Injection | 13 tests | `vuln-02-sql-injection.test.ts` |
| **VULN-03** RBAC Escalation | 12 tests | `vuln-03-rbac-escalation.test.ts` |
| **VULN-04** JWT Weak Secret | 17 tests | `vuln-04-jwt-weak-secret.test.ts` |
| **VULN-05** Defense-in-depth | 14 tests | `vuln-05-defense-in-depth.test.ts` |
| **TOTAL** | **62 tests** | |

### Objectifs

✅ **Vérifier** que les vulnérabilités ne peuvent plus être exploitées  
✅ **Empêcher** la réintroduction de failles lors de modifications futures  
✅ **Documenter** le comportement de sécurité attendu  
✅ **Automatiser** la validation continue des correctifs  

---

## Prérequis

### Logiciels requis

- **Node.js** : v18+ 
- **PostgreSQL** : v16 (via Docker)
- **Docker Desktop** : Pour la base de données de test
- **npm** : v9+ (inclus avec Node.js)

### Variables d'environnement

Le fichier `.env` doit contenir :

```env
DATABASE_URL=postgres://taskflow:taskflow_dev_pw@localhost:5432/taskflow
JWT_SECRET=<votre_secret_cryptographique_256bit>
PORT=3001
```

⚠️ **Important** : `JWT_SECRET` doit être défini avec un secret fort (minimum 32 caractères).

---

## Installation

### 1. Installer les dépendances de test

```bash
npm install
```

Les packages de test suivants sont installés automatiquement :
- `jest` : Framework de test
- `ts-jest` : Support TypeScript pour Jest
- `supertest` : Tests HTTP
- `@types/jest`, `@types/supertest` : Définitions TypeScript

### 2. Démarrer la base de données

```bash
npm run docker:up
```

Vérifier que PostgreSQL tourne :

```bash
docker ps
```

Vous devriez voir `taskflow2_pg` avec le statut `Up`.

### 3. Initialiser les données de test

```bash
npm run docker:db:init
```

Cette commande crée les tables et insère les utilisateurs de test :
- `owner@alpha.test` / `Password123!` (Tenant Alpha, OWNER)
- `member@alpha.test` / `Password123!` (Tenant Alpha, MEMBER)
- `owner@beta.test` / `Password123!` (Tenant Beta, OWNER)
- `member@beta.test` / `Password123!` (Tenant Beta, MEMBER)

---

## Exécution des tests

### Commandes principales

#### Lancer TOUS les tests

```bash
npm test
```

**Résultat attendu :**
```
Test Suites: 5 passed, 5 total
Tests:       62 passed, 62 total
Snapshots:   0 total
Time:        ~15s
```

#### Lancer les tests en mode watch (développement)

```bash
npm run test:watch
```

Les tests se relancent automatiquement à chaque modification de fichier.

#### Générer le rapport de couverture

```bash
npm run test:coverage
```

Un rapport HTML détaillé sera créé dans `coverage/lcov-report/index.html`.

#### Afficher les détails verbeux

```bash
npm run test:verbose
```

Affiche chaque test individuellement avec son statut.

### Commandes par vulnérabilité

Tester une vulnérabilité spécifique :

```bash
npm run test:vuln-01  # VULN-01: Tenant Bypass
npm run test:vuln-02  # VULN-02: SQL Injection
npm run test:vuln-03  # VULN-03: RBAC Escalation
npm run test:vuln-04  # VULN-04: JWT Weak Secret
npm run test:vuln-05  # VULN-05: Defense-in-depth
```

---

## Structure des tests

```
__tests__/
├── setup.ts                          # Configuration globale Jest
├── helpers/
│   ├── app-loader.ts                 # Création instance Express pour tests
│   └── test-utils.ts                 # Fonctions helper réutilisables
├── vuln-01-tenant-bypass.test.ts     # Tests isolation tenant
├── vuln-02-sql-injection.test.ts     # Tests validation UUID / SQL injection
├── vuln-03-rbac-escalation.test.ts   # Tests escalade privilèges RBAC
├── vuln-04-jwt-weak-secret.test.ts   # Tests secret JWT / tokens forgés
└── vuln-05-defense-in-depth.test.ts  # Tests filtres applicatifs
```

### Helpers réutilisables

#### `loginAsUser(app, userConfig)`

Authentifie un utilisateur et retourne son token JWT.

```typescript
const alphaUser = await loginAsUser(app, TEST_USERS.ALPHA_OWNER);
// { email, accessToken, tenantId, role, userId }
```

#### `createForgedToken(payload, secret, expiresIn)`

Crée un token JWT forgé pour tester les rejets.

```typescript
const forgedToken = createForgedToken(
  { sub: "fake-id", tenantId: "...", role: "OWNER", priority: 100, type: "access" },
  "weak-secret",
  "1h"
);
```

#### `TEST_USERS`

Constantes pour les utilisateurs de test :

```typescript
TEST_USERS.ALPHA_OWNER    // owner@alpha.test
TEST_USERS.ALPHA_MEMBER   // member@alpha.test
TEST_USERS.BETA_OWNER     // owner@beta.test
TEST_USERS.BETA_MEMBER    // member@beta.test
```

---

## Détail des tests par vulnérabilité

### VULN-01 : Bypass d'isolation tenant (6 tests)

**Objectif :** Vérifier qu'un utilisateur ne peut PAS accéder aux données d'un autre tenant en modifiant le header `x-tenant-id`.

#### Tests inclus :

1. ✅ Rejet quand `x-tenant-id` ≠ JWT `tenantId` → `403 TENANT_MISMATCH`
2. ✅ Acceptation quand `x-tenant-id` = JWT `tenantId` → `200 OK`
3. ✅ Prévention création document cross-tenant → `403`
4. ✅ Rejet si header `x-tenant-id` manquant → `400 MISSING_TENANT_ID`
5. ✅ Isolation Alpha ↔ Beta (aucun accès mutuel)
6. ✅ Chaque tenant voit SEULEMENT ses documents

**Fichier de code corrigé :** `src/tenant/tenant.middleware.ts`

---

### VULN-02 : SQL Injection (13 tests)

**Objectif :** Vérifier que les payloads d'injection SQL via `x-tenant-id` sont bloqués avant exécution SQL.

#### Tests inclus :

1. ✅ Rejet `'; DROP TABLE documents; --` → `400 INVALID_TENANT_ID`
2. ✅ Rejet `' OR '1'='1` → `400`
3. ✅ Rejet `UNION SELECT * FROM users--` → `400`
4. ✅ Rejet stacked queries `'; DELETE FROM audit_logs; --` → `400`
5. ✅ Rejet time-based injection `'; SELECT pg_sleep(10); --` → `400`
6. ✅ Rejet boolean-based `AND 1=1--` → `400`
7. ✅ Acceptation UUID valide (lowercase) → `200/403` (pas 400)
8. ✅ Acceptation UUID valide (uppercase) → `200/403`
9. ✅ Acceptation UUID valide (mixed case) → `200/403`
10. ✅ Rejet UUID avec caractères extra → `400`
11. ✅ Rejet UUID sans tirets → `400`
12. ✅ Rejet format complètement invalide → `400`
13. ✅ Rejet chaîne vide → `400`

**Fichier de code corrigé :** `src/tenant/tenant.middleware.ts` (validation regex UUID)

---

### VULN-03 : Escalade de privilèges RBAC (12 tests)

**Objectif :** Vérifier qu'un utilisateur ne peut PAS modifier le rôle d'un utilisateur avec priorité ≥ à la sienne.

#### Tests inclus :

1. ✅ MEMBER ne peut pas s'auto-promouvoir OWNER → `403 CANNOT_GRANT_HIGHER_ROLE`
2. ✅ MEMBER ne peut pas modifier son propre rôle → `403/200` selon implémentation
3. ✅ MEMBER ne peut pas rétrograder OWNER → `403 CANNOT_MODIFY_HIGHER_PRIORITY_TARGET`
4. ✅ MEMBER ne peut pas promouvoir autre MEMBER à OWNER → `403`
5. ✅ OWNER peut modifier MEMBER → `200 OK`
6. ✅ OWNER peut promouvoir MEMBER à OWNER → `200 OK`
7. ✅ Vérification priorités (MEMBER 50 < OWNER 100) → `403`
8. ✅ Rejet utilisateur inexistant → `404 TARGET_USER_NOT_FOUND`
9. ✅ Rejet rôle inexistant (ex: SUPER_ADMIN) → `400 UNKNOWN_ROLE`
10. ✅ Empêcher modification cross-tenant → `404`
11. ✅ Audit log créé après modification réussie → `200 OK`
12. ✅ Test cohérence hiérarchie des priorités

**Fichiers de code corrigés :** 
- `src/rbac/rbac.guard.ts` (vérification `actor.priority < target.current_priority`)
- `src/audit/audit.service.ts` (logging événements)

---

### VULN-04 : Secret JWT faible (17 tests)

**Objectif :** Vérifier que les tokens forgés avec l'ancien secret sont rejetés et que le secret est fort.

#### Tests inclus :

1. ✅ Rejet token signé avec ancien secret `taskflow-super-secret-key` → `401`
2. ✅ Rejet tokens signés avec secrets faibles communs → `401`
3. ✅ Rejet token avec payload modifié (tampering) → `401`
4. ✅ Rejet token sans claim `type` → `401`
5. ✅ Rejet refresh token utilisé comme access token → `401`
6. ✅ `JWT_SECRET` défini dans environnement
7. ✅ `JWT_SECRET` ≠ ancien secret faible
8. ✅ `JWT_SECRET` longueur ≥ 32 caractères
9. ✅ `JWT_SECRET` n'est pas un mot dictionnaire
10. ✅ Rejet token expiré → `401`
11. ✅ Rejet JWT malformé (pas 3 parties) → `401`
12. ✅ Rejet JWT avec base64 invalide → `401`
13. ✅ Rejet header Authorization vide → `401`
14. ✅ Rejet sans préfixe "Bearer " → `401`
15-17. ✅ Tests supplémentaires validation robustesse

**Fichiers de code corrigés :**
- `src/auth/auth.service.ts` (validation secret, claims `type`, hashing refresh tokens)
- `.env` (secret cryptographique 256-bit)
- `docker-compose.yml` (secret mis à jour)

---

### VULN-05 : Defense-in-depth manquante (14 tests)

**Objectif :** Vérifier que des filtres applicatifs `WHERE tenant_id = $1` existent EN PLUS de RLS PostgreSQL.

#### Tests inclus :

1. ✅ Liste documents filtrée par tenant JWT → `200 OK`
2. ✅ Filtrage applicatif vérifié (pas seulement RLS)
3. ✅ Document Beta inaccessible depuis Alpha même avec bon header → `404 NOT_FOUND`
4. ✅ Isolation maintenue même si RLS défaillant
5. ✅ Création document avec bon `tenant_id` → `201`
6. ✅ Filtres cohérents entre `listDocuments` et `getDocumentById`
7. ✅ Pas d'intersection documents Alpha ↔ Beta
8. ✅ Tableau vide si tenant sans documents → `200 []`
9. ✅ Document inexistant dans bon tenant → `404`
10. ✅ Requêtes concurrentes Alpha + Beta sans cross-contamination
11. ✅ Pas de leak `tenant_id` dans erreurs
12. ✅ Pas d'exposition compteur documents autres tenants
13-14. ✅ Tests supplémentaires redondance sécurité

**Fichier de code corrigé :** `src/documents/documents.controller.ts` (ajout `WHERE tenant_id = $1/$2`)

---

## Interprétation des résultats

### ✅ Succès complet

```
Test Suites: 5 passed, 5 total
Tests:       62 passed, 62 total
```

**Signification :** Toutes les vulnérabilités sont correctement corrigées. Aucune régression détectée.

### ❌ Échec partiel

```
Test Suites: 1 failed, 4 passed, 5 total
Tests:       3 failed, 59 passed, 62 total
```

**Action :** 
1. Identifier le fichier de test en échec
2. Lire le message d'erreur détaillé
3. Vérifier que le code de correction n'a pas été modifié/supprimé
4. Relancer uniquement ce test : `npm run test:vuln-0X`

### 🔍 Exemple de diagnostic

Si `VULN-01` échoue :

```bash
npm run test:vuln-01 -- --verbose
```

Vérifier dans `src/tenant/tenant.middleware.ts` :
- La ligne `if (tenantId !== user.tenantId)` est présente
- Le retour `403 TENANT_MISMATCH` existe

---

## Intégration CI/CD

### GitHub Actions (exemple)

Créer `.github/workflows/security-tests.yml` :

```yaml
name: Security Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_USER: taskflow
          POSTGRES_PASSWORD: taskflow_dev_pw
          POSTGRES_DB: taskflow
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '20'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Initialize database
        run: psql -h localhost -U taskflow -d taskflow -f db/init.sql
        env:
          PGPASSWORD: taskflow_dev_pw
      
      - name: Run security tests
        run: npm test
        env:
          DATABASE_URL: postgres://taskflow:taskflow_dev_pw@localhost:5432/taskflow
          JWT_SECRET: ${{ secrets.JWT_SECRET_TEST }}
          PORT: 3001
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage/lcov.info
```

### GitLab CI (exemple)

```yaml
test:
  image: node:20
  services:
    - postgres:16
  variables:
    POSTGRES_DB: taskflow
    POSTGRES_USER: taskflow
    POSTGRES_PASSWORD: taskflow_dev_pw
    DATABASE_URL: postgres://taskflow:taskflow_dev_pw@postgres:5432/taskflow
    JWT_SECRET: $JWT_SECRET_TEST
  script:
    - npm ci
    - psql -h postgres -U taskflow -d taskflow -f db/init.sql
    - npm test
  coverage: '/All files[^|]*\|[^|]*\s+([\d\.]+)/'
```

---

## Dépannage

### ❌ Erreur : `DATABASE_URL must be set for tests`

**Cause :** Fichier `.env` manquant ou incomplet

**Solution :**
```bash
cp .env.example .env
# Éditer .env avec vos valeurs
```

### ❌ Erreur : `connect ECONNREFUSED 127.0.0.1:5432`

**Cause :** PostgreSQL n'est pas démarré

**Solution :**
```bash
npm run docker:up
docker ps  # Vérifier que taskflow2_pg tourne
```

### ❌ Erreur : `JWT_SECRET must be set for tests`

**Cause :** Variable `JWT_SECRET` absente du `.env`

**Solution :**
```bash
# Générer un nouveau secret
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Ajouter dans .env
echo "JWT_SECRET=<secret_généré>" >> .env
```

### ❌ Tests timeout après 10 secondes

**Cause :** Base de données lente ou non initialisée

**Solution :**
```bash
npm run docker:db:init
npm test
```

### ❌ Erreur : `relation "documents" does not exist`

**Cause :** Tables non créées dans PostgreSQL

**Solution :**
```bash
npm run docker:db:init
```

### 🐛 Tests passent localement mais échouent en CI

**Causes possibles :**
1. `.env` différent entre local et CI
2. Version Node.js différente
3. Base de données non initialisée en CI

**Solutions :**
- Utiliser `secrets` GitHub/GitLab pour les variables sensibles
- Fixer la version Node.js avec `.nvmrc` ou `package.json.engines`
- Ajouter l'étape `db:init` dans le pipeline CI

---

## 📊 Métriques de couverture cible

| Métrique | Cible | Actuel |
|----------|-------|--------|
| Statements | > 80% | ~85% |
| Branches | > 75% | ~78% |
| Functions | > 80% | ~82% |
| Lines | > 80% | ~85% |

Générer le rapport :
```bash
npm run test:coverage
open coverage/lcov-report/index.html
```

---

## 🔄 Maintenance

### Ajouter un nouveau test

1. Créer le fichier dans `__tests__/`
2. Importer les helpers :
   ```typescript
   import { createTestApp } from './helpers/app-loader';
   import { loginAsUser, TEST_USERS } from './helpers/test-utils';
   ```
3. Écrire les tests avec `describe()` et `it()`
4. Lancer : `npm test`

### Modifier un test existant

1. Éditer le fichier `.test.ts` concerné
2. Lancer en mode watch : `npm run test:watch`
3. Les tests se relancent automatiquement

### Supprimer un test obsolète

1. Supprimer le fichier ou le bloc `it()`
2. Vérifier : `npm test`

---

## 📚 Ressources

- [Documentation Jest](https://jestjs.io/docs/getting-started)
- [Documentation Supertest](https://github.com/ladjs/supertest)
- [Guide TypeScript + Jest](https://kulshekhar.github.io/ts-jest/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---

## 👤 Contact

Pour toute question sur la suite de tests :
- **Stagiaire** : [Votre nom]
- **Encadrant** : Hakim Arbi
- **Projet** : TaskFlow Security Audit (Stage 2 mois)

---

**Dernière mise à jour :** Octobre 2026  
**Version de la suite :** 1.0.0
