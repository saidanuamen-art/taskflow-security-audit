# Explication des tests de sécurité — TaskFlow

Ce document explique **chacun des 71 tests** automatisés : ce qu'il fait, le résultat attendu et pourquoi il compte. Il explique aussi ce qui a été corrigé dans la suite de tests et un constat d'audit important sur le RLS.

> Règle de lecture : pour un test de sécurité, **« le test passe » = « l'attaque est bloquée »**.

---

## 1. Lancer les tests

Pré-requis : la base `taskflow2_pg` tourne (`npm run docker:up`) et contient les données de `db/init.sql`.

```bash
npm test                # les 71 tests
npm run test:vuln-01    # une seule vulnérabilité (01 à 05)
npm run test:verbose    # le nom de chaque test s'affiche
```

Résultat attendu : `Tests: 71 passed, 71 total`. Un lancement prend environ 20 s.

**Variables d'environnement** (`.env`) : `DATABASE_URL` (rôle `taskflow_app`, celui de l'application, soumis au RLS) et `ADMIN_DATABASE_URL` (rôle `taskflow`, administrateur). Les tests utilisent la connexion admin **uniquement** pour préparer la base et lire la vérité de référence ; tout le comportement testé passe par la connexion applicative.

**Comptes utilisés** (mot de passe `Password123!`) :

| Compte | Tenant | Rôle (priorité) |
|---|---|---|
| owner@alpha.test | Alpha `1111…` | OWNER (100) |
| member@alpha.test | Alpha `1111…` | MEMBER (50) |
| owner@beta.test | Beta `2222…` | OWNER (100) |
| member@beta.test | Beta `2222…` | MEMBER (50) |

**Fonctionnement d'un test.** Le test se connecte via `POST /auth/login` (helper `loginAsUser`) et récupère un JWT. Il envoie ensuite des requêtes HTTP à l'application avec `supertest`, puis vérifie le code HTTP, le message d'erreur et, si besoin, **l'état réel de la base**.

---

## 2. Ce qui a été corrigé dans les tests

Avant correction : 9 tests en échec sur 56, et des tests qui passaient sans rien prouver. Aujourd'hui : 71 tests, soit 6 + 13 + 16 + 19 + 17.

| Problème | Conséquence | Correction |
|---|---|---|
| Les tests utilisaient une **copie** des routes (`app-loader.ts`), différente de la vraie app : `/rbac/change-role` avec `requireRole(100)`, sans middleware tenant | On testait une app qui n'existe pas. 2 tests VULN-03 échouaient avec `FORBIDDEN` | `src/main.ts` exporte `app`, et les tests utilisent **la vraie app** (`/api/users/change-role`, `requireRole(50)`) |
| VULN-03 modifiait les rôles en base **sans les remettre** | Effet domino : `member@alpha` devenait OWNER, puis `owner@alpha` était rétrogradé MEMBER. Cela cassait les tests et Swagger, et empirait à chaque lancement | `resetSeedRoles()` remet les rôles d'origine **avant chaque test** et à la fin |
| Assertions dans des `if (docs.length > 0)` | Sans données, le test passait sans rien vérifier | Remplacées par un pré-requis explicite : `expect(docs.length).toBeGreaterThan(0)` |
| Tests qui vérifiaient seulement « c'est un tableau » | Ils ne prouvaient rien | Comparaison avec la **base de données** (source de vérité) |
| Le test d'audit ne lisait pas `audit_logs` | L'audit n'était pas vérifié | Il lit maintenant la table `audit_logs` |
| VULN-04 « token sans type » : `jwt.sign` recevait à la fois `exp` et `expiresIn` | Crash de la librairie, pas de l'API | Le token est signé directement sans claim `type` |
| VULN-05 créait des documents à chaque lancement | La base de dev se remplissait | Les documents créés sont supprimés en fin de suite |
| Connexions PostgreSQL jamais fermées, logs dotenv | Sortie Jest polluée | `pool.end()` et `quiet: true` dans `__tests__/setup.ts` |

Fichiers modifiés : `src/main.ts` (export de `app`, pas de `listen` sous Jest), `__tests__/setup.ts`, `__tests__/helpers/app-loader.ts`, `__tests__/helpers/test-utils.ts`, et les 5 fichiers `vuln-0X`.

---

## 3. Constat d'audit H0 : le RLS ne protégeait rien (corrigé)

**Constat.** L'application se connectait à PostgreSQL avec le rôle `taskflow`, créé par l'image Docker (`POSTGRES_USER`). Ce rôle est :
- **superutilisateur avec `BYPASSRLS`** : il ignore *toutes* les policies RLS, même avec `FORCE ROW LEVEL SECURITY` ;
- **propriétaire des tables** : sans `FORCE`, le propriétaire est lui aussi exempté.

Preuve : avec `app.current_tenant_id` fixé sur Alpha, `SELECT … FROM documents` renvoyait aussi les documents Beta. Une première tentative avec `FORCE` seul **n'a rien changé** (les tests l'ont montré) : la cause racine était le superutilisateur.

**Correctif appliqué** (`db/harden_rls.sql`, repris dans `db/init.sql`) :
1. **Rôle applicatif dédié `taskflow_app`** : ni superutilisateur, ni `BYPASSRLS`, ni propriétaire ; seulement `SELECT/INSERT/UPDATE/DELETE`. `DATABASE_URL` (`.env` et `docker-compose.yml`) l'utilise. `taskflow` reste réservé à l'administration.
2. **`FORCE ROW LEVEL SECURITY`** sur `documents` et `users` (protection même si le rôle devenait un jour propriétaire).
3. **Policies « fail-closed »** : `tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid`, en `USING` et `WITH CHECK`. Sans tenant fixé : aucune ligne visible, aucune écriture.
4. **Login via une fonction `SECURITY DEFINER`** `auth_find_user_by_email(email)` : au login, le tenant n'est pas encore connu ; cette fonction ne permet que cette recherche précise.
5. **`tenantMiddleware`** : tenant fixé par `set_config('app.current_tenant_id', $1, false)` (paramètre lié, plus de concaténation SQL), et **remis à vide avant de rendre la connexion au pool**. Sinon, la requête suivante sur cette connexion hériterait du tenant précédent.
6. **Changement de rôle** : utilise la connexion de la requête (tenant de l'acteur fixé) ; le RLS de `users` limite donc aussi la cible au tenant de l'acteur.

Base existante : `npm run docker:db:harden`. Résultat : l'isolation repose maintenant sur **deux couches indépendantes**, chacune testée seule (VULN-05, tests 6 à 10).

---

## 4. VULN-01 : contournement de l'isolation entre tenants (6 tests)

**La faille** : le tenant était lu dans le header `x-tenant-id`, que le client contrôle. Un utilisateur Alpha pouvait mettre l'id de Beta et lire ses données.
**Le correctif** (`src/tenant/tenant.middleware.ts`) : le header doit être **égal** au `tenantId` signé dans le JWT. Sinon : `403 TENANT_MISMATCH`.

| # | Test | Ce qu'il fait | Attendu | Pourquoi |
|---|---|---|---|---|
| 1 | reject request when x-tenant-id does not match JWT | Token Alpha + header Beta sur `GET /api/documents` | `403 TENANT_MISMATCH` | C'est l'attaque d'origine |
| 2 | allow request when x-tenant-id matches JWT | Token Alpha + header Alpha | `200` + tableau | Le correctif ne doit pas bloquer l'usage normal |
| 3 | prevent cross-tenant data access via document creation | Token Alpha + header Beta sur `POST /api/documents`, puis lecture en base | `403` et **aucun document « Malicious Document » chez Beta** | Empêche d'écrire dans un autre tenant, pas seulement de lire |
| 4 | reject request with missing x-tenant-id | Pas de header | `400 MISSING_TENANT_ID` | Pas de tenant « par défaut » implicite |
| 5 | Alpha cannot access Beta resources | Prend un vrai id de document Beta, Alpha le demande avec le header Beta | `403 TENANT_MISMATCH` | Même en connaissant l'id exact, l'accès est refusé |
| 6 | each tenant only sees their own documents | Liste Alpha et liste Beta | Aucun id en commun (les deux listes doivent être non vides) | Isolation complète dans les deux sens |

---

## 5. VULN-02 : injection SQL via `x-tenant-id` (13 tests)

**La faille** : le middleware construit `SET app.current_tenant_id = '${tenantId}'` par concaténation de chaîne. Un header contenant `'` permettait d'injecter du SQL.
**Le correctif** : le header doit respecter le format UUID (`/^[0-9a-f]{8}-…-[0-9a-f]{12}$/i`), sinon `400 INVALID_TENANT_ID`. La validation a lieu **avant** toute requête SQL.

**Attaques bloquées** → toutes attendent `400 INVALID_TENANT_ID` :

| # | Test | Valeur envoyée | Type d'injection |
|---|---|---|---|
| 1 | SQL injection payload | `'; DROP TABLE documents; --` | Destruction de table |
| 2 | SQL comment injection | `1111…' OR '1'='1` | Condition toujours vraie |
| 3 | UNION-based injection | `' UNION SELECT * FROM users--` | Extraction d'une autre table |
| 4 | stacked queries | `1111…'; DELETE FROM audit_logs; --` | Effacement des traces d'audit |
| 5 | time-based blind | `'; SELECT pg_sleep(10); --` | Injection « à l'aveugle » par délai |
| 6 | boolean-based | `1111…' AND 1=1--` | Injection « à l'aveugle » par vrai/faux |

**UUID valides acceptés** (non-régression) → attendu : **pas** `400`.

| # | Test | Valeur | Remarque |
|---|---|---|---|
| 7 | lowercase | `11111111-…` | Renvoie `200` |
| 8 | uppercase | `11111111-…` en majuscules | Format accepté (pas `400`), puis `403 TENANT_MISMATCH` car la comparaison avec le JWT est sensible à la casse. Comportement sûr |
| 9 | mixed case | UUID valide | `200` |

**Cas limites** → `400` :

| # | Test | Valeur |
|---|---|---|
| 10 | extra characters | `1111…1111extra` |
| 11 | missing dashes | `11111111111111111111111111111111` |
| 12 | completely invalid | `not-a-valid-uuid` |
| 13 | empty string | `''` (renvoie `400 MISSING_TENANT_ID`) |

> Défense en profondeur (appliquée) : en plus de la regex, le tenant est maintenant fixé par `SELECT set_config('app.current_tenant_id', $1, false)` avec un **paramètre lié**. Il n'y a plus aucune concaténation SQL : même si la regex était un jour supprimée, l'injection resterait impossible.

---

## 6. VULN-03 : escalade de privilèges RBAC (16 tests)

**La faille** : `POST /api/users/change-role` vérifiait seulement que l'acteur avait le droit d'attribuer **le nouveau rôle**, pas qu'il avait le droit de toucher **à la cible**. Un MEMBER pouvait donc rétrograder un OWNER en GUEST (GUEST < MEMBER, donc « autorisé »).
**Le correctif** (`src/rbac/rbac.guard.ts`) : la cible est cherchée **dans le tenant de l'acteur**, et `actor.priority < target.priority` donne `403 CANNOT_MODIFY_HIGHER_PRIORITY_TARGET`. Chaque changement réussi **et chaque refus** est écrit dans `audit_logs`, qui est en ajout seul (`db/harden_audit.sql`).

**Ordre des contrôles dans le code** (il explique les codes d'erreur attendus) :
1. `requireRole(50)` : priorité de l'acteur < 50 → `403 FORBIDDEN`
2. rôle demandé inconnu → `400 UNKNOWN_ROLE`
3. rôle demandé > priorité de l'acteur → `403 CANNOT_GRANT_HIGHER_ROLE`
4. cible absente du tenant de l'acteur → `404 TARGET_USER_NOT_FOUND`
5. cible plus haute que l'acteur → `403 CANNOT_MODIFY_HIGHER_PRIORITY_TARGET`
6. sinon : mise à jour, puis ligne `user.role_changed` dans `audit_logs` → `200 {ok:true}`

Les rôles d'origine sont remis avant chaque test. Les tests vérifient aussi **le rôle réel en base** après la requête, pas seulement le code HTTP.

| # | Test | Scénario | Attendu |
|---|---|---|---|
| 1 | MEMBER cannot promote themselves to OWNER | member@alpha → lui-même → OWNER | `403 CANNOT_GRANT_HIGHER_ROLE`, rôle en base toujours MEMBER |
| 2 | GUEST cannot promote themselves to MEMBER | L'OWNER rétrograde member en GUEST, puis le GUEST se reconnecte et tente de redevenir MEMBER | `403 FORBIDDEN` (bloqué par `requireRole(50)`), reste GUEST |
| 3 | MEMBER cannot modify OWNER role | member → owner → GUEST | `403 CANNOT_MODIFY_HIGHER_PRIORITY_TARGET`, owner reste OWNER. **C'est l'attaque d'origine** |
| 4 | MEMBER cannot promote another MEMBER to OWNER | member → id quelconque → OWNER | `403 CANNOT_GRANT_HIGHER_ROLE` (refusé avant même de chercher la cible) |
| 5 | OWNER can change another user to MEMBER | owner → member → MEMBER | `200`, rôle MEMBER en base |
| 6 | OWNER can promote MEMBER to OWNER | owner → member → OWNER | `200`, rôle OWNER en base (annulé ensuite par le reset) |
| 7 | priority-based access control | member → owner → MEMBER | `403 CANNOT_MODIFY_HIGHER_PRIORITY_TARGET` |
| 8 | non-existent users | owner → `00000000-…` | `404 TARGET_USER_NOT_FOUND` |
| 9 | unknown role names | owner → member → `SUPER_ADMIN` | `400 UNKNOWN_ROLE` |
| 10 | users from other tenants | owner@alpha → member@beta → GUEST | `404 TARGET_USER_NOT_FOUND`, member@beta inchangé (on ne peut même pas savoir que l'utilisateur existe) |
| 11 | log successful role changes | owner → member → GUEST, puis lecture de `audit_logs` | 1 ligne `user.role_changed` avec le bon tenant, le bon acteur, `newRoleName: GUEST` et `actorRole: OWNER` |
| 12 | log refused role changes as denied | MEMBER tente de devenir OWNER (403) | 1 ligne `user.role_change_denied` (motif `CANNOT_GRANT_HIGHER_ROLE`), **aucune** ligne `user.role_changed` |
| 13 | log access denied by the role guard | Un GUEST appelle la route (403 `FORBIDDEN`) | 1 ligne `authz.denied` avec `requiredPriority: 50`, `actorPriority: 10` |
| 14 | app role cannot modify audit logs | `UPDATE` / `DELETE` sur `audit_logs` avec le rôle applicatif | `permission denied` |
| 15 | even an admin cannot modify audit logs | `UPDATE` / `DELETE` / `TRUNCATE` en superutilisateur | Refusé par le trigger : « audit_logs est en ajout seul » |
| 16 | app can still append | `INSERT` avec le rôle applicatif (transaction annulée) | 1 ligne insérée. La transaction est annulée car une ligne de test ne pourrait plus jamais être supprimée |

> Pourquoi ces tests : un journal qu'on peut modifier n'a aucune valeur de preuve, et un refus non journalisé rend une tentative d'escalade invisible.

---

## 7. VULN-04 : secret JWT faible et authentification (19 tests)

**La faille** : le JWT était signé avec un secret en dur et devinable (`taskflow-super-secret-key`). N'importe qui pouvait fabriquer un token OWNER valide.
**Le correctif** (`src/auth/auth.service.ts`) : secret fort lu dans `JWT_SECRET` (l'app refuse de démarrer sans), et vérification que `type === "access"`.

**Tokens falsifiés** → tous attendent `401` :

| # | Test | Ce qui est envoyé | Pourquoi |
|---|---|---|---|
| 1 | old weak secret | Token OWNER signé avec `taskflow-super-secret-key` | L'attaque d'origine |
| 2 | common weak secrets | Tokens signés avec `secret`, `password`, `admin`, `123456`, `your-secret-key`, `jwt-secret`… | Secrets testés en premier par un attaquant (brute force par dictionnaire) |
| 3 | tampered payload | Vrai token MEMBER dont on change `priority: 50 → 100` sans re-signer | La signature ne correspond plus, donc refus |
| 4 | without "type" claim | Token signé avec le **bon** secret mais sans `type` | Seuls les tokens explicitement `access` sont acceptés |
| 5 | refresh token as access token | Le `refreshToken` du login dans `Authorization` | Un refresh token (7 jours) ne doit pas donner accès à l'API |

**Qualité du secret** (lecture de `process.env.JWT_SECRET`) :

| # | Test | Vérifie |
|---|---|---|
| 6 | variable is set | `JWT_SECRET` existe et n'est pas vide |
| 7 | not the old weak secret | ≠ `taskflow-super-secret-key` |
| 8 | sufficiently long | ≥ 32 caractères |
| 9 | cryptographically random | Ne commence pas par `password`, `secret`, `admin`, `123456`…, ni par 6 caractères identiques |

> Ces 4 tests vérifient le `.env` **local**. Le secret de `docker-compose.yml` doit aussi être fort, et ne devrait pas être commité dans Git.

**Tokens invalides ou mal formés** → `401` :

| # | Test | Envoi |
|---|---|---|
| 10 | expired access tokens | Token valide mais expiré depuis 1 h |
| 11 | malformed (not 3 parts) | `header.payload` |
| 12 | invalid base64 | `invalid!!!.payload!!!.signature!!!` |
| 13 | empty authorization header | `Authorization: ` vide (renvoie `MISSING_TOKEN`) |
| 14 | missing Bearer prefix | Token valide sans `Bearer ` (renvoie `MISSING_TOKEN`) |

**Protection contre le brute force sur `/auth/login`** (`src/auth/login-rate-limit.ts`). Seuls les échecs comptent : 5 par compte (IP + email) ou 20 par IP, sur 15 minutes. Chaque test utilise un email unique, pour ne jamais bloquer les comptes de test réels.

| # | Test | Ce qu'il fait | Attendu |
|---|---|---|---|
| 15 | block after 5 failed attempts | 5 mauvais mots de passe, puis une 6e tentative | 5 × `401 INVALID_CREDENTIALS`, puis `429 TOO_MANY_ATTEMPTS` avec en-tête `Retry-After` |
| 16 | other accounts not affected | Un compte bloqué, puis connexion d'un vrai compte | Le vrai compte reçoit `200` |
| 17 | successful logins never blocked | 8 connexions réussies d'affilée | `200` à chaque fois |
| 18 | lockout logged | 5 échecs | 1 ligne `auth.login_blocked` dans `audit_logs` |
| 19 | malformed request | Login sans mot de passe | `400 INVALID_REQUEST` |


---

## 8. VULN-05 : défense en profondeur (17 tests)

**La faille** : les requêtes sur `documents` ne filtraient pas par `tenant_id` et comptaient uniquement sur le RLS PostgreSQL, qui en plus ne filtrait rien (voir §3).
**Le correctif** : deux couches indépendantes.
- **Applicative** (`src/documents/documents.controller.ts`) : `WHERE tenant_id = $n` avec le tenant du **JWT**, dans `listDocuments` et `getDocumentById` ; `createDocument` utilise aussi le tenant du JWT.
- **Base de données** : RLS réellement active (rôle `taskflow_app`, `FORCE`, policies fail-closed, voir §3).

Plusieurs tests comparent la réponse de l'API à une lecture **directe en base** faite en admin (`getDocumentIdsInDb`) : c'est la seule façon de prouver « ni plus, ni moins ». Les tests 6 à 10 testent la couche RLS **seule**, avec la connexion applicative et des requêtes SQL **sans** filtre applicatif.

| # | Test | Ce qu'il fait | Attendu |
|---|---|---|---|
| 1 | only documents of the user tenant | Listes Alpha et Beta | Les deux listes sont non vides et n'ont aucun id commun |
| 2 | exactly the tenant documents stored in DB | Liste Alpha comparée aux ids Alpha en base | **Identiques** (aucun doc manquant, aucun doc en trop) |
| 3 | other tenants documents by ID | Alpha demande un vrai id Beta, avec **son propre** header (valide) | `404 NOT_FOUND`. VULN-01 ne bloque pas ce cas : seules les couches applicative et RLS le font |
| 4 | create in JWT tenant and read back | Alpha crée un doc | `201`, `tenant_id` = Alpha en base, Alpha le relit (`200`), Beta reçoit `404` |
| 5 | consistent filters on all endpoints | Chaque doc de la liste Alpha est lu par id ; chaque doc Beta est demandé par Alpha | Alpha : `200` partout. Docs Beta : `404` partout |
| 6 | **RLS alone** hides other tenants documents | Contexte Alpha, `SELECT DISTINCT tenant_id FROM documents` **sans** `WHERE` | Uniquement le tenant Alpha : le RLS filtre à lui seul |
| 7 | **RLS on users** hides other tenants users | Contexte Alpha, `SELECT DISTINCT tenant_id FROM users` | Uniquement Alpha |
| 8 | RLS **fail-closed** when no tenant is set | Connexion applicative sans tenant, `SELECT count(*) FROM documents` | `0` (et pas d'erreur) : oublier de fixer le tenant ne fuit rien |
| 9 | RLS blocks **insert** into another tenant | Contexte Alpha, `INSERT` d'un document avec `tenant_id` Beta | Erreur `row-level security policy` (`WITH CHECK`) |
| 10 | no tenant leak between **pooled connections** | 5 requêtes API Alpha, puis 5 requêtes sans contexte sur le pool | `0` document à chaque fois : le tenant est bien effacé avant de rendre la connexion |
| 11 | isolated through the API (filter + RLS) | Des docs Beta existent en base. Liste Alpha via l'API | Aucun doc Beta dans la réponse |
| 12 | ignore tenant_id sent in body on CREATE | Alpha crée un doc avec `tenant_id: Beta` dans le body | `201`, mais enregistré dans **Alpha** (mass assignment impossible) |
| 13 | empty array for tenant with no documents | Le test crée un tenant temporaire Gamma (sans documents) et un utilisateur, puis les supprime | `[]` exactement (et pas les docs des autres tenants) |
| 14 | 404 for non-existent document | Id `00000000-…` | `404 NOT_FOUND` |
| 15 | concurrent requests | Alpha et Beta en parallèle | Chaque liste correspond exactement à sa base |
| 16 | no tenant leak in error messages | Alpha demande un **vrai** id Beta | Réponse exactement `{ "error": "NOT_FOUND" }`, identique à un doc inexistant : impossible de deviner qu'il existe ailleurs |
| 17 | no document count from other tenants | Liste Alpha | Taille = nombre de docs Alpha en base, aucun champ `tenant_id` exposé |

> Leçon de mise au point : la première version du test 9 utilisait `INSERT … SELECT id FROM users WHERE email = 'owner@beta.test'`. En contexte Alpha, le RLS de `users` cache cet utilisateur : 0 ligne insérée, aucune erreur, et le test ne testait rien. L'id est maintenant lu en admin avant l'`INSERT`.

> Remarque d'audit : `GET /api/documents/:id` fait `SELECT *` et renvoie donc `tenant_id` et `owner_id` au propriétaire. Ce n'est pas une fuite entre tenants, mais mieux vaut lister explicitement les colonnes renvoyées.

---

## 9. Lire un résultat

```
Test Suites: 5 passed, 5 total
Tests:       71 passed, 71 total
```

- **Un test VULN-0X échoue** : soit la protection a été cassée (régression de sécurité), soit la base n'a pas les données de `db/init.sql`.
- **Un test RLS de VULN-05 (6 à 10) échoue** : vérifier que `DATABASE_URL` utilise bien `taskflow_app` (et pas `taskflow`, superutilisateur) et que `npm run docker:db:harden` a été appliqué.
- **`ADMIN_DATABASE_URL must be set`** : ajouter la connexion admin dans `.env` (voir `.env.example`).
- **`connect ECONNREFUSED 127.0.0.1:5432`** : la base ne tourne pas, lance `npm run docker:up`.
- Les tests écrivent dans la **même base** que l'app de dev, mais ils remettent les rôles et suppriment ce qu'ils créent. Seuls des refresh tokens et des lignes `audit_logs` s'accumulent : ces dernières ne peuvent plus être supprimées, puisque le journal est en ajout seul.
