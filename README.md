# TaskFlow — Playground SaaS multi-tenant (usage pédagogique)

⚠️ Ce dépôt est un environnement d'entraînement fictif. Aucune donnée, aucun nom de
client, aucun processus métier réel n'y figure. "TaskFlow" est un faux SaaS de gestion
de tâches en équipe (multi-organisation), choisi uniquement parce qu'il reproduit les
mêmes patterns d'architecture qu'une vraie plateforme SaaS B2B multi-tenant, sans
révéler de quoi que ce soit sur le produit d'origine.

## Contexte du produit fictif

TaskFlow permet à plusieurs organisations (tenants) de gérer leurs tâches et documents
internes sur une même plateforme mutualisée. Chaque tenant a des utilisateurs avec des
rôles différents (Owner, Member, Guest en lecture seule). Les données doivent être
strictement cloisonnées entre tenants.

## Stack technique

- Backend : Node.js + Express + TypeScript
- Base de données : PostgreSQL avec Row-Level Security (RLS)
- Auth : JWT (access + refresh token)
- RBAC : rôles avec priorité numérique (anti-escalade)

## Démarrage

```bash
docker compose up -d        # lance postgres
npm install
cp .env.example .env
npm run db:init             # crée le schéma + seed 2 tenants / plusieurs users
npm run dev
```

## Comptes de test (seed)

Mot de passe pour tous les comptes ci-dessous : `Password123!`

| Email | Tenant | Rôle |
|---|---|---|
| owner@alpha.test | Tenant Alpha | OWNER |
| member@alpha.test | Tenant Alpha | MEMBER |
| owner@beta.test | Tenant Beta | OWNER |
| member@beta.test | Tenant Beta | MEMBER |

## Ce que ce repo contient (volontairement)

Ce playground n'est PAS un exemple de code propre. Il contient un mélange de patterns
corrects et de vulnérabilités volontairement injectées, représentatives de risques
réels sur ce type d'architecture (isolation tenant, RBAC, gestion de sessions,
secrets, logs). Voir `docs/sujet_stage_playground.md` pour la mission complète.

## Ce que ce repo ne contient PAS

- Aucune logique métier réelle d'un produit existant
- Aucun schéma de données représentant un vrai produit
- Aucun identifiant, log ou donnée réelle

Toute ressemblance avec un produit existant se limite au *pattern d'architecture*
(multi-tenant + RLS + RBAC + JWT), qui est un standard extrêmement répandu dans le
SaaS B2B — pas une signature identifiable d'un produit en particulier.
