# Plan de Migration: `aioapns` + `asyncmy` + SQLAlchemy Core 2 + Alembic

## Objectif

Moderniser la stack backend pour:

1. supprimer les dépendances legacy/non maintenues,
2. fiabiliser la compatibilité Python moderne,
3. standardiser l'accès DB et les migrations de schéma.

## Cible Technique

- APNS: `aioapns`
- MySQL driver async: `asyncmy`
- DB layer: `SQLAlchemy Core 2.x` (mode async)
- Migrations: `Alembic`
- Runtime recommandé: Python `3.12` (support visé `3.10+`)

## Périmètre

### Inclus

1. Remplacement de la couche push APNS actuelle par `aioapns`.
2. Remplacement de la couche DB custom par `SQLAlchemy async` + `asyncmy`.
3. Introduction d'un dossier de migrations Alembic versionné.
4. Migration progressive des requêtes SQL vers SQLAlchemy Core 2.

### Exclu (phase ultérieure)

1. Réécriture complète métier des workers.
2. Refonte API produit.
3. Migration ORM complète (on reste en Core 2, pas ORM).

## Décisions d'architecture

1. **Core 2 avant ORM**: moins risqué pour un code existant très SQL-centric.
2. **Wrapper de compatibilité temporaire**: exposer une API `execute(...)` transitoire pour migrer fichier par fichier.
3. **Migration incrémentale**: pas de big-bang; chaque lot reste testable et déployable.
4. **APNS async isolé**: un provider dédié (`push/apns_provider.py`) injecté dans le gateway.

## Plan par phases

## Phase 0 — Préparation

1. Geler la branche de migration (`codex/push-modernization`).
2. Ajouter outils qualité minimaux:
   - lint/format,
   - tests unitaires ciblés,
   - checks CI pour install deps + import app.
3. Fixer la matrice runtime:
   - `3.12` obligatoire,
   - `3.10`/`3.11`/`3.13` best effort,
   - `3.14` non bloquante tant que non stabilisée upstream.

## Phase 1 — Introduire SQLAlchemy async + asyncmy

1. Ajouter dépendances:
   - `SQLAlchemy>=2`,
   - `asyncmy`,
   - `alembic`.
2. Créer module DB:
   - engine async,
   - fabrique de connexions,
   - helper `execute` transitoire.
3. Basculer le bootstrap serveur vers ce module sans changer encore toute la couche handlers.

Livrable:

- serveur démarre avec engine SQLAlchemy async,
- routes existantes toujours actives.

## Phase 2 — Basculer les requêtes vers Core 2

1. Migrer par lots:
   - `handlers/base.py`,
   - `handlers/dashboard.py`,
   - `handlers/analytics.py`,
   - `server.py` (requêtes notifications/trafic).
2. Remplacer concaténation SQL par requêtes paramétrées `text(...)`.
3. Uniformiser les retours (mapping dict-like) pour éviter les régressions.

Critère:

- plus aucun accès DB via couche legacy.

## Phase 3 — Introduire Alembic

1. Initialiser `alembic/`:
   - `env.py`,
   - template de révisions.
2. Créer baseline depuis schéma courant production.
3. Ajouter migrations initiales non destructives:
   - indexes manquants,
   - contraintes évidentes,
   - colonnes nécessaires aux évolutions futures (si besoin).
4. Documenter workflow:
   - `upgrade head`,
   - rollback d'une révision.

Critère:

- migration DB reproductible en local/staging.

## Phase 4 — Migrer APNS vers aioapns

1. Ajouter provider `aioapns` dédié.
2. Maintenir même contrat applicatif:
   - même logique de sélection des subscribers,
   - mêmes logs fonctionnels.
3. Support token-based auth Apple (prioritaire) + configuration stricte.
4. Gérer erreurs APNS de façon explicite:
   - invalid token -> purge cache ciblée,
   - erreurs temporaires -> retry borné.

Critère:

- envoi APNS de test fonctionnel,
- invalidation token vérifiée.

## Phase 5 — Nettoyage & durcissement

1. Retirer code/dépendances legacy:
   - anciens wrappers DB,
   - anciennes libs APNS.
2. Ajouter tests de non-régression sur endpoints push + analytics.
3. Stabiliser observabilité:
   - logs d'envoi push,
   - métriques erreurs DB/APNS.

## Plan de tests

1. Tests unitaires:
   - conversion payload push,
   - mapping erreurs provider,
   - helpers SQL.
2. Tests intégration:
   - endpoints `/apns`, `/fcm`, analytics,
   - cycle DB (read/write notifications).
3. Smoke tests locaux:
   - serveur boot,
   - connexion DB,
   - push APNS sandbox réel.
4. Tests migration DB:
   - `upgrade head`,
   - `downgrade -1` sur staging.

## Stratégie de rollout

1. Déployer en staging d'abord.
2. Exécuter Alembic avant bascule applicative.
3. Activer nouveau provider APNS via flag/config.
4. Surveiller erreurs pendant fenêtre de validation.

## Rollback

1. Revenir au tag applicatif précédent.
2. Si migration DB réversible: `alembic downgrade`.
3. Sinon: rollback app + hotfix SQL manuel documenté.

## Risques et atténuations

1. **Risque**: différences de comportement SQL entre wrapper legacy et SQLAlchemy.
   - **Atténuation**: migration par lots + tests snapshot de réponses.
2. **Risque**: régressions APNS sur invalidation token.
   - **Atténuation**: tests réels sandbox iOS + logs structurés d'erreurs APNS.
3. **Risque**: dépendances non compatibles Python 3.14.
   - **Atténuation**: cibler 3.12 pour prod à court terme.

## Critères de fin

1. Aucune dépendance DB/APNS legacy restante.
2. Toutes les migrations DB versionnées dans Alembic.
3. Serveur stable sur Python 3.12 avec pipeline de tests vert.
4. Documentation d'exploitation à jour (config + commandes de migration).
