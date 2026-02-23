# Plan de Réunification `master`/`develop` et Modernisation Maximale

## Résumé

Objectif: obtenir une base unique moderne, sans merge commit, avec:

- `develop` pour le développement
- `master` comme branche stable déployable

Tout en conservant une capacité de rollback immédiat vers l'état serveur actuel (`4bad3b4`, 21 août 2019).

Stratégie:

1. Partir de `develop` (base Python 3).
2. Rejouer uniquement les deltas utiles de `master`.
3. Moderniser runtime, dépendances et stack push.
4. Réaligner `develop` et `master` sur le même commit final (historique linéaire).

## État cible

À la fin:

1. `develop` et `master` pointent vers le même commit.
2. Aucun nouveau merge commit dans la réunification.
3. Des références de secours existent:
   - `backup/master-legacy-2020-03-15` (`419291a`)
   - `backup/develop-legacy-2014-12-12` (`64c8907`)
   - `backup/hub-master-2019-08-21` (`4bad3b4`)
4. Runtime Python moderne uniquement.
5. Notifications push migrées vers outils actuels (FCM + APNS token auth).

## Politique de branches et d'historique

1. Réécriture d'historique autorisée sur `develop` et `master`.
2. Réécriture avec `force-with-lease` uniquement.
3. Conservation des dates sur les commits rejoués lorsque possible:
   - conserver `author date` et `committer date` d'origine au moment du replay.
4. `master` reste stable; `develop` reste la branche d'intégration.
5. L'ancienne `master` est conservée explicitement pendant la fenêtre de migration.

## Deltas `master` à conserver pendant la réunification

À intégrer sur la base `develop`:

- durcissements `.gitignore` (`0e71dd7`, `cebb016`, `5ed85df`)
- assets de similarité webcam (`fbc7830`, `4bad3b4`)
- ajustements de dépendances utiles (au cas par cas, sans réintroduire de stack Python 2)

À ne pas rejouer:

- commits de bruit ou non fonctionnels (`c8b30af`, `%`)
- doublons historiques déjà couverts fonctionnellement dans `develop`

## Interfaces et compatibilité API

### Push Android

1. Endpoint canonique: `/fcm`
2. Compatibilité: conserver `/gcm` en alias pendant une release.
3. Même validation métier des champs d'entrée.

### Push iOS

1. Endpoint conservé: `/apns`
2. Backend APNS migré de certificat vers token auth HTTP/2.
3. Support sandbox/prod maintenu via config.

### Payloads

1. Accepter temporairement:
   - `coords.lat/lng`
   - `coords.latitude/longitude`
2. Normaliser en interne vers un format unique.

### Websocket

1. Conserver `/socket` et `/socket/send`.
2. Aucun breaking change dans cette phase.

## Configuration

Mettre à jour `config.example.ini`:

1. Déprécier `gcm_api_key`
2. Ajouter configuration FCM:
   - `fcm_project_id`
   - `fcm_service_account_file`
3. Déprécier les paramètres APNS certificat
4. Ajouter configuration APNS token:
   - `apns_key_id`
   - `apns_team_id`
   - `apns_bundle_id`
   - `apns_auth_key_file`

## Plan d'exécution

## Phase 0 — Sécurisation

1. Geler temporairement les pushes sur `master` et `develop`.
2. Créer et pousser les branches/tags backup (`origin` + `hub`).
3. Vérifier que la prod suit toujours `hub/master` et que `hub/master` est sauvegardée.

## Phase 1 — Réunification Git sans merge commit

1. Créer `codex/reunify-modernize-2026-02-19` depuis `develop`.
2. Rejouer les deltas utiles de `master` par cherry-pick sélectif ou port manuel.
3. Résoudre conflits en privilégiant la compatibilité Python 3.
4. Générer un fichier de mapping de traçabilité `old_sha -> new_sha`.

## Phase 2 — Modernisation Python/dépendances

1. Cible runtime: Python 3.12 (minimum accepté: 3.11).
2. Supprimer dépendances obsolètes / Python 2.
3. Migrer vers dépendances maintenues et verrouillées.
4. Introduire `requirements.in` + `requirements.txt` locké.
5. Corriger SQL concaténé restant vers requêtes paramétrées.

## Phase 3 — Migration Push

1. Implémenter provider FCM moderne (HTTP v1).
2. Implémenter APNS token auth moderne.
3. Conserver compatibilité d'API avec alias `/gcm` temporaire.
4. Garder une double lecture/écriture transitoire des clés cache si nécessaire.

## Phase 4 — Validation

1. Tests unitaires:
   - validation payloads push
   - logique de notification
   - utilitaires géographiques
2. Tests intégration:
   - routes Tornado
   - websocket subscribe/update
   - push providers mockés
3. Quality gates:
   - compilation Python 3 de tous les `.py`
   - lint/type checks (selon outillage choisi)
4. Go/No-Go:
   - zéro échec critique
   - pas de régression fonctionnelle sur endpoints legacy

## Phase 5 — Déploiement et rollback

1. Déployer d'abord en validation/staging.
2. Conserver `hub/master` actuelle tant que la validation n'est pas complète.
3. Basculer `develop`, puis `master`, sur le SHA final validé.
4. En cas d'incident, rollback immédiat vers `backup/hub-master-2019-08-21`.

## Fichiers à traiter en priorité

- `server.py`
- `handlers/gcm.py`
- `handlers/apns.py`
- `handlers/traffic.py`
- `traffic_loader.py`
- `road_watcher.py`
- `requirements.txt`
- `config.example.ini`

## Tests et scénarios minimaux

1. Enregistrement Android via `/gcm` (alias) et `/fcm`.
2. Enregistrement iOS via `/apns`.
3. Notification simulée pour chaque langue (`fr`, `nl`, `en`, `de`).
4. Mise à jour d'abonnement websocket (`code=4`).
5. Parsing trafic et webcam sans crash Python 3.
6. Reconnexion service avec ancienne config puis nouvelle config.

## Assomptions verrouillées

1. Réécriture d'historique autorisée.
2. Conservation temporaire de l'ancienne `master` requise.
3. Migration push complète demandée (GCM retiré fonctionnellement, compat API temporaire).
4. Objectif de modernisation élevé (pas une simple fusion Git).
