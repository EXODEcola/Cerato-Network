# Activation contrôlée des comptes natifs sur Cerato Network RISE-1 / 8787

Statut : **préparation testée, NON activée sur OVH**. La version de production connue est `v0.1.2-beta.1`. Aucune étape de ce document n'autorise le retrait de HTTP Basic, de l'ancien login, ni le déploiement du frontend de développement sur le port 8787.

## Contrainte de compatibilité

Les empreintes historiques d'octobre 2026 de `backend/server.py` et `web/app.js` ne sont plus utilisables comme base de remplacement après les releases signées `v0.1.1-beta.1` et `v0.1.2-beta.1`.

Le backend réellement installé **n'est pas publié dans GitHub** et peut contenir des données privées. Les copies doivent rester exclusivement sur OVH dans un répertoire root `0700` ; elles ne doivent jamais être jointes à un ticket GitHub, à un chat, à une release ou au dépôt. Ne pas déplacer cette opération vers la VM Build.

## Étape A : audit réel en lecture seule

Exécuter `integrations/audit_live_8787_auth_cutover.py --check` sur la VM Cerato Network OVH. Il lit le backend et l'interface installés, les indicateurs de Nginx, systemd et du stockage privé, puis émet uniquement :
- Empreintes SHA-256 du backend, JavaScript et CSS, et tailles des fichiers.
- Unicité du handler historique, protection des méthodes HTTP et couverture des routes connues ; nombre des routes non classifiées, **jamais** leur contenu.
- Présence du modèle de routage `/32` et des correctifs de NAT, du JavaScript signé et des neuf rubriques du panneau.
- Présence éventuelle de la configuration `CERATO_WEB_ORIGIN`, des dépendances Argon2 et cryptography, et de l'emplacement privé des comptes.
- L'ancien login, HTTP Basic et l'absence de nouvelles sessions restent détectables par indicateurs booléens, sans exposer les mots de passe ni les directives Nginx.

Les champs `safe_to_cut_over`, `safe_to_disable_legacy_login`, `safe_to_modify_nginx`, `production_modified` et `network_modified` valent **toujours false**, même après un audit vert.

## Étape B : candidat privé et inactif

Après validation des résultats de l'audit, `integrations/stage_current_live_auth_candidate.py --stage` :
1. Calcule les empreintes exactes des fichiers courants depuis la VM elle-même ; elles servent à lier **la copie inerte**, pas à autoriser la production.
2. Vérifie les routes, marqueurs signés, structure HTTP et les neuf rubriques.
3. Crée sous `/var/backups` un répertoire unique privé `0700` avec son manifeste, un `server/backend/server.py` transformé et les modules `security/`, et un `client/web/` enrichi.
4. Ajoute à la copie JavaScript l'authentification Owner/Admin/User, le MFA, la gestion de comptes, un adaptateur CSRF limité aux écritures de même origine, et la persistance de la navigation `#/overview`, `#/ips`, `#/machines`, etc.
5. Exige la compilation Python et `node --check`, puis recompare les empreintes originales : un changement concurrent invalide l'opération et supprime seulement la copie nouvellement créée.
6. N'exécute pas les scripts de production, ne crée pas d'utilisateurs, de base SQLite, de port HTTP ni de service, et ne redémarre pas Nginx.

Le dossier candidat contient des sources **confidentielles** : ne jamais le publier.

## Étape C : validation avant activation

À réaliser sur une copie isolée du **véritable** backend RISE-1, pas sur `gateway/http_api.py` de développement :
- Vérifier l'URL HTTPS effective, `Host` et `Origin`, la politique Nginx, le cookie `HttpOnly; Secure; SameSite=Strict`, les protections systemd et les versions de dépendances.
- Réaliser la création du seul Owner avec token SSH à usage limité, le MFA obligatoire Owner/Admin, la révocation, les codes de récupération et les sessions persistantes.
- Éprouver les accès Viewer expurgés sur **toutes** les routes réseau et de mise à jour, ainsi que la protection Owner contre la modification et la suppression.
- Tester tous les formulaires historiques de routage (y compris les écritures), le CSRF sur chaque méthode, les routes inconnues, la désactivation de `/api/login` et `/api/logout`.
- Contrôler navigation/F5, attribution routée Dell, pages machines, pare-feu, topologie, mises à jour, historique, rollback et absence de tout appel réseau inattendu.
- Tester une restauration complète depuis une sauvegarde en cas de défaillance après coupure.

**Ne jamais** activer le backend, retirer HTTP Basic ou migrer le navigateur sur la seule base d'un audit AST vert ou d'une compilation syntaxique.

## Étape D : publication et activation

Une fois C validée, préparer un patch signé Ed25519 s'appliquant *localement* aux empreintes approuvées du backend et du frontend privés. Le ZIP GitHub ne contient jamais `server.py` ni la base d'authentification. Installation avec sauvegarde et rollback via l'onglet « Mises à jour » existant.

Conserver l'ancien service d'accès et la configuration de réseau tant que les connexions Owner/Admin/User et tous les endpoints n'ont pas passé les tests HTTP, puis procéder au remplacement de l'ancienne protection dans une opération atomique et réversible.

## Invariants réseau non négociables

Aucun changement sur `wg-cerato`, le Dell R530, les IP additionnelles routées, `ip rule`, nftables, NAT actuel, le port SSH, les interfaces WAN, les clés du tunnel, Nginx actif ou la VM Build pendant A/B.

Le nouveau produit expose en priorité les **attributions IPv4 complètes /32** et non des formulaires de redirection NAT par port ; l'ancien moteur reste présent jusqu'à migration explicite, afin de préserver les services existants.

Le code de ce lot est publié dans une release de développement **non installable**. Il ne faut pas la pousser sur le miroir HTTPS signé OVH.
