# Comptes natifs Cerato Network — intégration progressive

## État

Ce lot est **préproduction uniquement**. Il ne modifie pas le backend de
`51.210.223.57` ni l'interface actuellement servie sur le port 8787.
Les releases CSS signées et les contrôles de mise à jour Web existants
continuent normalement.

Branche : `feature/secure-accounts-ui`.

## Gestion des comptes

- **Owner** : identité principale créée une seule fois, immuable depuis
  les comptes secondaires. Accès aux comptes, au réseau et aux mises à jour.
- **Admin** : coadministration des machines, réseau, comptes secondaires
  et mises à jour ; ne peut pas supprimer, modifier ni prendre le rôle Owner.
- **User** : consultation expurgée uniquement. Ne voit pas les détails
  d'IP, configurations WireGuard, secrets, règles d'administration ou
  journaux sensibles dans la réponse API.
- Les utilisateurs peuvent modifier leur propre adresse ou mot de passe
  en fournissant leur mot de passe actuel. Une nouvelle authentification
  est obligatoire après ce changement.
- Une modification de rôle, de mot de passe, une désactivation ou une
  réinitialisation MFA révoque les sessions existantes.
- Les Owner/Admin doivent compléter TOTP ou utiliser un code de récupération
  à usage unique. Un simple mot de passe ne crée pas de session privilégiée.

## Changements dans ce lot

`web/live-auth-overlay.js` :
- actions « Mon profil » et « Comptes et accès » adaptées au rôle ;
- activation/désactivation des comptes secondaires ;
- changement de rôle Admin/User ;
- réinitialisation du mot de passe et de la 2FA d'un administrateur
  secondaire, avec confirmation explicite ;
- graphiques et formulaires cohérents avec le thème Graphite et la
  palette Cerato Network.

`security/legacy_auth_api.py` :
- liste explicite des champs modifiables ;
- refus des champs inconnus, des requêtes PATCH vides et des
  champs de création incomplets ;
- respect du contrôle des rôles et de la validation CSRF existants.

## Raccordement au panneau historique (préparé)

- L'interface native fournit un adaptateur `legacyFetch` qui transmet
  automatiquement le **nouveau** `X-Cerato-CSRF` sur les modifications
  `/api/` strictement internes, sans jamais l'ajouter aux URL externes
  ou aux routes de connexion et de comptes.
- Les requêtes GET ne sont pas transformées et aucune connexion ne peut
  passer en écriture sans un compte validé et son jeton CSRF. Le **backend**
  continue de vérifier lui-même la session, la permission et l'origine.
- **Fail closed pour les lecteurs** : aucune requête User n'exécute un
  ancien handler HTTP. Pour la vue d'ensemble, un fournisseur explicite
  `netstate()` est projeté par `viewer_projection`, puis sérialisé par
  le nouveau pont HTTP. Si ce fournisseur manque, l'accès est refusé.
  C'est nécessaire car les anciens handlers pouvaient sérialiser par
  `_json()` ou écrire directement dans le flux, contournant un filtrage
  fondé uniquement sur `send_json()`.
- La préparation de l'interface refuse les variantes historiques
  sans `fetch()` et chemins API vérifiés, ainsi que toute interface
  dont l'empreinte n'est pas approuvée.
- Les tests utilisent un véritable mini-serveur HTTP **localhost**
  en CI (aucune connexion à l'OVH), y compris les tentatives anonymes,
  écritures sans CSRF, rôle User, login historique et MFA.

Aucune de ces protections n'est activée sur la machine OVH pour le moment.
L'ancienne interface publique continue de fonctionner tant que le
basculement et le rollback n'ont pas été revus de bout en bout.

## Résultat réel du précontrôle OVH — 31 octobre 2026

Le diagnostic local (sans export du code privé) confirme :

- **Un** gestionnaire HTTP historique, avec des chemins GET et POST identifiés.
- Routes API attendues présentes, sans route inconnue ni route non classifiée.
- Les deux anciens endpoints `/api/login` et `/api/logout` sont encore actifs.
- Une couche HTTP Basic est toujours déclarée dans Nginx.
- `ProtectSystem=strict`, `ProtectHome=yes` et `PrivateTmp=yes`.
- Stockage `/var/lib/cerato-network-auth` absent, et aucune exception
  `ReadWritePaths` pour ce stockage.
- La baseline initiale ne correspond plus aux fichiers déployés ;
  ce fait **ne doit pas** entraîner l'acceptation automatique des nouveaux hashes.

Un outil `integrations/prepare_private_auth_storage.py` permet de
préparer **uniquement** le dossier de comptes (propriétaire `ceratonet`,
permissions `0700`). Par défaut, `--check` ne modifie rien ;
`--install` crée seulement le dossier s'il n'existe pas. Aucune clé,
base SQLite, identité Owner ou session n'est créée par cet outil.

Le fragment `deploy/cerato-native-auth-storage.conf` prépare une
exception systemd de **seul** répertoire
`ReadWritePaths=/var/lib/cerato-network-auth`. Il est **inactif** dans
le dépôt et ne doit pas être appliqué avant la migration contrôlée.
La création du dossier ne signifie pas que les comptes sont activés.

## Dernières corrections et répétition privée

Le backend RISE-1 actuel définit `do_GET` et `do_POST`, **pas**
`do_PATCH` ni `do_DELETE`. Le pont HTTP génère désormais ces deux
méthodes supplémentaires **dans sa copie privée**, pour les seules
routes de l'API native authentifiée. Tout chemin réseau historique
ou méthode non explicitement autorisée continue d'être refusé. Les tests
HTTP réels en localhost couvrent :
- `PATCH /api/auth/me` avec réauthentification et CSRF ;
- `PATCH /api/accounts/{id}` pour les modifications de rôle ;
- `DELETE /api/accounts/{id}` pour les comptes secondaires ;
- refus des variantes PATCH/DELETE sur NAT, firewall, etc. ;
- refus sans session, sans CSRF, avec origine hostile ou en rôle User.

`integrations/rehearse_native_auth.py` prépare et compile les candidats
backend/frontend exclusivement dans un répertoire temporaire privé,
supprimé automatiquement. Le script n'**importe ni n'exécute** le serveur
historique ; il ne crée aucun socket ni ne teste les véritables commandes
WireGuard et NAT.

Il refuse un hash backend/frontend ne correspondant pas à une baseline
réellement approuvée. Le rapport OVH du 31/10 signale précisément que
la baseline initiale est **périmée**. **Ne pas la mettre à jour en
copiant automatiquement les empreintes observées :** ce serait supprimer
le contrôle d'approbation, et non vérifier la migration.

Cette répétition valide la syntaxe et la structure privées, pas la
capacité d'activer l'authentification sur le RISE-1 ni un rollback réel.

## Validations avant bascule

1. Vérifier la **vraie structure** de l'actuel `server.py` et ses
   routes. Il n'est pas présent comme source complète dans GitHub.
2. Intégrer une seule connexion native et retirer les anciennes
   authentifications sans désactiver les protections trop tôt.
3. Raccorder les sessions/CSRF de `/api/auth/me` à toutes les
   actions de l'ancien frontend. Le jeton CSRF hérité du backend ne
   doit pas être confondu avec celui de la nouvelle session.
4. Auditer les réponses de chaque route API pour les utilisateurs
   lecture seule. La dissimulation des boutons ne constitue jamais
   une autorisation côté serveur.
5. Exécuter les tests HTTP de bout en bout pour Owner/Admin/User,
   TOTP, récupération MFA, anti-CSRF, révocation des sessions, NAT,
   WireGuard et le centre de mises à jour.
6. Valider sauvegarde et retour arrière, puis signer une release
   de migration compatible avec l'installation OVH. La première
   release `v0.1.0-beta.1` n'est qu'un correctif CSS.

**Ne pas déployer ce lot automatiquement.** La signature GitHub ne
doit pas installer un nouveau backend sans un contrôle explicite de
compatibilité avec l'installation RISE-1 et un rollback testé.

Aucune commande ni intervention nécessaire sur CERATO-BUILD-01.
