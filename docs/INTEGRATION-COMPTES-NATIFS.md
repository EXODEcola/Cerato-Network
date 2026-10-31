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
