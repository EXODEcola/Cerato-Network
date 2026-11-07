# Cerato Network — interface intégrée et modèle IPv4 routé

Statut : **console de développement fonctionnelle, non déployée sur RISE-1**.
La console de production conserve ses fichiers historiques et ses attributions publiques.
Toute migration en production exige une validation locale complète puis une release signée Ed25519.

## Contrat produit

### Routage IPv4 — pas de publication NAT par port

- Une IPv4 supplémentaire OVH est affectée entièrement à une machine raccordée en WireGuard, avec un routage `/32` et une route de retour vérifiée.
- **Le nombre de publications NAT peut rester égal à zéro lorsque le routage est opérationnel.** L'interface distingue systématiquement les allocations routées des anciennes publications.
- Les IPv4 attribuées ne sont jamais réaffichées comme « Disponibles ». Les collisions entre IP, machine et mode `local-nat` ou `routed-wg` entraînent un refus, pas une modification corrective automatique.
- La machine possède son propre filtrage des ports ; le panneau n'expose pas de formulaire de DNAT TCP/UDP comme mécanisme principal.
- La création, révocation, réaffectation ou migration d'une IPv4 implique un préflight réseau, l'identité de la machine, une validation de la propriété de l'IP chez l'hébergeur, un rollback armé et un canal SSH de secours. **Aucune modification de ce type n'est activée dans le serveur de développement.**

### Authentification et permissions

- Un propriétaire principal unique est créé par code d'initialisation SSH à usage limité. Aucun compte ou mot de passe par défaut.
- Email + mot de passe Argon2 ; pour Owner/Admin, session privilégiée seulement après MFA TOTP valide. Codes de récupération à usage unique. Compte User en lecture seule avec réponses expurgées côté backend.
- Session serveur stockée en cookie `HttpOnly; Secure; SameSite=Strict` ; aucun secret ni jeton dans `localStorage`. Origine et CSRF vérifiés sur les actions.
- Owner protégé contre suppression/modification par les autres comptes ; le co-administrateur peut gérer les autres comptes selon la politique RBAC.
- Les listes de comptes exposent uniquement les informations publiques, le statut MFA et le **nombre** de sessions actives, jamais les jetons ou les secrets.
- Les anciens endpoints de connexion historique doivent être rendus inaccessibles et HTTP Basic retiré **uniquement à la fin du basculement testé**. Un simple écran de connexion ne constitue pas une migration des autorisations.

### UX transversale

- Une navigation URL `#/dashboard`, `#/routes`, `#/machines`, `#/accounts`, `#/updates`, `#/profile` conserve la section après F5 et prend en charge les boutons Précédent/Suivant du navigateur.
- Aucune page restreinte ne devient accessible par manipulation du hash : la session et les permissions serveur restent les arbitres.
- Palette graphite homogène, accent vert/gris discret, surfaces rectangulaires, tableaux lisibles, états indisponibles explicites ; aucune donnée fictive, aucun gradient néon.
- Composants et messages identiques pour la connexion, le MFA, la gestion des comptes, le réseau et les mises à jour ; affichage responsive et `prefers-reduced-motion`.

## Ce qui est prêt dans le code

1. `gateway/http_api.py` fournit `GET /api/ip/allocations`, exclusivement en lecture et soumis à la politique `view_sensitive`. La commande privilégiée autorisée est uniquement `sudo -n /usr/local/sbin/cerato-ipctl status`. En mode d'authentification isolé, l'accès retourne une indisponibilité explicite.
2. `web/app.js` affiche la vue « Routage IPv4 », les attributions et leurs états réels, la navigation persistante, les écrans Owner/Admin/User/MFA existants, et l'état des sessions/MFA des comptes.
3. `web/style.css` est un système de design unifié ; la nouvelle interface ne concatène plus plusieurs thèmes historiques.
4. Des tests HTTP, RBAC, MFA, status IPv4, compatibilité de la navigation et absence de mutation NAT par port sont exécutés dans GitHub Actions, sans accès à OVH ou au Dell.

## Conditions **non remplies** pour le basculement du RISE-1

- La source du backend historique `/opt/cerato-network/backend/server.py` est privée et a été modifiée par les releases signées IPv4. Les anciennes empreintes d'octobre 2026 sont donc obsolètes ; **ne pas les réutiliser** pour un remplacement.
- L'overlay d'authentification préparatoire dans `security/live_http_bridge.py` et `web/live-auth-overlay.js` doit être testé contre cette version exacte du backend et toutes les routes de production (y compris le nouveau `GET /api/ip/allocations`).
- Démontrer sur une copie locale isolée du serveur réel : bootstrap, login, MFA, changement de mot de passe, permissions Owner/Admin/User, CSRF, cookies, refus de l'ancien mot de passe, navigation F5, statut réel WireGuard, mise à jour signée, rollback complet, reprise HTTPS.
- Appliquer un correctif backend **signé et vérifié localement**. Ne jamais distribuer la source privée de `server.py` via GitHub, ne jamais remplacer le backend avec `gateway/http_api.py`.
- Ne retirer la protection de connexion historique et ne permettre les opérations de routage `/32` depuis le Web qu'après ces vérifications et un plan de restauration validé. Les anciens endpoints de NAT par port doivent être désactivés lors de cette migration, sans toucher aux règles réseau déjà en service.

## Limites de déploiement

- **OVH RISE-1, Dell R530 et WireGuard sont hors de toute intervention automatique de ce lot.**
- **VM Build non utilisée** : les validations sont exécutées dans GitHub Actions.
- Les versions `-dev.N` publiées sur GitHub sont des aperçus sources non signés et **ne doivent jamais être installées sur le panneau de production**.
- Le mécanisme de distribution HTTPS signée de Cerato Network demeure l'unique voie pour une version Web installable.
