# Raccordement des comptes natifs — statut vérifié (31 octobre 2026)

## Ce qui a été réellement ajouté

Sur `feature/secure-accounts`, `security/live_http_bridge.py` permet de
faire passer **toutes les anciennes routes /api/** par un seul point
d'autorisation. Le raccordement refuse les sessions de l'ancien mot de passe,
valide le cookie de session moderne, le rôle Owner/Admin/User, le TOTP des
comptes privilégiés, l'Origin sur les écritures et le jeton CSRF. Les routes
inconnues sont refusées. Un compte User ne peut utiliser que la lecture autorisée
et son statut passe par une projection expurgée **avant** sérialisation.

Les endpoints modernes `/api/auth/*` et `/api/accounts*` sont reliés à
`security/legacy_auth_api.py`; les anciennes routes `/api/login` et
`/api/logout` reçoivent un statut 410 lorsque le bridge est actif. Aucune
permission ne repose sur le masquage de boutons du navigateur.

`integrations/stage_live_auth_backend.py` prépare une **copie privée** du
backend actuel après vérification stricte de son empreinte. Il refuse les
structures inconnues, les classes ambigües et tout répertoire situé sous
l'installation active. Il ne modifie pas le serveur, les comptes, le réseau,
Nginx, le service 8787 ou le mécanisme de mise à jour.

Les tests de `tests/test_live_http_bridge.py` et
`tests/test_stage_live_auth_backend.py` couvrent les refus de connexion
historique, l'expiration de session, l'accès administrateur, le CSRF, les
comptes en lecture seule, la double authentification et la préparation privée.

## Limites d'activation

**Le bridge n'est PAS activé sur RISE-1.** Le backend réel
`/opt/cerato-network/backend/server.py` n'est pas présent sur GitHub ; son
inventaire de routes et son empreinte ont été vérifiés, mais cela ne garantit
pas que l'ancienne interface fonctionnera avec les nouvelles sessions.
Le code de développement `web/app.js` possède déjà les écrans Owner,
Admin, User et TOTP, mais il ne remplace pas les pages réseau du RISE-1.

Avant le basculement :
1. Tester la version préparée avec **une copie privée complète** du serveur
   HTTP installé, en inspectant localement les handlers et leur compatibilité
   avec la nouvelle session.
2. Intégrer l'écran de connexion natif dans l'interface réseau existante,
   en conservant toutes ses pages et son moteur de mises à jour.
3. Valider un test navigateur réel, avec connexion initiale par token SSH,
   obligation du TOTP avant accès admin, rôle User expurgé, interdiction des
   anciennes routes, sous-utilisateurs et gestion des sessions.
4. Préparer un **basculement atomique réversible** ; retirer HTTP Basic seulement
   lorsque l'authentification native fonctionne de bout en bout et que le
   retour arrière est vérifié.
5. Configurer une vraie source HTTPS et une clé publique Ed25519 approuvée
   avant toute installation par le centre de mises à jour.

Ne **jamais** distribuer, publier ou téléverser la copie préparée de
`server.py` : elle peut contenir des données privées. Les releases
compatibles devront appliquer un patch signé **sur le serveur cible** plutôt
que republier son backend.

## Infrastructure conservée

Le Dell R530 (`10.77.0.2`), le tunnel `wg-cerato`, l'IPv4
`54.37.165.151`, le NAT TCP 8080, les règles de pare-feu, les sessions
actuelles et la page d'administration historique **ne sont pas modifiés** par
ce lot.

La vérification automatique du dépôt exécute toutes les suites sur GitHub
Actions. Elle ne remplace pas le test du basculement réel sur RISE-1.
