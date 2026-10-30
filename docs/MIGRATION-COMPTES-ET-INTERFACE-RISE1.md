# Migration réelle du panneau unique RISE-1 : comptes, sous-utilisateurs, 2FA et nouvelle interface

## Diagnostic réel du 30 octobre 2026

Le RISE-1 possède **une seule console active sur le port 8787**, avec ses modules historiques de gestion réseau (`backend/server.py`, `web/app.js`). L'import Additional IPv4 et la nouvelle page Mises à jour ont été raccordés par des patchs ciblés. La page Mises à jour affiche « Version historique » et « Distribution non configurée » : **aucune release officielle compatible n'est encore installable**.

Les nouveaux modules `security/auth_store.py`, `security/access_policy.py`, `security/mfa.py`, `web/app.js` et `gateway/http_api.py` ont été développés et testés séparément, mais **ne sont pas intégrés au service Web historique sur 8787**. Le nouveau backend de développement ne gère pas encore toutes les actions réseau : le remplacer en direct ferait régresser la console.

Le serveur Dell R530 est sous **Ubuntu 24.04**, avec son pair WireGuard existant (`10.77.0.2`), et deviendra ensuite un hôte **Cerato Panel**. Aucune reconfiguration du Dell n'est nécessaire pour la migration des comptes Web du RISE-1.

## Ce qui doit être intégré, sans installation parallèle

1. **Compatibilité du backend existant.** Identifier les routes et points de vérification de la session du service **réel**, et figer un inventaire de compatibilité. Les anciens endpoints sont maintenus.
2. **Noyau d'authentification.** Ajouter `AuthStore` au même service `cerato-network-web.service` sous le compte Unix `ceratonet`, avec une base et une clé AES privées. Aucun compte par défaut.
3. **Prise en charge du propriétaire unique.** Définir e-mail/mot de passe depuis l'interface avec un code initial SSH temporaire. Enclencher le 2FA obligatoire avant toute autorisation d'action réseau.
4. **RBAC backend de toutes les anciennes routes.** Un rôle `user` est **lecture seule**, avec résultat expurgé côté serveur. Les `owner` et `admin` peuvent exploiter le réseau avec contrôle CSRF et session TOTP validée. Les comptes admin ne peuvent ni supprimer ni réinitialiser le propriétaire.
5. **Nouvelle interface intégrée.** Reprendre l'interface moderne, l'écran de connexion, les comptes et sous-utilisateurs tout en conservant les vraies pages IPv4, NAT, pare-feu, machines/tunnels, topologie et mises à jour.
6. **Basculement progressif.** Sauvegarde de l'ancien système d'authentification et des comptes, compatibilité testée, accès de secours, activation atomique des nouvelles sessions et désactivation contrôlée de l'ancien mot de passe. **Ne jamais laisser l'ancienne session administrateur contourner le rôle lecture seule.**
7. **Publication signée.** Le VPS **CERATO-BUILD-01** prépare et teste un overlay compatible avec 8787. Signature approuvée séparément, distribution HTTPS et installation depuis la page Mises à jour. Pas de build/compression/signature via GitHub Actions.

## Inventaire de compatibilité sans exporter de secrets

Sur le **RISE-1**, après mise à jour du dépôt :

~~~bash
cd ~/Cerato-Network
git pull --ff-only origin feature/secure-accounts
python3 integrations/inspect_live_auth_compat.py
~~~

Cette commande :
- lit seulement `/opt/cerato-network/backend/server.py` et `/opt/cerato-network/web/app.js` ;
- extrait des **noms de routes API, noms de fonctions d'authentification, sections UI et empreintes SHA-256** ;
- n'affiche pas de lignes source, mots de passe, IP, clés, données WireGuard ni fichiers de configuration ;
- n'ouvre aucun port, ne modifie pas les permissions, la configuration, la base de données ou les services.

L'outil refuse les chemins symboliques, et le rapport est volontairement limité à des métadonnées. Il ne peut pas déduire les autorisations réelles à partir des noms de routes uniquement : une revue des fonctions de session/CSRF et du routage d'origine reste obligatoire avant déploiement.

Une fois cet inventaire validé, les règles à documenter et tester se trouvent dans `security/legacy_policy.py` ; les routes inconnues y sont interdites. **Ce module n'est pas encore importé par le backend actif.**

Sur **CERATO-BUILD-01**, les tests de développement sont :

~~~bash
cd ~/Cerato-Network
bash scripts/update-dev.sh
~~~

Les nouvelles suites `tests/test_live_auth_compat.py` et `tests/test_legacy_policy.py` doivent réussir. Ne pas annoncer leur réussite avant réception du résultat.

## Pourquoi le centre des mises à jour affiche une erreur

Le centre a été installé, mais la source HTTPS officielle et la clé publique de confiance **n'ont pas encore été configurées**. Après le clic « Rechercher », le contrôleur ne peut pas trouver de release signée. Le message générique « Échec de vérification » n'implique pas que WireGuard, l'adresse OVH ou la connexion Dell sont en panne.

Il faut publier une première release **compatible** et enregistrer sa source HTTPS/clé de confiance par un mécanisme d'approbation hors bande (une fois), puis les mises à jour suivantes pourront être réalisées depuis le panneau.

## Bloquants avant de pouvoir annoncer « nouvelle interface + sous-utilisateurs opérationnels »

- Validations réelles du backend installé, en particulier ses handlers d'API et protections de session existantes.
- Intégration de l'authentification dans le service 8787, **pas en parallèle**.
- Tests de droits sur chaque API réseau déjà utilisée, tests du 2FA, test de perte de session et restauration.
- Construire une release **overlay** reprenant les fichiers compatibles avec le panneau historique, pas l'archive générale du dépôt.
- Validation du rollback sur installation réelle avec console OVH de secours.
- Chaîne de signature/distribution officielle avant activation de l'installation Web.

**Ne pas remplacer `/opt/cerato-network/backend/server.py` par `gateway/http_api.py`. Ne pas supprimer la configuration WireGuard, le pool IPv4, les mappings NAT ou la base du panneau existant.**
