# Cerato Network — point d'entrée privé de l'authentification

## État réellement confirmé sur RISE-1 OVH, 7 novembre 2026

Le panneau continue de servir la bêta signée `v0.1.2-beta.1`. Le test privé des comptes natifs a réussi : 20 échanges simulés, Owner/Admin MFA, User expurgé, CSRF, Origin et ancien login rejeté. La copie privée inactive est vérifiée, et Argon2id 25.1.0 / cryptography 47.0.0 ont été testés sous `ceratonet`.

Le diagnostic `audit_private_live_http_boundary.py` a confirmé un handler, 20 routes connues, zéro route inconnue, zéro méthode non prise en charge et 35 paires de permissions. Il a aussi dénombré **10 instructions de module potentiellement exécutables** et **8 sites d'appel possiblement externes ou réseau**. Un site d'appel n'est pas la preuve qu'un appel a eu lieu.

## Nouvelle classification sans exécution

Le script `integrations/audit_private_live_startup_map.py --check` :
- recalcule le préflight hash du backend actif, de la copie privée, des modules de sécurité, et du venv natif ;
- sépare les 8 sites d'appel potentiels selon le contexte : au chargement du module, dans le bloc littéral `if __name__ == "__main__"`, ou dans des fonctions/méthodes différées ;
- dénombre les imports, décorateurs, définitions de classe, affectations dynamiques et autres instructions au niveau du module, sans les exécuter ;
- analyse **aussi le candidat privé** et vérifie l'existence du décorateur `@_cerato_secure_handler` appliqué au handler et de la construction `_CeratoAuthStore` qu'il appelle.

Seuls des indicateurs numériques/boolean sont retournés. Aucun code serveur, ligne du backend, valeur de configuration, compte, clé, chemin temporaire ou adresse n'est exporté. L'exécution de `server.py` reste interdite par le rapport.

## Important : création du stockage d'authentification à l'import

Le code `integrations/stage_live_auth_backend.py` prépare `@_cerato_secure_handler`. À la définition de la classe HTTP Python, ce décorateur construit immédiatement `_CeratoAuthStore(Path("/var/lib/cerato-network-auth/accounts.sqlite3"))`.

`AuthStore.__init__` crée ou accède au répertoire, initialise `mfa-encryption.key` et initialise les tables SQLite. **Exécuter directement le candidat privé peut donc créer des comptes/une clé dans le stockage réel** même si aucun utilisateur n'ouvre un navigateur et si le port 8787 n'est pas utilisé.

Un futur banc d'essai exécutant le vrai code historique devra isoler **aussi** le chemin `/var/lib/cerato-network-auth` sous un stockage de test, pas seulement le port HTTP. L'accès aux vrais fichiers secrets/réseau doit être refusé. Des protections `PrivateNetwork`, un environnement d'utilisateur non privilégié, des permissions systemd/chroot/namespaces pertinentes, une séparation de l'IPv4 publique, des routes d'écriture et du rollback devront être démontrées sur l'hôte **avant** toute exécution.

## Conditions non encore remplies

- Pas de validation de l'exécution du vrai `/opt/cerato-network/backend/server.py` en environnement isolé.
- Pas de validation de la configuration Nginx effective, des cookies de navigateur, du rollback du Web ou de l'ancienne connexion.
- Pas de lancement d'une release installable ; toute publication `dev.N` n'est qu'une étape du dépôt.
- L'ancienne authentification ne doit pas être retirée, et la VM Build, le Dell, WireGuard, NAT, firewall et SSH restent inchangés.

L'objectif final reste : activation Owner/Admin/User + MFA sur l'interface existante, routage IPv4 complet `/32`, navigation F5 et UI Graphite uniforme, via une bêta **signée**, après tests d'isolation et rollback.
