# Test des comptes natifs sur la copie privée de Cerato Network

État de production connu : `v0.1.2-beta.1`, backend/Web historique actifs sur RISE-1 OVH. L'environnement cryptographique indépendant `/opt/cerato-network/native-auth-venv` a été validé par l'exploitant : `argon2-cffi 25.1.0`, `cryptography 47.0.0`, Argon2id et AES-GCM vérifiés sous le compte `ceratonet`.

## Objectif du test

`integrations/run_private_native_auth_http_contract.py --check` exécute une **simulation des requêtes HTTP en mémoire avec le vrai code des sept modules de sécurité approuvés**, sur le runtime `ceratonet`. Ce n'est **pas** un test réseau HTTP du backend privé. Aucun socket HTTP ou port de production n'est ouvert.

1. Vérifie la copie `/var/backups/cerato-private-auth-candidate.*`, les empreintes exactes du backend et du frontend installés (après `v0.1.2-beta.1`), et tous les modules de sécurité comparés aux fichiers de la révision GitHub validée.
2. Vérifie de nouveau le venv isolé avec Argon2id et AES-GCM exécutés sous `ceratonet`.
3. Copie uniquement les modules contrôlés et le scénario de test dans un dossier **temporaire** `/var/tmp/cerato-auth-contract.*` ; le code est détenu par root, accessible en lecture au groupe de `ceratonet`, sans droit d'écriture pour ce dernier.
4. Crée un sous-dossier `test-only-db` détenu par `ceratonet`, `0700`. L'unique base SQLite et la clé MFA qui seront générées dans cet essai sont **fictives** et confinées dans ce dossier.
5. Lance le test avec `runuser -u ceratonet -- /opt/cerato-network/native-auth-venv/bin/python -I` et le code `AuthStore`, `LegacyAuthAPI` et `LiveHTTPBridge` provenant de la copie approuvée.
6. Vérifie concrètement le bootstrap d'un unique Owner, MFA Owner et Admin, sessions `Secure/HttpOnly/SameSite=Strict`, User lecture seule avec expurgation serveur, refus de mutation NAT au User, CSRF/Origin sur les opérations, protection du compte Owner, rejet de l'ancien login, hôte incorrect, route hors API et permissions sur la liste de comptes.
7. **Efface automatiquement** la base temporaire, les secrets de test et le dossier d'essai, que les tests passent ou échouent. Seuls des booléens et le nombre de contrôles sont retournés dans le rapport.

## Limitations de sécurité

- Aucun backend actif ni candidat privé `server.py` n'est exécuté ou importé. L'ancien backend n'est jamais transféré vers GitHub.
- Les requêtes HTTP sont simulées *en mémoire* au travers du bridge ; une validation de bout en bout du **véritable serveur historique** sur une instance isolée, du proxy Nginx et des cookies navigateur sera exigée avant la release de basculement.
- Ce test ne crée **aucun** compte réel et n'initialise pas `/var/lib/cerato-network-auth/accounts.sqlite3`. Le service Web n'est pas redémarré et n'utilise pas encore le venv.
- Ne modifie ni Nginx, systemd, le tunnel WireGuard, le Dell, les allocations IPv4, nftables, NAT ni la VM Build.
- Les sorties `safe_to_cut_over: false` et `production_modified: false` restent toujours fausses même si tous les tests passent.

**Prochaine étape si le test sur OVH est conforme :** préparer une instance réellement isolée du backend historique (sans attacher de routeur ou de contrôleur réseau), vérifier l'HTTP de bout en bout avec des comptes temporaires et une restauration complète, puis seulement envisager une release **beta signée** contenant un patch local à empreintes, sans jamais mettre `server.py` dans l'archive.
