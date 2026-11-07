# Environnement Python isolé des comptes natifs Cerato Network

État de la production connue : `v0.1.2-beta.1` sur OVH RISE-1. Le panneau existant est actif, son routage IPv4 publique vers Dell R530 et sa connexion historique doivent être maintenus.

## Pourquoi deux dépendances non conformes

Le contrôle `prepare_native_auth_host.py --install` a préparé le répertoire privé `/var/lib/cerato-network-auth` et sa surcharge systemd **sans redémarrer le service**, mais `argon2-cffi>=25.1,<26` et `cryptography>=44,<48` sont absents ou trop anciens pour le Python système du Web. Modifier le Python global d'Ubuntu 24.04 serait risqué et n'est pas nécessaire.

## Nouveau préparateur, séparé du Web et du stockage des comptes

`integrations/prepare_native_auth_python_runtime.py --check|--install` :

1. Réutilise le contrôle du panneau existant qui exige les empreintes SHA-256 approuvées des trois fichiers du Web, `v0.1.2-beta.1`, un service Web actif et le dossier de comptes vide déjà préparé.
2. Vérifie un répertoire `/opt/cerato-network` appartenant à root et non accessible en écriture aux tiers.
3. En mode `--install`, **ne touche pas au Python système** : crée un environnement `venv` neuf sous un nom temporaire dans `/opt/cerato-network`, sans packages système. Si `python3 -m venv` ou `ensurepip` manque, arrêt sécurisé ; **pas d'apt ou pip global automatique**.
4. Installe par `pip --isolated --only-binary=:all: --no-cache-dir` seulement les distributions de `security/requirements.txt` et leurs dépendances reconnues, au sein de cet environnement. La connexion à PyPI nécessite un accès réseau HTTPS valide de la machine et dépend de la politique d'approvisionnement.
5. Vérifie avant et après l'installation : `include-system-site-packages=false`, propriété root, accès en lecture/exécution du compte `ceratonet`, versions admises, Argon2id (hash/vérification), AES-GCM (encrypt/decrypt). Les tests cryptographiques ne créent aucun compte ni clé permanente.
6. Place le venv au chemin fixe `/opt/cerato-network/native-auth-venv` uniquement après toutes les validations. Réexécution idempotente ; refuse un chemin différent, symbolique ou insuffisamment protégé. En cas d'échec, efface le répertoire temporaire et ne touche pas à un venv déjà présent.
7. **Ne change aucune unité systemd, aucun `ExecStart`, Nginx, compte, SQLite, WireGuard, NAT, IPv4, SSH, adresse du Dell, mise à jour signée ou VM Build.**

## Limite essentielle

La présence de ce venv, même vérifiée sous `ceratonet`, **ne rend pas ces bibliothèques accessibles automatiquement au service Web actuellement exécuté sous le Python système**. L'activation native devra plus tard utiliser explicitement cet interpréteur, dans une release signée qui sauvegarde le backend et son ancien mode d'exécution, teste toutes les routes HTTP et les sessions, puis applique un rollback en cas d'échec.

Ne pas installer ce venv dans la release GitHub, ni publier de secrets, ni créer le premier Owner à cette étape. La création Owner, MFA et révocation des anciennes sessions ne peuvent être réalisées qu'une fois les tests d'authentification réels validés.

## Tests

Suite GitHub dédiée : `tests/test_native_auth_python_runtime.py`, couvre les sources des exigences, les accès, l'exécution sous compte de service simulé, l'isolation de pip, la double validation, le refus des environnements inconnus, la non-modification système et le nettoyage si une installation échoue.
