# RISE-1 : raccordement sécurisé de l'authentification au panneau existant

## Statut au 30 octobre 2026

La première vérification du RISE-1 a renvoyé `adapter_design_ready=true` et `source_hashes_match=true`. **Cela autorise le développement, pas le basculement en production.** La nouvelle interface doit rester intégrée à l'unique console existante sur le port 8787 : aucun service 8788 ni second panel en production.

### Nouvelles pièces développées et versionnées

- `security/legacy_auth_api.py` : adaptateur HTTP isolé gérant bootstrap, login, TOTP, sessions, profil, comptes et sous-utilisateurs, sans commandes réseau. Les anciennes routes `/api/login` et `/api/logout` sont rejetées.
- `security/live_session_guard.py` : contrôle RBAC, CSRF et projection expurgée des données pour les utilisateurs en lecture seule.
- `integrations/inspect_live_handler_flow.py` : analyse en lecture seule des handlers réels avec `ast`, sans afficher le code ni les secrets. Seuls les noms des routes déjà connus et approuvés peuvent figurer dans son rapport.
- `tests/test_legacy_auth_api.py`, `tests/test_live_handler_flow.py` : simulations de connexion/MFA, droits des comptes, CSRF et conservation des routes existantes.

Ces modules **ne sont pas importés par `/opt/cerato-network/backend/server.py`**. Les ajouter au dépôt de développement ne change pas le service en cours d'exécution.

## Vérification des handlers du panneau actif

Commande à lancer **sur RISE-1**, sans `sudo`, sans installation et sans changement réseau :

```bash
cd ~/Cerato-Network
git pull --ff-only origin feature/secure-accounts
python3 integrations/check_live_auth_cutover.py
python3 integrations/inspect_live_handler_flow.py
```

L'inventaire inspecte seulement le backend et le frontend existants. Le résultat donne le nombre de handlers, les méthodes HTTP et les routes reconnues dans les conditions, ainsi que le nombre d'appels visibles à `check_session`, `read_body` et `send_json`. **Un appel détecté ne prouve pas qu'il protège toutes les branches.**

Ne pas envoyer le fichier `server.py`, les secrets ou la base de comptes sur GitHub pour obtenir ce rapport.

## Tests sur CERATO-BUILD-01

```bash
cd ~/Cerato-Network
git pull --ff-only origin feature/secure-accounts
python3 -m unittest discover -s tests -p 'test_live_auth_cutover.py' -v
python3 -m unittest discover -s tests -p 'test_live_handler_flow.py' -v
python3 -m unittest discover -s tests -p 'test_live_session_guard.py' -v
python3 -m unittest discover -s tests -p 'test_legacy_auth_api.py' -v
python3 -m unittest discover -s tests -p 'test_legacy_policy.py' -v
```

Les dépendances `argon2-cffi` et `cryptography` doivent être présentes dans l'environnement de développement. Ne pas exécuter `scripts/update-dev.sh` sur l'OVH actif.

## Points obligatoires avant intégration live

1. Confirmer avec la carte AST l'emplacement réel de la classe `Handler`, la logique des méthodes `do_GET` et `do_POST` et l'ordre des contrôles. Auditer localement les sorties non couvertes par `check_session`.
2. Raccorder les nouveaux endpoints d'authentification **dans la console existante**, puis protéger **chaque** route historique par le contrôle RBAC et CSRF avant la première action réseau. Les routes inconnues doivent être interdites. La nouvelle session ne doit jamais accepter l'ancien cookie/password.
3. Conserver la réponse expurgée pour le rôle `user` **côté serveur**, avant sérialisation. Éviter toute fuite dans les chargements automatiques et dans les erreurs.
4. Prévoir l'extraction des cookies HttpOnly et un contrôle strict Host/Origin derrière Nginx HTTPS. Ne pas faire confiance à `X-Forwarded-For` hors proxy de confiance. Mettre `Cache-Control: no-store` sur les réponses d'authentification.
5. Conserver toutes les interfaces réseau (IPv4, machines, NAT, pare-feu, topologie, logs, configuration, mises à jour) et leurs comportements. L'ancien frontend installé n'est **pas** identique au `web/app.js` autonome du dépôt.
6. Sur une copie isolée de l'installation en préproduction, valider sessions, MFA, changement mot de passe, création admin/user, ancien login désactivé, CSRF, restrictions réseau et rollback.
7. Construire puis signer un overlay compatible sur CERATO-BUILD-01. Installer depuis l'onglet Mises à jour uniquement **après** validation de la source de distribution HTTPS et de sa clé publique.

## Hors périmètre, non modifié

Le serveur Dell R530, `wg-cerato`, `10.77.0.2`, l'Additional IPv4 `54.37.165.151`, les interfaces WAN, le NAT, les règles nftables, les routes, les services SSH et les bases de données live.

**Aucun installateur ne doit être lancé à cette étape.** Le prochain patch des handlers historiques ne peut être validé qu'après la lecture du rapport structurel et des tests sur une copie intégrale, isolée, de la console.
