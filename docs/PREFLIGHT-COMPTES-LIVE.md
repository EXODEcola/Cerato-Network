# Cerato Network — diagnostic de compatibilité des comptes (OVH)

## Objectif

Exécuter un **contrôle en lecture seule** de la console Cerato Network
déjà installée sur RISE-1, avant d'envisager la migration Owner/Admin/User.

Il ne modifie **aucun** compte, cookie, clé, route HTTP, règle NAT,
tunnel WireGuard, Nginx, systemd, service ou fichier du panneau.
Il ne déploie pas l'authentification native.

## Sur le serveur OVH Cerato Network uniquement

```bash
cd ~/Cerato-Network && git pull --ff-only origin main && \
sudo python3 integrations/preflight_native_auth.py
```

La commande ne contacte pas CERATO-BUILD-01. Aucun besoin de basculer
sur une branche de préproduction.

## Lecture du résultat

- `production_cutover_ready` est **toujours false** : aucun script
  de diagnostic ne peut approuver une migration sans vérification humaine.
- `baseline_matches` peut être faux, car le backend et l'interface
  ont été mis à jour depuis le relevé du 30 octobre 2026. Ce statut
  signale un écart à auditer, **pas** une anomalie réseau.
- `auth_store_write_scope_declared` permet de vérifier si le
  répertoire privé des comptes pourrait être écrit par le service
  Web sans désactiver `ProtectSystem=strict`.
- `auth_storage` indique uniquement si le répertoire du stockage
  possède des permissions privées et le bon propriétaire système.
- `http_handler_candidates` et les compteurs de routes signalent
  les incompatibilités structurelles possibles.
- `nginx_auth_basic_declared` est une observation structurelle,
  et non une vérification de la protection effective de chaque route.

Aucune sortie n'expose le code source du panneau, les configurations
Nginx, identifiants, mots de passe, secrets TOTP, adresses réseau privées
ou clés WireGuard. Les données affichées sont une liste de champs fixes,
des booléens et des compteurs. Vérifier la sortie avant tout partage.

Un diagnostic favorable ne déclenche **aucune migration automatique** :
les tests fonctionnels sur une copie privée, les données de comptes,
la révocation des sessions historiques et le rollback doivent encore
être approuvés avant une release signée installable depuis le Web.

La PR de développement Owner/Admin/User reste en préproduction :
https://github.com/EXODEcola/Cerato-Network/pull/2
