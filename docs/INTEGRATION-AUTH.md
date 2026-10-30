# Intégration de l'authentification au serveur existant

**Statut : brique de sécurité en développement, non intégrée au RISE-1.** Aucun script de ce dépôt ne doit actuellement remplacer directement le service Web en production.

## Tests de la base de comptes (sur CERATO-BUILD-01, pas GitHub Actions)

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r security/requirements.txt
python3 -m unittest discover -s tests -p 'test_auth_store.py' -v
```

## Emplacement de la base

Créer `/var/lib/cerato-network-auth/` appartenant uniquement au compte système dédié `ceratonet`, permissions `0700`. Le fichier `accounts.sqlite3` doit être `0600`. Ne **jamais** placer cette base dans `/opt/cerato-network/web`.

Ne pas installer sur le RISE-1 en conservant le vieux backend d'authentification : cela ne produirait pas le nouveau login et risquerait de bloquer l'accès.

## Première installation (après intégration de l'API et du nouvel écran)

Lancer en SSH, avec une session interactive et le compte de service :

```bash
sudo -u ceratonet /opt/cerato-network/venv/bin/python \
  /opt/cerato-network/security/cli.py bootstrap-token
```

Le navigateur ouvre ensuite **Configuration initiale**, exige le code à usage unique, l'e-mail et le mot de passe choisis par le propriétaire. Une fois validé, afficher l'écran **Se connecter** ; aucune création automatique de compte d'usine.

**En production** : l'API de bootstrap doit retourner `already_initialized=true` si owner existe, **refuser** de renouveler son code via HTTP, et limiter les tentatives de saisie du code. L'assistant ne doit pas exposer les secrets ou le compte principal.

## Récupération locale (après intégration)

```bash
sudo -u ceratonet /opt/cerato-network/venv/bin/python \
  /opt/cerato-network/security/cli.py owner-reset
```

La commande demande un nouvel e-mail (facultatif) et un nouveau mot de passe sans les afficher, invalide toutes les sessions du propriétaire et journalise le changement. L'opération n'est **pas** disponible dans l'API d'administration des co-administrateurs.

## Restrictions d'accès HTTP impératives

- Exiger HTTPS sur le frontal Nginx ; service Python uniquement sur loopback, avec hôte/origine autorisés.
- Les cookies doivent être `Secure`, `HttpOnly`, `SameSite=Strict`; CSRF à contrôler pour chaque mutation.
- Chaque endpoint doit appeler `store.actor(session)` puis `store.require_permission(actor, action)`, y compris les endpoints hérités `/api/peers`, `/api/ip/add`, `/api/nat/add`, `/api/enroll/token` et les actions de mise à jour.
- Pour un viewer, appeler `viewer_projection(status)` **avant** de sérialiser la réponse API. Ne jamais envoyer les données confidentielles puis simplement masquer les éléments en JavaScript.
- La couche admin ne peut jamais modifier un enregistrement `owner`; seule l'action authentifiée **Mes identifiants** peut changer son propre e-mail ou mot de passe avec vérification du mot de passe actuel.
- Une opération d'enrôlement ou de publication réseau doit être autorisée au backend même si un bouton est caché dans l'interface.
- Ne jamais permettre au client HTTP de spécifier le rôle `owner`.

## Travaux restants avant déploiement

1. Finaliser l'API de session/comptes et son adaptation au backend en cours d'exécution (migration de `web-auth.json`).
2. Créer le nouvel écran de première connexion, l'écran mail/mot de passe, la gestion des comptes et le masquage viewer.
3. Ajouter et tester le 2FA TOTP pour owner/admin, mécanisme de récupération et révocation de sessions.
4. Tests d'intégration HTTP : prise de contrôle initiale, CSRF, sessions, RBAC, XSS, brutal force, mode lecture seule.
5. Migrer avec sauvegarde et test de retour arrière : en cas de souci, préserver l'accès SSH et le backend précédent.
6. Publier une release via CERATO-BUILD-01 puis déployer manuellement après vérification ; pas via GitHub Actions.

**Aucun changement de pare-feu, de routes, d'IP, de WireGuard ou de secrets de production n'est requis pour les tests unitaires.**
