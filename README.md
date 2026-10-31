# Cerato Network

Console d'administration du réseau Cerato : passerelles, serveurs, tunnels WireGuard, IPv4 supplémentaires, NAT, pare-feu et supervision.

> **État : dépôt initialisé.** Le logiciel est encore en développement ; aucune publication de production n'est déclenchée par ce dépôt.

## Architecture de publication

```text
GitHub / Cerato-Network          (sources et historique)
           |
           | récupération des sources
           v
CERATO-BUILD-01 / VPS de build   (tests, compilation, compression, signature)
           |
           | manifest signé + archive vérifiée
           v
Distribution des releases       (hébergement à configurer)
           |
           | contrôle signature + SHA-256, sauvegarde, déploiement
           v
RISE-1 / Cerato Network         (service de production)
```

**La CI GitHub vérifie les PR et prépare uniquement des archives de sources non signées.** Un workflow facultatif, réservé aux tags GPG approuvés, peut lancer automatiquement la compilation sur un runner isolé `cerato-build` lorsqu'il a réellement été enregistré et activé. Aucune clé privée Ed25519 ni release de production n'est hébergée ou signée par la CI.

## Composants prévus

- `gateway/` : API et moteur de contrôle, sans secrets de production.
- `web/` : interface d'administration Cerato Network.
- `agent/` : enrôlement et télémétrie des machines.
- `build/` : scripts exécutés uniquement sur le VPS de build.
- `scripts/` : vérification et installation de releases signées.
- `tests/` : validation et tests de non-régression.
- `docs/` : architecture, sécurité et exploitation.

## Sécurité

- Ne **jamais** versionner de clé privée WireGuard, mot de passe, token, fichier `.env`, fichier d'authentification, configuration en production ou clé de signature.
- Clé de signature privée conservée sur le VPS de build sécurisé ; clé de vérification publique sur les serveurs cibles.
- Installation d'une release uniquement après vérification de signature, d'intégrité et de compatibilité.
- Sauvegarde et restauration avant tout déploiement ; aucune mise à jour ne doit réinitialiser WireGuard ou les règles réseau.
- Toute opération de routage, NAT ou pare-feu nécessite des contrôles de sécurité spécifiques.

## État du déploiement

Le RISE-1 actuel **n'est pas modifié** par l'initialisation de ce dépôt. Les archives de release, le moteur d'auto-update piloté par le VPS de build et l'intégration finale seront publiés après validation de la chaîne de distribution.
