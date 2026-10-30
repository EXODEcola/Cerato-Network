# Cerato Network

**Cerato Network est un projet open source de gestion de tunnels, passerelles réseau et routage pour serveurs Linux.** Son objectif est de proposer une console Web centralisée pour WireGuard, les machines, les adresses IPv4, les publications NAT, la supervision, les permissions et les mises à jour vérifiées.

> **État du projet : en développement actif — pas de version stable ni de promesse de sécurité de production.** Le code présent est partiel : la nouvelle authentification, le frontend et le moteur réseau doivent encore être intégrés et audités ensemble. Ne pas appliquer la branche de développement sur une passerelle critique.

## Fonctionnalités visées

| Module | Périmètre | État |
|---|---|---|
| Accès propriétaire / administrateurs / utilisateurs | Initialisation via code SSH, Argon2id, sessions, RBAC | Connexion HTTP et TOTP intégrées dans la PR, validation de sécurité et migration à terminer |
| Tunnel WireGuard | Pairing, clés créées localement, télémétrie, handshake | Prototype existant à rendre générique |
| Adresses IPv4 | Pool, vérification des IP fournies par l'opérateur | Prototype, configuration opérateur manuelle |
| NAT | Publication TCP/UDP contrôlée vers les pairs | Prototype, règles firewall avancées non finalisées |
| Supervision | État, trafic RX/TX, version des agents, dernière activité | Interface de développement, agent à finaliser |
| Mises à jour | Versions signées, stable/bêta, rollback, déploiement par vagues | Catalogue Web et staging signés en PR, activation production non opérationnelle |
| Gestion des comptes | Propriétaire protégé, co-admins, comptes lecture seule | Implémentation de base en PR |

### Principes fondamentaux

- **Open source :** contribution et audit publics ; aucun serveur propre à l'équipe ne doit être nécessaire pour exploiter Cerato Network.
- **Générique :** zéro IP, mot de passe, clé, domaine, interface WAN ou fournisseur imposé.
- **Sécurité côté serveur :** l'API contrôle chaque permission, le frontend ne fait que refléter ces contrôles.
- **Données minimales :** les simples utilisateurs ne reçoivent jamais de secrets, ni même de champs masqués seulement en JavaScript.
- **Déploiement prudent :** sauvegardes et accès console de secours avant toute modification réseau ; aucune installation automatique du moteur sur le serveur en production.
- **Clés privées locales :** les clés WireGuard et de signature restent sur les machines qui les utilisent.
- **Mises à jour vérifiées :** intégrité SHA-256 et signature Ed25519 avec rollback ; la mise à jour des agents n'est déclenchée qu'après validation du nœud central.

## Build et distribution

```text
Dépôt GitHub public (sources et versions)
                 |
                 v
VPS de build indépendant (tests, packages, signatures)
                 |
                 v
Hébergement HTTPS des archives signées
                 |
                 v
Passerelle Cerato Network (validation, sauvegarde, déploiement)
                 |
                 v
Agents installés sur les nœuds connectés (mise à jour contrôlée)
```

**Aucune compilation, compression ou signature via GitHub Actions.** Toute la chaîne de build s'exécute sur une infrastructure externe choisie par l'administrateur. Voir [documentation du déploiement](docs/DEPLOIEMENT.md).

## Développement

La branche `main` est la base documentaire publique et la branche `feature/secure-accounts` contient la première implémentation des comptes, des permissions et des tests. Voir [la proposition en cours](https://github.com/EXODEcola/Cerato-Network/pull/1).

Sur une machine **de développement isolée** (pas un RISE-1 ou une passerelle de production) :

```bash
git clone https://github.com/EXODEcola/Cerato-Network.git
cd Cerato-Network
git switch feature/secure-accounts
bash scripts/bootstrap-dev.sh
```

Pour les mises à jour suivantes, depuis ce même dossier : `bash scripts/update-dev.sh`. **Ne jamais recloner un dépôt à l'intérieur de lui-même.**

**Ces commandes ne déploient pas la passerelle.** Les 39 premiers tests publiés avant l'ajout du staging signé ont été validés par un testeur ; les tests des commits plus récents restent à exécuter sur la machine de build. Voir [le développement MFA](docs/DEPLOIEMENT.md) et la [PR en cours](https://github.com/EXODEcola/Cerato-Network/pull/1).

## Sécurité et signalement

Voir [SECURITY.md](SECURITY.md). Ne jamais ouvrir une issue publique avec des clés, identifiants, journaux contenant des secrets ou détails exploitables d'une installation.

## Licence

MIT — voir [LICENSE](LICENSE). Le code peut être réutilisé et modifié sous cette licence, sous réserve de conservation des mentions. Le nom et les logos Cerato restent des signes distinctifs du projet ; la licence du code ne concède pas automatiquement un droit sur la marque.
