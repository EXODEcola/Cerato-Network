# Cerato Network — procédure d'exploitation des mises à jour Web

## Règles de maintenance (31 octobre 2026)

- **CERATO-BUILD-01 est hors périmètre.** Ne demander ni SSH,
  ni création manuelle de clé sur Build, ni réinstallation du runner.
  La chaîne de compilation Cerato existante reste indépendante.
- **OVH RISE-1 (51.210.223.57)** est le seul hôte où une
  dernière activation SSH du centre de mises à jour est autorisée.
- Les versions suivantes doivent être recherchées et installées dans
  l'onglet **Mises à jour**, avec signature, compatibilité, sauvegarde
  et restauration automatiques. Un SSH OVH ponctuel reste admis pour
  le développement technique, pas pour chaque installation courante.

## Ce qui a été prouvé sur RISE-1

- Web historique Graphite sur port interne 8787, service actif.
- Contrôleur `cerato-updatectl` et page « Mises à jour » installés.
- Nginx sur la même IP HTTPS distribue le répertoire prévu
  `https://51.210.223.57/cerato-releases/`.
- Certificat TLS valide **pour l'IP** lors du dernier contrôle Nginx.
- Sauvegarde Nginx :
  `/var/backups/cerato-network-inplace/nginx-releases/20261031T110532Z`.

Ce qui **n'a pas été prouvé** : existence d'une clé publique Ed25519
indépendamment approuvée et épinglée, présence de l'index de canal signé,
publication d'une première release visuelle compatible et réussite d'une
installation de bout en bout via le navigateur.

## Commande unique OVH

Le script `integrations/activate_live_updates.py` est le seul
point d'entrée recommandé pour l'activation finale, sans toucher
à Build, au réseau, au serveur Web ou à Nginx.

Si la source officielle **est déjà épinglée** :

```bash
cd ~/Cerato-Network && git pull --ff-only origin feature/secure-accounts && sudo python3 integrations/activate_live_updates.py --install
```

Si la source n'est pas encore épinglée, l'activation nécessite une
**clé publique officiellement approuvée et son empreinte SHA-256 DER
vérifiée indépendamment**. Elles ne sont pas actuellement disponibles
dans ce dépôt ou dans les résultats d'exploitation fournis.
Une fois la clé publique copiée et approuvée sur OVH, utiliser **une
seule commande** avec les deux paramètres `--public-key` et
`--fingerprint`, comme décrit dans
`docs/OBJECTIF-MAJ-WEB-RISE1.md`.
Ne jamais inventer une empreinte ou copier une clé privée sur OVH.

La commande **sans `--install`** donne l'état actuel, sans modifier
le serveur :

```bash
cd ~/Cerato-Network && git pull --ff-only origin feature/secure-accounts && sudo python3 integrations/activate_live_updates.py
```

Les résultats doivent être lus précisément :

| Statut | Signification |
| --- | --- |
| `source_missing` | Source signée non épinglée ; configuration impossible sans clé publique approuvée |
| `waiting_for_signed_release` | Source raccordée, mais canal public absent |
| `published_not_verified` | Canal accessible HTTPS, signature encore non vérifiée |
| `verification_failed` | Canal présent mais validation de signature/compatibilité en échec |
| `incompatible_release` | Archive authentifiée mais incompatible avec ce panneau |
| `ready` | Contrôle de signature terminé ; le navigateur peut utiliser les releases compatibles |

**Un statut `ready` ne signifie pas nécessairement qu'une mise à jour
est disponible**. Le champ `installable` décide si le bouton
« Installer » peut être activé.

## Circuit des prochaines versions

Développement → tests GitHub (une exécution par push) → compilation
par la chaîne Cerato Build **déjà existante** → approbation/signature
par l'autorité prévue → distribution HTTPS publique sur OVH →
vérification et installation depuis l'interface Cerato Network.

La distribution **ne signera jamais automatiquement un ZIP à partir
du dépôt seul** ; un pipeline qui fournit une release non signée ne
suffit pas. Les fichiers `manifest.sig`, `channels/beta.sig` et la
clé publique de l'autorité réelle sont indispensables.

Les changements Owner/Admin/User + 2FA restent un basculement
indépendant et ne doivent pas désactiver HTTP Basic ni l'ancienne
connexion avant tests HTTP de bout en bout et rollback validé.

Le Dell R530 (`10.77.0.2`), l'Additional IPv4
`54.37.165.151`, WireGuard, NAT, règles de pare-feu et
configurations d'accès réseau sont hors du périmètre de l'activation.
