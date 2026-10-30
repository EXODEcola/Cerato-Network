# Mises à jour signées — conception et fonctionnement réel

Cette documentation distingue les composants **développés** des opérations **encore interdites en production**.

## Flux

```text
GitHub public — code source uniquement
           |
           v
VPS de build indépendant — tests, packaging, signature Ed25519
           |
           v
Stockage HTTPS des manifests/archives (non déployé à ce stade)
           |
           v
Cerato Network — vérifie le manifest signé et SHA-256
           |
           v
Préparation isolée sous répertoire 0700 (fonctionnelle en développement)
           |
           v
Basculement avec healthcheck + rollback (moteur local à tester)
           |
           v
Distribution de la release aux agents (file créée, agent installateur à finaliser)
```

Aucune compilation/compression avec GitHub Actions.

## Sécurité de la distribution

Le VPS de build doit stocker la **clé privée de signature hors du Git et hors de l'environnement qui exécute des PR non fiables**. La passerelle et les agents auront uniquement la clé publique. Une archive non signée, altérée, mal formatée, contenant un lien symbolique ou une collision de version sera refusée.

Les fichiers de production sensibles, les clés WireGuard, les configurations nftables et les secrets ne doivent jamais être inclus dans une release. Les données locales doivent rester en dehors du dossier de déploiement.

## Composants présents

### 1. Fabrication de l'archive

`tools/build_release.py` génère `manifest.json`, `manifest.sig` et `cerato-network-release.zip`. La version est contrôlée et les fichiers sensibles sont exclus du build.

### 2. Catalogue Web

`updates/catalog.py` vérifie la signature et l'intégrité des archives locales. `GET /api/updates` et `POST /api/updates/check` exigent owner/admin. Un utilisateur simple n'accède pas au catalogue détaillé.

### 3. Préparation Web en développement

`POST /api/updates/stage` exige owner/admin, une session valide et une preuve CSRF. Cette action est **désactivée par défaut** et nécessite `CERATO_DEV_STAGE_ENABLED=1` sur un environnement de développement, avec trois chemins **définis par l'opérateur serveur** :

```text
CERATO_RELEASE_DIR=<dossier de l'archive et du manifeste>
CERATO_RELEASE_PUBKEY=<clé publique Ed25519>
CERATO_DEV_STAGE_ROOT=<dossier de déploiement isolé, propre à l'utilisateur et chmod 700>
```

Le navigateur ne fournit aucun chemin, URL, commande shell ou nom de fichier arbitraire. L'extraction vérifie la signature et recontrôle le SHA-256 sur les **octets mêmes** extraits avant d'accepter une release. La version est déposée dans un répertoire privé, sans exécution.

Le bouton Web **Installer sur le panneau et les machines reste désactivé**.

### 4. Basculement et retour arrière (bibliothèque locale)

`updates/installer.py` comprend `activate(root, version, healthcheck)` et `rollback(root, healthcheck)`. Le basculement se fait par lien symbolique atomique et rétablit la version précédente si le healthcheck échoue.

**Ce moteur n'est PAS un service de mise à jour production** : il ne redémarre aucun service, ne modifie pas Nginx et ne fournit pas encore de healthcheck du vrai backend. Il ne faut donc pas l'appeler depuis le navigateur ni l'exécuter directement sur une passerelle réseau en production.

## Règles du futur service de production

Avant toute activation de la mise à jour Web, il faudra impérativement :

1. Vérifier l'état actuel du réseau et de la connexion SSH ; garder un accès hors bande fonctionnel.
2. Sauvegarder l'ancienne version et sa configuration locale (sans inclure les secrets dans Git).
3. Isoler l'agent d'update et autoriser seulement des transitions validées, pas de shell arbitraire.
4. Installer une nouvelle version dans un dossier distinct puis contrôler la compatibilité de base et l'état des services.
5. Recharger les services selon un ordre défini, vérifier le healthcheck, et **restaurer automatiquement** l'ancienne version si nécessaire.
6. Déclencher les agents **seulement après** la validation du panneau principal, avec tests d'identité et contrôle de la signature sur chaque machine.
7. Mettre les machines hors ligne en attente, pas en échec destructif ; conserver un journal de statut.
8. Éviter les redémarrages de l'OS et des serveurs de jeux pour une mise à jour d'agent.

## Tests

Sur un VPS de build/dev **distinct de la passerelle en production**, avec la branche `feature/secure-accounts` et les dépendances déjà présentes :

```bash
cd ~/Cerato-Network
bash scripts/update-dev.sh
```

Ce script réutilise le même checkout, effectue un `git pull --ff-only` et exécute les tests. Ne pas relancer `git clone` depuis le dossier cloné.

L'objectif des tests est de vérifier : version signée, corruption, collisions, permissions des chemins, verrouillage et retour arrière après un healthcheck négatif. Un test réussi n'autorise pas à l'utiliser sur le serveur RISE-1.

**État : code expérimental publié sur une branche non fusionnée ; aucune release stable ni migration réseau initiée.**
