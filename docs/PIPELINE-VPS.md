# Chaîne de publication sur VPS externe — Cerato Network

**Aucune GitHub Action ne compile, ne compresse ou ne signe les fichiers.** Le dépôt GitHub est public et contient uniquement les sources. Les paquets et la signature sont produits et testés par une machine de build indépendante.

## Contrat de sécurité de publication

1. Le mainteneur approuve une révision et crée un **tag Git annoté et signé GPG** `vX.Y.Z` ou `vX.Y.Z-beta.N`.
2. La VM de build reconnaît la clé publique du mainteneur comme fiable pour vérifier `git tag -v` (provisionnée séparément, jamais une clé inconnue auto-importée).
3. Un processus **non privilégié et sans clé de signature** exécute les tests et prépare un ZIP reproductible et un manifeste non signé.
4. Un autre utilisateur/machine de signature reçoit une copie contrôlée du ZIP et du manifeste après approbation du commit, vérifie SHA-256 et appose la signature Ed25519.
5. La clé **publique** de vérification est distribuée aux passerelles et agents. Le manifeste et le ZIP sont diffusés depuis un endpoint HTTPS sous un emplacement immuable.
6. La passerelle télécharge la release, revérifie la signature et le ZIP, puis prépare la version dans un dossier privé. **Le basculement de production n'est pas activé à ce stade**.

## Première mise en place sur le VPS de build

Ces commandes s'appliquent **uniquement à CERATO-BUILD-01 ou une machine isolée**, jamais au RISE-1 de production.

```bash
git clone https://github.com/EXODEcola/Cerato-Network.git
cd Cerato-Network
git switch feature/secure-accounts
bash scripts/bootstrap-dev.sh
```

Pour mettre à jour ce checkout de développement et relancer les tests, **ne pas cloner une deuxième fois** :

```bash
cd ~/Cerato-Network
bash scripts/update-dev.sh
```

Le bootstrap installe les dépendances manquantes et prépare l'environnement Python sans modifier de firewall, service réseau ou tunnels. Il bloque le lancement s'il détecte le service Cerato Network en cours d'exécution.

## Publier un tag approuvé (environnement de release distinct)

Sur une branche validée, le mainteneur crée un tag annoté signé :

```bash
git tag -s v0.1.0-beta.1 -m "Cerato Network 0.1.0 beta 1"
git push origin v0.1.0-beta.1
```

Il faut configurer GPG et la clé signataire du mainteneur au préalable. Ce tag ne doit être créé **qu'après** revue et approbation du code. Activer la protection des tags GitHub pour éviter leur réécriture.

Sur le VPS, le compte de build doit connaître la **clé GPG publique de confiance** du mainteneur, configurée par l'administrateur de l'infrastructure (ne jamais considérer comme fiable une clé récupérée automatiquement depuis le dépôt compromis).

Après checkout explicite du commit tagué dans un workspace de release indépendant :

```bash
git fetch --tags origin
git switch --detach v0.1.0-beta.1
bash scripts/prepare-approved-tag.sh v0.1.0-beta.1 /chemin/production-build/unsigned-v0.1.0-beta.1
```

Cette commande refuse les tags non signés, les tags non approuvés par GPG, un HEAD différent du tag, les modifications locales suivies et les tests qui échouent.

## Signature (identité système séparée)

Le code de release et ses tests ne doivent **jamais** s'exécuter en présence de la clé privée Ed25519 de production. La signature doit avoir lieu sous un compte de service dédié et dans un répertoire non modifiable par le compte qui compile. L'administrateur contrôle l'archive et le SHA-256 avant de déplacer une copie dans ce répertoire.

Sur le compte signataire autorisé :

```bash
python3 tools/release_pipeline.py sign \
  --output /repertoire-de-signature/approved-v0.1.0-beta.1 \
  --signing-key /chemin/prive/ed25519-signing.key
```

La signature est refusée si le manifeste n'est pas canonique, si la taille ou le SHA-256 diffèrent, si l'archive est altérée ou si les fichiers de clé sont trop permissifs.

Pour vérifier le paquet signé avec la clé **publique** :

```bash
python3 tools/release_pipeline.py verify \
  --output /repertoire-de-signature/approved-v0.1.0-beta.1 \
  --public-key /chemin/public/ed25519-signing.pub
```

L'archive officielle contient `cerato-network-release.zip`, `manifest.json` et `manifest.sig`. La séparation empêche les tests de code public d'accéder directement à la clé privée de signature.

**Ne jamais** coller de clé privée, mot de passe, token SSH ou secret WireGuard dans un commit, un ticket GitHub ou une conversation.

## Production : travaux encore obligatoires

La distribution HTTPS immuable, le compte signataire isolé, le service local de mise à jour, les healthchecks réels, le rollback après redémarrage et la distribution contrôlée des mises à jour aux agents doivent encore être configurés et testés ensemble. Ces fichiers sont **une base de publication testable**, pas une release prête à installer sur un routeur.

## Tests de sécurité du pipeline

La suite `tests/test_release_pipeline.py` couvre la séparation des opérations, le déterminisme des archives, l'exclusion des fichiers secrets, l'impossibilité de resigner une release existante et le rejet d'archives modifiées.

L'exécution locale de tests, même réussie, ne remplace pas une revue de sécurité indépendante ni des tests de mise à jour/restauration sur une VM de préproduction.
