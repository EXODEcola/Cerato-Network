# Distribution HTTPS signée : stable et bêta

**Statut : développement.** Le client vérifie et télécharge les releases mais ne les installe pas. Le serveur de distribution et l'orchestration des agents ne sont pas encore déployés.

## Séparation des responsabilités

- GitHub public : code source, historique, tags, sans secrets.
- CERATO-BUILD-01 : tests et archives non signées, sans clé privée de release.
- Compte ou VM de signature : vérifie les artefacts approuvés et signe en Ed25519.
- Distribution HTTPS : sert des fichiers statiques, sans clé privée.
- Passerelle et agents : possèdent seulement une clé publique épinglée.

**Pas de GitHub Actions pour les builds ou la compression.**

## Arborescence du serveur de distribution

- https://releases.example.org/cerato/channels/stable.json
- https://releases.example.org/cerato/channels/stable.sig
- https://releases.example.org/cerato/channels/beta.json
- https://releases.example.org/cerato/channels/beta.sig
- https://releases.example.org/cerato/releases/v0.1.0/manifest.json
- https://releases.example.org/cerato/releases/v0.1.0/manifest.sig
- https://releases.example.org/cerato/releases/v0.1.0/cerato-network-release.zip

Ces noms de domaine sont des **exemples**, pas un service en production.

L'index de canal contient la version, le canal, la date d'émission, une expiration (maximum 7 jours) et le SHA-256 du manifeste. Il est signé avec Ed25519. Le manifeste, signé séparément, définit la taille et le SHA-256 de l'archive. Le client refuse les redirections, les signatures incorrectes, les versions inférieures ou égales, les index expirés et les archives altérées.

Un index expiré doit être **renouvelé** par la machine de signature, éventuellement pour la même version et le même SHA-256 si aucune release n'a changé. Il est interdit de changer le contenu d'une release sans augmenter sa version ou de revenir à une version inférieure dans un index.

Les fichiers index et signature doivent être publiés dans un **instantané unique** de la distribution : le serveur HTTP bascule atomiquement son répertoire actif après contrôle, plutôt que de remplacer les deux fichiers l'un après l'autre.

## Produire l'index sur l'hôte de signature

Après approbation et vérification d'une release, sous le compte de signature isolé :

~~~bash
python3 tools/channel_index.py \
  --release /signing/approved/v0.1.0 \
  --channel stable \
  --output /signing/pending/channels \
  --signing-key /signing/secrets/release.key \
  --public-key /signing/public/release.pub \
  --valid-seconds 86400
~~~

Cela produit seulement stable.json et stable.sig. La clé privée ne quitte jamais l'hôte de signature. Voir deploy/releases.nginx.sample.conf pour un exemple de serveur HTTPS en lecture seule. Aucun upload automatique n'est activé.

## Client de vérification et de téléchargement

Installer la **clé publique** de vérification localement après validation de son origine, indépendamment du serveur HTTPS. Ne jamais faire confiance à une clé simplement fournie par le dépôt ou par l'index distant pendant une mise à jour.

Vérification :

~~~bash
python3 scripts/release-client.py check \
  --base-url https://releases.example.org/cerato \
  --public-key /chemin/local/release.pub \
  --channel stable \
  --installed-version v0.0.9
~~~

Téléchargement **sans exécution ni installation** :

~~~bash
python3 scripts/release-client.py download \
  --base-url https://releases.example.org/cerato \
  --public-key /chemin/local/release.pub \
  --channel stable \
  --installed-version v0.0.9 \
  --cache /chemin/local/prive/release-cache
~~~

Le cache doit être possédé par le service et avoir les permissions 0700. La version et tous les chemins téléchargés sont dérivés d'un index signé, jamais d'une URL transmise par un utilisateur Web. La signature, le manifeste et le checksum ZIP sont validés AVANT dépôt de la release.

## Agent distant et panneau Web : non terminés

Le client ne lance aucune commande privilégiée : pas de systemctl, sudo, nft, wg, redémarrage ou changement de route.

L'agent doit encore être intégré au contrôleur central : identité de machine, version assignée, téléchargement, signature indépendante, compatibilité avec son propre type de composant, sauvegarde, activation avec healthcheck, rollback et rapport de statut.

Le contrôleur central devra mettre à jour les agents après validation de la passerelle, par vagues, en laissant les machines hors ligne en attente. Le moteur de file est présent dans updates/fleet.py, mais l'agent complet ne l'est pas.

## Validation de développement

Sur CERATO-BUILD-01 uniquement :

~~~bash
cd ~/Cerato-Network
bash scripts/update-dev.sh
~~~

Les tests tests/test_remote_distribution.py simulent des réponses HTTPS sans réseau réel ; ils vérifient les cas de signature incorrecte, redirection, expiration, cache corrompu, version obsolète et archive altérée. Ces nouveaux tests restent à exécuter sur la VM de build.

Avant production : signature et rotation de clés, publication immuable réelle, migration du panneau existant, installation contrôlée, reprise après crash, healthchecks et audit de sécurité.
