# Mise en service de la distribution signée Cerato Network

**État confirmé :** Nginx du RISE-1 sert maintenant le préfixe
`https://51.210.223.57/cerato-releases/`, avec certificat valide pour l'IP.
Les répertoires publics sont créés. Aucune release officielle ni clé de
vérification épinglée n'a encore été publiée/configurée ; il est donc normal
que le panneau indique **« Distribution à configurer »**.

## Travail logiciel terminé dans le dépôt

- `scripts/init-release-signer.sh` prépare **une seule fois** une identité
  de signature Ed25519 dans l'espace privé d'un **compte non-root sur un hôte
  distinct du routeur OVH**. Il refuse les clés déjà présentes et ne place
  jamais le secret dans GitHub ou dans le serveur de distribution. Il affiche
  la clé **publique** et son empreinte SHA-256 DER.
- `tools/stage_signed_static_release.py` contrôle l'index de canal,
  le manifeste, les signatures, la période de validité et le contenu exact
  d'une release graphique RISE-1 **avant toute publication**.
- `tools/publish_signed_release.py` vérifie la source et la clé publique
  **déjà épinglées** sur OVH ; précontrôle par défaut, installation uniquement
  avec `--install`. Il publie l'archive immuable avant de basculer
  atomiquement le canal vers un répertoire de signatures cohérent. Une
  version inférieure ou déjà publiée avec d'autres octets est refusée.
- La console et son contrôleur acceptent seulement les releases compatibles
  et signées ; l'IP publique, WireGuard, NAT et le backend historique ne
  sont pas modifiés par le mécanisme de publication.

## Deux frontières de confiance

**Hôte de signature distinct (exemple : CERATO-BUILD-01, sous un compte
non-root de signature dédié, pas le compte de CI)** :

```bash
cd ~/Cerato-Network
git pull --ff-only origin feature/secure-accounts
bash scripts/init-release-signer.sh --init
```

La commande affiche le chemin de la clé publique et l'empreinte DER. **Ne
jamais mettre la clé privée sur RISE-1, dans GitHub ou dans les fichiers Web.**
Conserver une sauvegarde hors ligne chiffrée et sécurisée de cette clé. La
confirmation indépendante de l'empreinte est une opération humaine de
confiance, non automatisable par le serveur auquel on cherche à faire confiance.

**Avant l'activation sur RISE-1 :**

1. Préparer une copie **explicitement approuvée** de l'interface Web actuelle
   `web/app.js` et `web/style.css`, sans exporter le `server.py`.
   Un numéro supérieur à l'état de départ `v0.0.0` est requis.
2. Préparer l'overlay compatible :
   ```bash
   python3 tools/compose_live_overlay.py \
     --source /DOSSIER-PRIVE-DES-FICHIERS-WEB-APPROUVES \
     --destination /SOURCE-RELEASE/live-overlay \
     --from-version v0.0.0 --visual-only
   ```
   La source de release doit aussi contenir `LICENSE` et `README.md`.
3. Construire le paquet avec `tools/release_pipeline.py prepare`.
   Copier l'archive et le manifeste approuvés dans le répertoire privé du
   compte de signature, puis signer via `tools/release_pipeline.py sign`.
   Produire un index de canal `beta` avec `tools/channel_index.py`.
4. Vérifier avec `tools/stage_signed_static_release.py` et copier **uniquement**
   les cinq fichiers publics validés, ainsi que la clé **publique**, sur OVH.
5. Installer la clé publique sur OVH dans un fichier appartenant à root, puis
   provisionner la source avec la véritable empreinte DER approuvée :
   ```bash
   sudo python3 tools/configure_live_release_source.py \
     --url https://51.210.223.57/cerato-releases \
     --public-key /CHEMIN/CLE-PUBLIQUE-APPROUVEE.pub \
     --fingerprint EMPREINTE-SHA256-DER-APPROUVEE \
     --channel beta
   ```
6. Sur OVH, après transfert dans des répertoires **privés et contrôlés** :
   ```bash
   sudo python3 tools/publish_signed_release.py \
     --release /CHEMIN/RELEASE-SIGNEE/v0.1.0-beta.1 \
     --channels /CHEMIN/INDEX-CANAL-SIGNE \
     --install
   ```
   Puis `sudo /usr/local/sbin/cerato-updatectl check` et vérification
   des permissions et de l'affichage dans l'onglet Mises à jour.

**Les chemins /CHEMIN et empreintes ci-dessus sont des marqueurs, pas des
valeurs réelles. Ne pas lancer ces commandes avant la création et la
vérification des fichiers indiqués.**

## Limitations à ne pas masquer

- La signature initiale et la première release réelles ne peuvent pas être
  fabriquées par GitHub seul. Il faut un compte de signature distinct et
  l'approbation de la clé publique.
- Le déploiement du **nouveau système Owner/Admin/User + 2FA** est un autre
  basculement sécurisé, toujours en préparation : le front actuel conserve
  volontairement ses deux protections.
- Un `git pull` seul sur RISE-1 ne remplace pas les étapes d'approbation
  cryptographique et de publication.
- Les index signés expirent et doivent être renouvelés sur le signataire
  même lorsqu'aucune mise à jour du code n'est publiée.

Quand le dispositif est initialisé, le navigateur peut télécharger et
installer les releases **compatibles** sans répéter ces étapes SSH à chaque
version.
