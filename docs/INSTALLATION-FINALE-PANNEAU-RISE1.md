# Mise à jour du panneau OVH RISE-1 — procédure finale de bootstrap

**Branche :** `feature/secure-accounts`  
**Cible :** panneau historique Cerato Network, port 8787, serveur OVH `51.210.223.57`.

Le dépôt comprend une refonte graphique à palette graphite et la mise à niveau du moteur de releases signées. **Le dépôt GitHub n'est pas l'installation OVH.** Le script ci-dessous réalise une opération initiale sur la machine ; l'installation depuis le Web devient disponible **uniquement après** activation d'un dépôt HTTPS signé et présence d'une release compatible.

## 1. Première application sur OVH — une fois

Conserver l'accès console KVM OVH disponible, puis exécuter :

```bash
cd ~/Cerato-Network
git switch feature/secure-accounts
git pull --ff-only origin feature/secure-accounts
sudo bash scripts/finish-live-panel.sh --check
```

Le préflight exige un panneau actif, le moteur de mise à jour existant, une correspondance exacte avec les empreintes du RISE-1 inspecté et un JavaScript valide. Il refuse d'écraser un panneau inconnu. Si la commande affiche **« Contrôle de compatibilité : OK »**, lancer :

```bash
sudo bash scripts/finish-live-panel.sh --install
```

Il sauvegarde le Web actuel et le contrôleur root, met à niveau **seulement** les fichiers `web/app.js`, `web/style.css` et les trois composants du moteur d'updates, puis redémarre **uniquement** `cerato-network-web.service`. Il vérifie la réponse HTTP locale, les signatures de syntaxe, la réponse JSON du contrôleur et les empreintes des configurations réseau persistantes. En cas d'échec, la restauration automatique des fichiers est tentée.

**Aucune modification** de `wg-cerato`, `10.77.0.2`, `54.37.165.151`, NAT, nftables, routes, SSH ou d'une MAC virtuelle OVH.

Ouvrir `https://51.210.223.57/` (ou le domaine HTTPS habituel) et rafraîchir complètement le cache du navigateur avec Ctrl+F5. La nouvelle page Mises à jour affiche des états explicites. Une mention « Source HTTPS non configurée » reste normale tant que l'étape suivante n'est pas faite.

## 2. Activer la distribution réelle de releases signées

Cette étape est un **provisionnement de confiance unique**, impossible à simuler ou à deviner depuis GitHub. Il faut posséder un **véritable domaine de distribution HTTPS**, une release compatible et la clé **publique** de vérification d'un signataire indépendant de RISE-1. La clé privée Ed25519 reste sur l'hôte de signature, jamais dans le navigateur ou sur OVH.

Après validation du fournisseur, provisionner sur OVH :

```bash
sudo python3 tools/configure_live_release_source.py \
  --url https://VOTRE-DOMAINE-DE-RELEASES/cerato \
  --public-key /CHEMIN/DE-LA-CLE-PUBLIQUE-APPROUVEE.pub \
  --fingerprint EMPREINTE_SHA256_DER_CONTROLEE \
  --channel beta
```

**Les valeurs en majuscules sont des placeholders, pas une configuration utilisable.** L'outil rejette les configurations incertaines et contrôle l'empreinte DER de la clé publique. Il ne récupère jamais la clé privée. Pour créer et publier les versions, suivre `docs/DISTRIBUTION-HTTPS.md` et `docs/LIVRAISON-MISES-A-JOUR-ET-INTERFACE.md`. Une release visuelle ne doit contenir que `web/app.js`, `web/style.css` et `compat.json` avec la source version autorisée ; le ZIP entier est signé.

Sans source, signer et publier réellement le paquet ne peut pas être fait automatiquement. Le bouton « Installer » doit donc rester désactivé et **cela ne signifie pas qu'une release a été installée**.

## 3. Mise à jour normale — une fois la distribution activée

1. Dans **Cerato Network → Système → Mises à jour**, cliquer sur **Rechercher une mise à jour**.
2. Le serveur télécharge la release et contrôle l'index, le manifeste et les fichiers **Ed25519 + SHA-256**, puis l'overlay de compatibilité `8787`.
3. Si l'état affiche **« Prête à installer »**, cliquer sur **Installer la version vérifiée** et confirmer.
4. Le service systemd sauvegarde la version précédente, vérifie Python/JavaScript, redémarre le Web et teste l'intégrité réseau ; en cas d'échec, il tente de rétablir l'ancienne installation.

Les évolutions suivantes **ne nécessitent pas de connexion SSH**, tant que le canal, la clé publique et le format de compatibilité ne changent pas. Pour le premier amorçage, le provisionnement du domaine et de la clé est une opération privilégiée obligatoire.

## 4. Limites réelles au moment de publier ces scripts

- La première installation sur OVH et le chemin réseau réel **ne sont pas encore testés**. L'opération doit être exécutée par l'administrateur du serveur.
- Le dépôt ne contient aucune URL de distribution officielle ni clé de signature approuvée : elles ne doivent pas être fabriquées ou remplacées par une clé autogénérée dans le navigateur.
- La migration Owner/Admin/User + 2FA reste **un autre lot**. Les adaptateurs sont publiés, mais non activés dans le backend historique. Ne pas remplacer le backend existant par le backend de développement.
- La configuration persistante de l'Additional IP et son routage vers le Dell restent hors périmètre du bootstrap graphique.

## 5. Diagnostics, sans réinstallation

Si le navigateur affiche encore l'ancien rendu, effectuer un rechargement complet (Ctrl+F5). Si le script échoue, ne pas relancer plusieurs installateurs ; conserver la sortie du message d'erreur. Le chemin de sauvegarde est affiché après l'installation et reste sous `/var/backups/cerato-network-inplace/graphite-bootstrap/`.

Le test CI sur GitHub ne remplace pas la vérification de l'installation et de la distribution signée dans l'environnement réseau réel.

## Correctif du redémarrage et ancienne double connexion — 31 octobre 2026

Sur le premier essai, l'appel HTTP de validation sur `127.0.0.1:8787` a reçu `Connection refused` immédiatement après `systemctl restart`. Le script a donc déclenché son rollback ; **ce message seul ne prouve pas une panne persistante du backend**.

Le script attend maintenant que le service soit réellement prêt, en effectuant au maximum 30 vérifications locales, et attend aussi la reprise du service après une restauration. En cas d'échec persistant, il affiche les champs systemd d'état sans journal ni secret. Le contrôleur ne modifie pas WireGuard, NAT ou les IP.

Une seule commande enchaînée (les étapes suivantes ne se lancent que si la précédente a réussi) :

```bash
cd ~/Cerato-Network && \
git pull --ff-only origin feature/secure-accounts && \
sudo bash scripts/finish-live-panel.sh --check && \
sudo bash scripts/finish-live-panel.sh --install
```

Le nouveau précontrôle décrit uniquement la présence structurelle des anciennes protections (HTTP Basic côté reverse proxy, connexion historique dans le panneau, routes d'authentification modernes) **sans exporter d’identifiants ni de configuration Nginx**.

**Attention :** cette installation corrige le thème et le moteur de mise à jour ; **elle ne remplace pas encore** la double authentification historique. Le système Owner/Admin/User et 2FA n'est pas encore activé sur `server.py` du RISE-1. Ne pas supprimer `auth_basic` ou les anciennes routes tant que toutes les API réseau ne sont pas protégées par les nouvelles sessions, les permissions et le CSRF, et que la migration des comptes n'a pas passé les tests de bout en bout.
