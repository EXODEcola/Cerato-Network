# Cerato Network — signature GitHub et dernière activation OVH

## Règle de fonctionnement

**Ne pas toucher à CERATO-BUILD-01.** Le pipeline de cette release
fonctionne sur des runners **GitHub hébergés par GitHub**, sans accès
SSH à la VM Build ni au serveur OVH. Le serveur OVH RISE-1 conserve
l'installation historique Graphite sur le port 8787 et sert la
distribution via `https://51.210.223.57/cerato-releases/`.

Le workflow `.github/workflows/publish-signed-release.yml` signe
avec Ed25519 une première release **CSS-only**. Elle ne remplace
ni `web/app.js`, ni `backend/server.py`, ni les configurations réseau.
Les fichiers sont publiés comme assets de **GitHub Releases**. OVH
les copie vers son Nginx public après vérification de l'archive et de
l'index avec la clé publique approuvée.

## 1. Provisionnement GitHub unique (depuis le navigateur)

1. Ouvrir `EXODEcola/Cerato-Network` → **Settings → Environments**.
2. Créer l'environnement exact **`cerato-network-signing`**.
   Limiter les branches autorisées à **`main`**. Protéger `main`
   par des règles de revue et de validation obligatoires.
3. Générer **en local sur son propre PC**, et non sur Cerato Build ni
   sur OVH, une paire officielle Ed25519 compatible OpenSSL, conserver
   la clé privée dans un coffre chiffré et ne jamais l'envoyer en chat.
   Avec OpenSSL installé dans un terminal local :
   ```bash
   umask 077
   openssl genpkey -algorithm Ed25519 -out cerato-release-signing.key
   openssl pkey -in cerato-release-signing.key -pubout -out cerato-release-signing.pub
   openssl pkey -pubin -in cerato-release-signing.pub -outform DER | sha256sum
   ```
4. Dans l'environnement, créer le **secret** exact
   `CERATO_ED25519_PRIVATE_PEM` : copier uniquement le contenu PEM
   complet de `cerato-release-signing.key`. Ne pas enregistrer ce secret
   comme variable normale.
5. Dans le même environnement, créer la **variable**
   `CERATO_SIGNING_PUBLIC_SHA256` : mettre l'empreinte SHA-256 de la
   clé publique **au format DER**, 64 caractères minuscules, telle que
   vérifiée localement.
6. Sous **Settings → Secrets and variables → Actions → Variables**
   (au niveau du dépôt, **pas dans l'environnement**), créer la variable
   `CERATO_SIGNING_ENABLED=true`, mais **uniquement après** la
   protection et la configuration du secret ci-dessus.

En l'absence de la dernière variable, le job de signature est **ignoré**
et ne déclenche pas des runs échoués ou des signatures de test.
L'environnement doit rester limité à `main`, jamais à une branche
de PR. Le script vérifie la correspondance entre la clé privée, sa
clé publique dérivée et l'empreinte approuvée **avant signature**.

Si des **reviewers obligatoires** sont activés, toutes les exécutions,
y compris le renouvellement périodique de l'index, devront être approuvées.
Pour que le renouvellement reste entièrement automatique, conserver des
restrictions strictes sur `main` et une revue des changements, sans
approval gate supplémentaire sur cet environnement. Cette décision
de politique d'accès appartient au propriétaire du dépôt.

## 2. Première publication signée

Quand le workflow est sur `main`, ouvrir
**Actions → Cerato Network - Publication signée → Run workflow**,
sélectionner **`main`** et renseigner :

| Paramètre | Valeur |
| --- | --- |
| version | `v0.1.0-beta.1` |
| channel | `beta` |
| from_version | `v0.0.0` |

Le job réalise les tests **avant** la signature, prépare seulement
`live-overlay/compat.json` et `live-overlay/web/style.append.css`,
signe le manifeste puis `beta.json` et vérifie le ZIP. Enfin il
publie six assets sur une release GitHub marquée prerelease :
`cerato-network-release.zip`, `manifest.json`, `manifest.sig`,
`beta.json`, `beta.sig` et `release-verification.pub`.
Le ZIP signé reste immuable. Les fichiers du canal sont renouvelés
périodiquement (validité 7 jours, programmation dimanche et mercredi).
Un index expiré **ne doit jamais** être accepté.

L'ancienne interface GitHub de Cerato **Panel** n'est pas utilisée
comme clé ni comme moteur de distribution pour Cerato Network.

## 3. Dernière commande sur OVH RISE-1

Une fois la première release GitHub **réellement publiée** et
l'empreinte **vérifiée dans l'environnement GitHub** (et conservée
hors du système à vérifier), exécuter sur `ubuntu@cerato-network` :

```bash
cd ~/Cerato-Network && git pull --ff-only origin feature/secure-accounts && \
sudo bash scripts/connect-github-updates.sh EMPREINTE_SHA256_DER_APPROUVEE
```

Remplacer les 64 caractères de l'empreinte fictive par l'empreinte
**réelle** de l'étape 1. Ne pas recopier de clé privée et ne pas
supprimer les contrôles cryptographiques.

La commande :
1. télécharge depuis le dépôt GitHub officiel la **clé publique**
   et les assets, vérifie leur intégrité, signature et compatibilité ;
2. épingle la clé publique dans `/etc/cerato-network` ;
3. met à jour le contrôleur d'updates avec sauvegarde et rollback ;
4. synchronise la release sur le HTTPS existant d'OVH ;
5. active un miroir en lecture seule toutes les 4 heures et
   un contrôle des mises à jour toutes les 6 heures ;
6. vérifie que le panneau accepte la release signée.

**Aucun téléchargement depuis GitHub n'est installé directement comme
code sur le serveur**. Les releases sont d'abord publiées comme fichiers
statiques, puis le **bouton Installer de Cerato Network** déclenche
l'installation et les vérifications du Web 8787. Les opérations
GitHub → OVH n'utilisent aucun secret SSH.

Si la release ou la clé manque, l'activation est refusée sans
fabrication de faux fichiers. Le premier test réel sur OVH demeure
indispensable avant de déclarer la mise à jour entièrement fonctionnelle.

## 4. Évolutions suivantes

Les corrections CSS seules peuvent être livrées avec ce format signé.
Les mises à jour JavaScript, les comptes Owner/Admin/User + TOTP,
le backend réseau, les agents et le pare-feu nécessitent des overlays
**compatibles et explicitement approuvés** ; ce premier paquet
CSS-only ne les active pas.

Une nouvelle version devra respecter le format de release contrôlé et
le schéma de migration autorisé. Il est interdit de publier un frontend
de développement à la place de `web/app.js` de production.

Le Dell R530, WireGuard, les Additional IPv4 et les règles NAT restent
hors périmètre du système de signature et de mise à jour Web.
