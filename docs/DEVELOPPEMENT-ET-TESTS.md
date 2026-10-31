# Démarrage de l'interface de développement (sans modifier de route)

Ce document concerne **uniquement la branche de développement** et n'est **pas** une procédure de migration ou une installation de production. L'ancien moteur réseau ne doit pas être remplacé par ce service.

## Prérequis

Linux, Python >= 3.11, OpenSSL, une session shell et un navigateur. Pour voir des données WireGuard réelles, `ceratoctl status` doit exister, mais aucune commande de modification réseau n'est lancée par ce serveur.

## Installation sur machine de test

```bash
git clone https://github.com/EXODEcola/Cerato-Network.git
cd Cerato-Network
git switch feature/secure-accounts

# Sur un VPS de développement/build Debian/Ubuntu séparé :
bash scripts/bootstrap-dev.sh

# Le bootstrap installe automatiquement Python venv, Node et dépendances manquantes,
# puis lance les tests, dont l'API HTTP locale de bout en bout.
# Il refuse de s'exécuter si cerato-network-web.service tourne déjà.
```

Si les tests échouent, **ne pas poursuivre**.

### Créer le propriétaire une seule fois

```bash
mkdir -p .dev
chmod 700 .dev
python security/cli.py --database "$PWD/.dev/accounts.sqlite3" bootstrap-token
```

Le code affiché doit être saisi dans l'assistant Web avec l'**e-mail et le mot de passe de ton choix**. Il expire au bout de 15 minutes et ne fonctionne qu'une fois.

### Test depuis localhost (HTTP uniquement sur loopback)

```bash
CERATO_DEV_AUTH_ONLY=1 \
CERATO_DEV_LOOPBACK_HTTP=1 \
CERATO_AUTH_DB="$PWD/.dev/accounts.sqlite3" \
CERATO_PORT=8788 \
python gateway/http_api.py
```

Ouvrir `http://127.0.0.1:8788` sur **la même machine**. Pour un hôte distant, utiliser une redirection SSH vers ce port, jamais une ouverture du port 8788 sur Internet.

**Le mode HTTP explicite est réservé aux tests locaux.** Le service de développement refuse de démarrer sans `CERATO_DEV_AUTH_ONLY=1`, et la future production devra utiliser Nginx HTTPS, cookies Secure, 2FA et une autorisation complète de tous les endpoints.

### Récupération locale du propriétaire

```bash
python security/cli.py --database "$PWD/.dev/accounts.sqlite3" owner-reset
```

La commande demande un nouveau mot de passe sans l'afficher ; seul l'accès SSH au compte autorisé peut l'exécuter. Les sessions du propriétaire sont révoquées.

## Publication signée sur le VPS de build

Générer des clés sur le VPS de build avec accès exclusif à l'utilisateur de signature :

```bash
umask 077
openssl genpkey -algorithm ED25519 -out /chemin/prive/cerato-signing.key
openssl pkey -in /chemin/prive/cerato-signing.key -pubout -out /chemin/public/cerato-signing.pub
```

La clé privée ne doit être ni dans Git, ni dans un conteneur non fiable, ni sur la passerelle réseau.

**Après** validation des tests dans un environnement isolé, préparer une archive depuis un checkout tagué et audité (la sortie doit être hors du checkout) :

```bash
python tools/build_release.py build \
  --source "$PWD" \
  --output /chemin/release \
  --version v0.1.0-beta.1 \
  --signing-key /chemin/prive/cerato-signing.key

python tools/build_release.py verify \
  --output /chemin/release \
  --public-key /chemin/public/cerato-signing.pub
```

Le build refuse les liens symboliques, les secrets et les fichiers trop volumineux. Les trois sorties sont `manifest.json`, `manifest.sig` et `cerato-network-release.zip`. **La génération de l'archive ne constitue pas une autorisation de déployer.** Les mises à jour en un clic, le service de distribution HTTPS et le déploiement des agents attendent leur intégration et leurs tests E2E.

L'utilisateur de signature doit être isolé de l'environnement exécutant les tests de code non fiable. Ne jamais exécuter des tests de pull requests non approuvées avec accès à la clé de signature.

## Limites connues bloquant une release stable

1. 2FA TOTP : primitives disponibles, mais pas encore reliées au flux de connexion ni à la base des comptes.
2. Gestion complète du réseau : le moteur `ceratoctl` de la passerelle existante n'a pas encore été importé, généralisé et intégré au nouveau backend.
3. Enrôlement : finaliser le client et les jetons avec validation des identités et la télémétrie signée.
4. Updater : connecter les archives signées, le téléchargement HTTPS, la validation et le rollback au moteur d'installation et au contrôleur Web.
5. Rollout : la file de mises à jour est présente, mais l'agent n'effectue pas encore les installations ni le rapport d'état E2E.
6. Migration : prouver la sauvegarde et le retour arrière sur une copie du RISE-1 sans casser le tunnel, SSH et les règles NAT.

**Aucune release stable ni mise à jour OVH n'est autorisée tant que ces points restent ouverts.**
