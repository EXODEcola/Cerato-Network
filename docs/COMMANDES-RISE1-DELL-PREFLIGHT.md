# Commandes contrôlées — Cerato Network, Dell R530 et IPv4 publique

**Statut :** préflight et code de développement ; **pas une activation du routage**.
Les deux blocs ci-dessous ne modifient ni les tables IP, ni SSH, ni les
interfaces, ni les fichiers de configuration de production.

## RISE-1 — passerelle OVH (ubuntu@cerato-network)

```bash
cd ~/Cerato-Network
git fetch origin feature/public-ip-path-preflight
git show origin/feature/public-ip-path-preflight:scripts/preflight_public_ipv4.py > /tmp/cerato-preflight-public-ipv4.py
python3 -m py_compile /tmp/cerato-preflight-public-ipv4.py

sudo python3 /tmp/cerato-preflight-public-ipv4.py \
  --role gateway --mode local-nat \
  --public-ip 54.37.165.151 --peer-ip 10.77.0.2 \
  --wan enp1s0f0 --tunnel wg-cerato --port 8080

sudo python3 /tmp/cerato-preflight-public-ipv4.py \
  --role gateway --mode routed-wg \
  --public-ip 54.37.165.151 --peer-ip 10.77.0.2 \
  --wan enp1s0f0 --tunnel wg-cerato
```

Contrôles complémentaires (lecture seule) :

```bash
ip -4 route get 10.77.0.2
ip -br -4 addr show dev enp1s0f0
sudo wg show wg-cerato allowed-ips
sudo nft -a list table ip cerato_network
sudo systemctl is-active cerato-network-web.service
sudo /usr/local/sbin/cerato-updatectl status
```

Le `drop` observé sur `54.37.165.151` était une règle INPUT :
ne pas la supprimer sans revoir sa fonction. La chaîne FORWARD est
distincte et doit être auditée lors du basculement.

## Dell Ubuntu 24.04 (ceratoadmin@cerato-panel)

```bash
git clone --depth 1 --branch feature/public-ip-path-preflight \
  https://github.com/EXODEcola/Cerato-Network.git \
  ~/Cerato-Network-preflight
cd ~/Cerato-Network-preflight
python3 -m py_compile scripts/preflight_public_ipv4.py

sudo python3 scripts/preflight_public_ipv4.py \
  --role peer --mode local-nat \
  --public-ip 54.37.165.151 --peer-ip 10.77.0.2 \
  --tunnel wg-cerato --port 8080

sudo python3 scripts/preflight_public_ipv4.py \
  --role peer --mode routed-wg \
  --public-ip 54.37.165.151 --peer-ip 10.77.0.2 \
  --tunnel wg-cerato --port 22
```

Contrôles complémentaires (lecture seule) :

```bash
ip -4 rule show
ip -4 route show table 51820
ip -4 route get 1.1.1.1 from 10.77.0.2
sudo sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.wg-cerato.rp_filter
sudo ss -ltnp | grep ':22'
sudo sshd -T | grep -E '^(passwordauthentication|permitrootlogin|pubkeyauthentication) '
sudo ufw status verbose
```

Le `sudo sshd -T` vérifie la configuration globale par défaut ;
les directives `Match` peuvent être différentes suivant le client.
Ne pas exposer SSH publiquement avant d'avoir vérifié les clés,
le pare-feu et un accès de récupération indépendant.

## Test fonctionnel actuel 8080 (optionnel)

Lancer temporairement sur le Dell :

```bash
mkdir -p /tmp/cerato-empty
python3 -m http.server 8080 --bind 10.77.0.2 --directory /tmp/cerato-empty
```

Tester depuis un **autre réseau Internet**, sans utiliser le Dell ni RISE-1 :

```bash
curl --connect-timeout 5 -v http://54.37.165.151:8080/
```

Arrêter le service Python avec Ctrl+C.
Un succès via VPN `10.77.0.2` ne prouve pas un accès via
`54.37.165.151`. La publication NAT 8080 ne teste pas SSH 22.

## Mises à jour

La branche de travail ajoute le format signé `v0.1.1-dev.1`
et le canal Dev, tout en conservant Bêta/Stable. Il faut attendre une
release **officiellement signée**, fusionnée sur `main` et adaptée
au backend RISE-1 avant de changer le canal du panneau.
`git pull` sur OVH ne met pas à jour automatiquement les fichiers
`/opt/cerato-network` du service en production.

Ne jamais exécuter les commandes suivantes dans le but de tester :
`nft flush ruleset`, `ip route replace default`, suppression manuelle
de `54.37.165.151/32` sur WAN, suppression de la clé du pair WireGuard,
ou désactivation de Tailscale. L'activation exige encore deux watchdogs
indépendants et un rollback physique validé.


## Résultats réels du 31 octobre 2026

Contrôles exécutés sur RISE-1 :

- `wg-cerato` présent, handshake récent, `ip_forward=1`.
- `enp1s0f0` conserve `54.37.165.151/32` ; aucune route publique
  /32 vers WireGuard n'est active.
- `wg show wg-cerato allowed-ips` ne contient que
  `10.77.0.2/32` pour le Dell (ne jamais remplacer cette valeur sans
  une sauvegarde complète des autres pairs).
- nftables DNAT TCP 8080 présent, aucun SNAT visible dans la chaîne
  `postrouting`, chaîne FORWARD filtrante avec règle `drop` générale
  sur l'arrivée WAN / sortie WireGuard hors connexion DNAT.
- Mise à jour du panneau `v0.1.0-beta.1`, canal `beta`,
  `already_current` : aucun correctif réseau n'a été installé.

Contrôles exécutés sur le Dell :

- Règle `from 10.77.0.2 lookup 51820` et table 51820 avec
  `default dev wg-cerato` ; `rp_filter=2`.
- Aucun alias `54.37.165.151/32`, aucune règle de routage source
  pour cette IPv4. La commande `ip route get 1.1.1.1 from 54.37.165.151`
  est susceptible d'échouer tant que l'adresse n'existe pas : ce n'est
  pas en soi un dysfonctionnement du tunnel.
- SSH en écoute sur le port 22 mais configuration par défaut :
  `PasswordAuthentication yes`, `PermitRootLogin without-password`,
  `PubkeyAuthentication yes`. UFW inactif. **SSH non prêt à être
  exposé sur l'IPv4 supplémentaire sans durcissement**.

### Prochaine étape : vérifier l'accès SSH exclusivement par clé

Depuis une machine administratrice déjà autorisée, dans une
**deuxième session**, après récupération de l'IP Tailscale du Dell :

```bash
ssh -o PreferredAuthentications=publickey \
  -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no \
  ceratoadmin@IP_TAILSCALE_DELL
```

Ce test est à exécuter depuis **le PC administrateur**, pas depuis le
Dell. Il échouera si aucune clé SSH publique de l'administrateur n'a
été enregistrée dans le compte `ceratoadmin` : il faut alors
configurer la clé, pas désactiver prématurément les mots de passe.
Ne pas déconnecter la session SSH actuelle.

Sur le Dell, vérifier l'analyse des paramètres globaux :

```bash
sudo /usr/sbin/sshd -t
sudo /usr/sbin/sshd -T | grep -E '^(passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitrootlogin) '
```

`sshd -T` sans argument `-C` ne garantit pas les paramètres
applicables à des règles `Match`. Après confirmation de la connexion
par clé depuis un autre poste et d'un accès console de secours,
préparer une politique SSH restrictive, valider la configuration et
tester une seconde session **avant** d'envisager un rechargement du
service. Ne pas activer UFW sans définir des règles spécifiques qui
préservent SSH et WireGuard.

### Vérification de la publication NAT actuelle

Le HTTP 200 déjà reçu depuis `10.77.0.1` vers `10.77.0.2:8080`
démontre que le tunnel transporte ce trafic. Il ne prouve pas le
chemin Internet vers `54.37.165.151:8080`. Faire un unique test
depuis 4G/5G ou un autre réseau extérieur avant de conclure au bon
fonctionnement de la publication NAT.

Le passage en mode routé doit mettre à jour l'état persistant OVH et Dell
**de manière coordonnée** ; ne pas se contenter d'opérations `ip`
éphémères. En attendant, conserver la règle NAT et le tunnel.

## Audit des dépendances de basculement (à lancer sur RISE-1)

Ce contrôle est complémentaire au préflight IP déjà effectué. Il détecte
les dépendances **persistantes** qui risquent de réinstaller l'ancienne
adresse publique sur la WAN, ou de remplacer les règles nftables.

```bash
cd ~/Cerato-Network
git fetch origin feature/public-ip-path-preflight
git show origin/feature/public-ip-path-preflight:scripts/audit_routed_cutover_dependencies.py \
  > /tmp/cerato-cutover-audit.py

sudo python3 /tmp/cerato-cutover-audit.py \
  --public-ip 54.37.165.151 \
  --peer-ip 10.77.0.2 \
  --wan enp1s0f0 --wg wg-cerato
```

Ce script lit les paramètres réseau Cerato et les résume en booléens
et nombres, sans publier les clés, les configurations brutes ou les
identifiants. Le champ `can_activate` reste volontairement
`false` : les prérequis SSH et de rollback hors bande doivent
être validés indépendamment. **Ne pas désactiver les services
`cerato-network-additional-ip` ou `cerato-network-rules` avant
la migration coordonnée**.

## Inventaire du vrai contrôleur RISE-1 (lecture seule, sans secret)

Le projet GitHub possède des contrats de routage et de persistance
mais la logique active `/usr/local/sbin/ceratoctl` régénère
`table ip cerato_network`. Avant de développer une migration
permanente, identifier les fonctions exactes du contrôleur installé,
sans exporter les fichiers de configuration ou les clés :

```bash
cd ~/Cerato-Network
git fetch origin feature/public-ip-path-preflight
git show origin/feature/public-ip-path-preflight:scripts/inspect_live_network_engine.py \
  > /tmp/cerato-live-engine-inspect.py
python3 -m py_compile /tmp/cerato-live-engine-inspect.py
sudo python3 /tmp/cerato-live-engine-inspect.py
```

L'outil n'affiche que les empreintes SHA256, la taille des sources et
les noms des fonctions et commandes d'administration pertinentes.
Il n'ouvre aucun port, ne change aucune IP et n'imprime pas les
valeurs sensibles. Si les fichiers actifs sont inconnus, un
résultat `exists=false` ou `python=false` signifie qu'il faut
identifier la vraie implémentation avant toute migration.

**Ne jamais partager** le contenu intégral de
`/etc/cerato-network/config.json`, `/etc/wireguard/wg-cerato.conf`
ou un dump avec clés privées.

## Introspection des fonctions de régénération (RISE-1)

Le premier inventaire a confirmé sur RISE-1 :
- `ceratoctl` Python SHA-256 `41e11e267af622b608a40403d1d8d976903e9ea88470a078a7e568854935f2b6`,
  avec fonctions `render_nft`, `rewrite_wg_peers`, `apply`, `save`.
- `server.py` SHA-256 `9c7087a1eeca7e3c8a4462c2cd8e6659e4d692409771117c575cd00b46b30360`.

L'inventaire ci-dessous est **strictement en lecture seule**,
bloque les empreintes différentes, n'imprime ni source ni valeurs de
configuration et résume uniquement les appels, paramètres et clés connues
de l'AST. Il sert à adapter le patch du contrôleur existant :

```bash
cd ~/Cerato-Network
git fetch origin feature/public-ip-path-preflight
git show origin/feature/public-ip-path-preflight:scripts/inspect_live_controller_semantics.py \
  > /tmp/cerato-live-controller-semantics.py
python3 -m py_compile /tmp/cerato-live-controller-semantics.py
sudo python3 /tmp/cerato-live-controller-semantics.py \
  --controller-sha 41e11e267af622b608a40403d1d8d976903e9ea88470a078a7e568854935f2b6 \
  --backend-sha 9c7087a1eeca7e3c8a4462c2cd8e6659e4d692409771117c575cd00b46b30360
```

Une empreinte différente signifie que le fichier de production a changé.
Ne pas contourner la comparaison pour forcer un patch. Les scripts
d'inventaire restent distincts des opérations d'installation.

## Détails du générateur réel pour raccordement IPv4 /32

À partir de l'inspection réelle transmise, le contrôleur
`/usr/local/sbin/ceratoctl` possède bien `render_nft(data)`,
`rewrite_wg_peers(data)`, `apply(data)`, et le SHA-256 suivant :
`41e11e267af622b608a40403d1d8d976903e9ea88470a078a7e568854935f2b6`.

Le générateur `network/routed_nft_inject.py` prépare désormais les
autorisations ciblées vers et depuis une /32 routée en les insérant avant
les deux DROP historiques, et conserve le DROP INPUT destiné à la
passerelle. Les tests reproduisent la topologie observée le 31/10/2026.
**Ce n'est pas encore un patch installé sur le contrôleur RISE-1.**

Pour raccorder le code sans deviner les implémentations privées, l'outil
ci-dessous produit un AST limité aux trois fonctions citées, avec toutes
les chaînes littérales masquées et un contrôle du SHA avant lecture :

```bash
cd ~/Cerato-Network
git fetch origin feature/public-ip-path-preflight
git show origin/feature/public-ip-path-preflight:scripts/review_live_network_generators.py \
  > /tmp/cerato-review-generators.py
python3 -m py_compile /tmp/cerato-review-generators.py

sudo python3 /tmp/cerato-review-generators.py \
  --controller-sha 41e11e267af622b608a40403d1d8d976903e9ea88470a078a7e568854935f2b6
```

L'inspection ne lance aucune fonction de `ceratoctl`, ne modifie pas
les IP et n'imprime pas le contenu brut des fichiers. **Lire tout
de même le rapport avant partage** : les noms de variables et
l'architecture logicielle sont visibles même si les valeurs des
chaînes ne le sont pas. En cas d'empreinte différente, elle refuse
l'analyse sans réappliquer le réseau.

## Préparer une copie isolée du contrôleur réel (aucune installation)

Le rapport AST vérifié a montré que `render_nft(data)` termine par
le retour du rendu, et que `rewrite_wg_peers(data)` écrit la variable
`original` dans un fichier temporaire avant `os.replace`.
Le correctif AST injecte uniquement deux appels dans ces fonctions,
plus une bibliothèque de rendu pur. Il conserve les anciennes règles
NAT et les anciens pairs si `routed_ipv4` est absent ou vide.

**Important :** le résultat est une copie de développement, PAS une
release prête à installer. Ne pas copier les fichiers générés dans
`/usr/local/sbin/` ou `/opt/cerato-network/`.

Sur RISE-1, depuis le dépôt Git actuel :

```bash
set -o pipefail
cd ~/Cerato-Network
git fetch origin feature/public-ip-path-preflight

git show origin/feature/public-ip-path-preflight:scripts/stage_live_routed_controller.py \
  > /tmp/cerato-stage-controller.py

STAGE="$(sudo mktemp -d /tmp/cerato-routed-stage.XXXXXXXX)"
sudo install -d -m 0700 "$STAGE/support"

for f in live_routed_compat.py routed_nft_inject.py routed_firewall.py; do
  git show "origin/feature/public-ip-path-preflight:network/$f" \
    | sudo tee "$STAGE/support/$f" >/dev/null
done

sudo python3 /tmp/cerato-stage-controller.py \
  --source /usr/local/sbin/ceratoctl \
  --controller-sha 41e11e267af622b608a40403d1d8d976903e9ea88470a078a7e568854935f2b6 \
  --support-dir "$STAGE/support" \
  --destination "$STAGE/patched"

sudo python3 -m py_compile "$STAGE/patched/ceratoctl" \
  "$STAGE/patched/cerato_routed_support.py" \
  "$STAGE/patched/routed_nft_inject.py" \
  "$STAGE/patched/routed_firewall.py"
```

Ce code ne lance aucune fonction du vrai contrôleur, ne change
aucun service et refuse une empreinte modifiée. L'étape suivante
reste la validation du rendu complet sous préproduction avant
de créer un vrai installateur avec sauvegarde, rollback et watchdog.

## Contrôle statique de la copie effectivement créée sur RISE-1

Le `stage_live_routed_controller.py` a retourné `staged-only`,
`network_modified=false`, source
`41e11e267af622b608a40403d1d8d976903e9ea88470a078a7e568854935f2b6`
et copie
`4eb69872bf571b678f469eb33dc6cff26f0adf468aa1d98b1b39b943a02fa793`.
Le dossier réellement créé était
`/tmp/cerato-routed-stage.Gwi10hKO/patched`.

Le validateur ci-dessous contrôle les empreintes, la propriété
root et les permissions des quatre fichiers, les deux appels
AST d'insertion réseau, ainsi que l'identité octet par octet des
modules d'origine. Il **ne charge ni n'exécute** le `ceratoctl`
préparé ni les modules, ne touche pas à l'IP, et ne prouve pas la
fonctionnalité du routage réel.

```bash
cd ~/Cerato-Network
git fetch origin feature/public-ip-path-preflight
git show origin/feature/public-ip-path-preflight:scripts/verify_staged_routed_controller.py \
  > /tmp/cerato-verify-routed-stage.py
sudo python3 /tmp/cerato-verify-routed-stage.py \
  --stage /tmp/cerato-routed-stage.Gwi10hKO/patched \
  --support-dir /tmp/cerato-routed-stage.Gwi10hKO/support \
  --patched-sha 4eb69872bf571b678f469eb33dc6cff26f0adf468aa1d98b1b39b943a02fa793
```

Résultat attendu : `status=review-only-verified`,
`ready_to_install=false`, `network_modified=false`.

### Convergence des deux états persistants

En amont du basculement, l'état
`additional-ip-managed.json` représente une /32 routée sous
`{"ip":...,"peer":...,"wan":...}`, tandis que le contrôleur historique
doit lire une allocation `{"ip":...,"peer":...}` de sa propre
configuration. Le nouveau contrat pur
`network/routed_state_agreement.py` **refuse toute divergence** et
tout alias local ou NAT encore actif sur l'adresse routée. Il fournit
au rendu le `management_ipv4` relevé sur la route WAN effective,
non depuis une entrée utilisateur.

Cela reste un contrat de validation sans lecture/écriture système.
Une future transaction privilégiée devra synchroniser les deux
sources de vérité et vérifier le rollback avant toute publication.

## Essai à blanc du moteur nft avec les données réelles du RISE-1 (lecture seule)

Une fois que le staging `Gwi10hKO` a passé la vérification
`status=review-only-verified`, le script ci-dessous vérifie le
**rendu** du contrôleur historique contre celui de la copie, puis
construit une simulation d'état futur à partir de **copies en mémoire**.
Il retire virtuellement le NAT TCP 8080 et prépare virtuellement une
route `54.37.165.151/32` vers le pair `10.77.0.2`. Il ne sauvegarde
aucun fichier et n'exécute ni le contrôleur complet, ni `nft`,
ni `wg`, ni `ip` ni `systemctl`.

Le script ne traite que la fonction AST `render_nft(data)` vérifiée
par SHA avec un espace d'exécution limité aux fonctions de rendu
nécessaires. Les trois modules de compatibilité sont également
vérifiés sur leurs empreintes avant chargement.
**Les données de configuration et le rendu nft ne sont jamais
imprimés**. Une différence de forme de règles provoque un refus,
plutôt qu'une correction automatique.

```bash
cd ~/Cerato-Network
git fetch origin feature/public-ip-path-preflight

git show origin/feature/public-ip-path-preflight:scripts/dry_run_staged_routed_controller.py \
  > /tmp/cerato-routed-dry-run.py

python3 -m py_compile /tmp/cerato-routed-dry-run.py

sudo python3 /tmp/cerato-routed-dry-run.py \
  --stage /tmp/cerato-routed-stage.Gwi10hKO/patched \
  --public-ip 54.37.165.151 \
  --vpn-ip 10.77.0.2 \
  --management-ip 51.210.223.57
```

Résultat attendu : `status=validated-in-memory`,
`current_legacy_render_unchanged=true`, les trois contrôles
`virtual_forward_inbound`, `virtual_forward_outbound` et
`virtual_gateway_input_drop_preserved` à `true`,
`network_modified=false`, `ready_to_install=false`.
Ce résultat est une preuve de **compatibilité de génération de
règles seulement**, et non une preuve de bon routage ni un feu vert
pour retirer l'alias WAN actuel.

Le basculement réel nécessite encore les vérifications OVHcloud,
l'agent Dell, la politique du firewall du Dell et le rollback
à expiration indépendant sur les deux hôtes.

## Correction dry-run INPUT pool-set (31 octobre 2026)

L'essai à blanc sur le RISE-1 a renvoyé
`INPUT drop historique absent ou dupliqué`. L'ancien validateur
attendait un DROP sur une IPv4 seule, mais `render_nft` peut émettre
l'ensemble `ip daddr { 54.37.165.151, ... } drop` depuis le pool
historique. Le correctif parse **l'ensemble littéral exact de la
chaîne INPUT** et refuse le cas où la /32 n'est pas membre, si une
entrée est invalide/dupliquée, ou si la protection a changé.

**Attention :** la copie
`/tmp/cerato-routed-stage.Gwi10hKO/patched` contient l'ancien
`routed_nft_inject.py` ; elle ne doit pas être utilisée pour ce
nouveau test. Préparer une **nouvelle** copie privée avec le module
corrigé, sans installer quoi que ce soit sur le réseau.

```bash
set -euo pipefail
cd ~/Cerato-Network
git fetch origin feature/public-ip-path-preflight
REV=08db1e75ba8064208fa1b62ccdc2534311869cfa
git cat-file -e "$REV^{commit}"

git show "$REV:scripts/stage_live_routed_controller.py" > /tmp/cerato-stage-controller-fix.py
git show "$REV:scripts/dry_run_staged_routed_controller.py" > /tmp/cerato-routed-dry-run-fix.py

STAGE="$(sudo mktemp -d /tmp/cerato-routed-stage.XXXXXXXX)"
sudo install -d -m 0700 "$STAGE/support"
for f in live_routed_compat.py routed_nft_inject.py routed_firewall.py; do
  git show "$REV:network/$f" | sudo tee "$STAGE/support/$f" >/dev/null
done

test "$(sudo sha256sum "$STAGE/support/routed_nft_inject.py" | cut -d' ' -f1)" \
  = 3f60268c1532d86ddbdd873be5471948636b7455390163044d0851ffe82eb299

sudo python3 /tmp/cerato-stage-controller-fix.py \
  --source /usr/local/sbin/ceratoctl \
  --controller-sha 41e11e267af622b608a40403d1d8d976903e9ea88470a078a7e568854935f2b6 \
  --support-dir "$STAGE/support" --destination "$STAGE/patched"

sudo python3 /tmp/cerato-routed-dry-run-fix.py \
  --stage "$STAGE/patched" \
  --public-ip 54.37.165.151 \
  --vpn-ip 10.77.0.2 \
  --management-ip 51.210.223.57
```

La révision `08db1e75...` est précisément celle dont les tests
CI sont réussis. Le script exige toujours le SHA-256 de
`ceratoctl` original et de sa copie, ainsi que les empreintes
des trois modules. Aucun `nft`, `wg`, `ip`, ni accès SSH
n'est exécuté. La configuration reste inchangée ; ce test
n'autorise ni installation ni basculement de l'Additional IPv4.

## Dell R530 — audit détaillé et filtrage de la future IPv4 (31 octobre)

La simulation du moteur nftables sur **OVH RISE-1** est confirmée
`status=validated-in-memory` avec le contrôleur
`/tmp/cerato-routed-stage.qRfaZSoQ/patched` et aucun changement réseau.

Le point suivant est l'accès réel et le firewall du **Dell Ubuntu
24.04.5**. L'outil `scripts/preflight_dell_routed_peer.py` ne fait
que des lectures (adresse WG, retour par la table 51820, conflit
priorité 1101, `rp_filter`, `sshd -T`, interfaces Tailscale et ports
TCP ouverts). Il ne lit pas les clés et ne modifie aucun paramètre.
Il laisse toujours `ready_to_activate=false`.

Depuis **le Dell connecté en SSH par Tailscale** :

```bash
cd ~
if [ ! -d Cerato-Network-preflight/.git ]; then
  git clone --depth 1 --branch feature/public-ip-path-preflight \
    https://github.com/EXODEcola/Cerato-Network.git Cerato-Network-preflight
fi
cd ~/Cerato-Network-preflight
git fetch origin feature/public-ip-path-preflight
git show FETCH_HEAD:scripts/preflight_dell_routed_peer.py \
  > /tmp/cerato-dell-peer-audit.py
python3 -m py_compile /tmp/cerato-dell-peer-audit.py

sudo python3 /tmp/cerato-dell-peer-audit.py \
  --public-ip 54.37.165.151 --vpn-ip 10.77.0.2 \
  --tunnel wg-cerato --table 51820 --priority 1101
```

Le champ `ufw_state` est informatif : `inactive` ne démontre
pas qu'il n'y a aucune autre règle nftables. Une configuration
firewall dédiée est obligatoire avant l'ouverture Internet.
`network/dell_public_firewall.py` prépare, sans appliquer, une
politique INPUT restrictive **uniquement** pour l'adresse publique
routée : SSH TCP 22 explicitement autorisé, puis DROP sur la /32
(autres ports à autoriser individuellement, notamment 8080 si le
service actuellement publié doit rester accessible).

Ne **pas** appliquer ces règles depuis SSH, ni attribuer la /32
directement, tant que la transaction et le rollback indépendants
Dell/RISE-1 ne sont pas implémentés et validés.

## Dell — audit d'exposition et routage cryptokey WireGuard (lecture seule)

Résultat du premier audit fourni par le Dell R530 (31 octobre) :
11 vérifications sur 11 conformes, `sshd` par clé seule,
`wg-cerato=10.77.0.2`, source VPN routée par table `51820`,
priorité `1101` disponible, `rp_filter` non strict et Tailscale
présent. TCP écoute sur les ports 22, 53, 40295, 60784 ;
`ufw_state=inactive`. Ce ne sont pas des preuves d'exposition
publique de ces ports.

Sur le **Dell**, pas sur RISE-1, lancer le complément :

```bash
cd ~/Cerato-Network-preflight
git fetch origin feature/public-ip-path-preflight

git show FETCH_HEAD:scripts/preflight_dell_exposure_cryptokey.py \
  > /tmp/cerato-dell-exposure.py

python3 -m py_compile /tmp/cerato-dell-exposure.py

sudo python3 /tmp/cerato-dell-exposure.py \
  --public-ip 54.37.165.151 \
  --gateway-vpn-ip 10.77.0.1 \
  --tunnel wg-cerato
```

Le script ne montre ni clés WireGuard, ni adresses locales réelles,
ni règles nft en clair, ni processus. Il classe les adresses liées
aux ports TCP/UDP et mesure si le pair cryptokey associé à
`10.77.0.1` dispose bien de `0.0.0.0/0`, requis pour acheminer
l'ensemble des destinations Internet via cette route source.
Il relève aussi l'existence de chaînes INPUT nftables et d'une IPv6
globale ; ces comptages ne certifient aucune politique de filtrage.

`ready_to_activate=false` reste volontaire, même si tous les
contrôles techniques passent. Les pare-feu, watchdogs et agents
d'activation restent à développer et tester en conditions réelles.
