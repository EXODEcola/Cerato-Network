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
