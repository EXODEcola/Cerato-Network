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
