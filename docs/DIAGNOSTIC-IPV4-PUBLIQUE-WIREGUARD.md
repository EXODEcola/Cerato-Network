# Préflight IPv4 publique vers un pair WireGuard (lecture seule)

Le tunnel WireGuard et une règle DNAT ne suffisent pas à démontrer la
connectivité entrante depuis Internet. Le présent outil inspecte **sans
modifier** les routes, interfaces, règles nftables et sockets locales.
Il ne nécessite ni redémarrage ni modification du panneau historique.

> Ne jamais transmettre les fichiers WireGuard, les clés privées ou le
> contenu brut de /etc/cerato-network. Ne pas ouvrir le port du panneau
> administratif ni celui de WireGuard sur l'Additional IPv4.

## Situation actuelle et cible

- `local-nat` : l'Additional IPv4 est configurée sur la WAN de RISE-1.
  Le DNAT `IPv4:8080/tcp -> 10.77.0.2:8080/tcp` publie **ce port
  uniquement**. Une tentative SSH sur `IPv4:22` ne teste pas la règle 8080.
- `routed-wg` (cible, non activé) : l'IPv4 /32 est portée par le Dell.
  RISE-1 doit avoir une route `IPv4/32` vers le pair WireGuard, et ce
  pair doit accepter cette destination dans ses AllowedIPs. L'agent Dell
  doit avoir une route de retour *sélective* par WireGuard pour les flux
  dont la source est l'IPv4 publique ; sa route par défaut existante ne
  doit pas être remplacée.
- Le pare-feu de chaque hôte et, le cas échéant, celui de l'hébergeur
  doivent autoriser uniquement les services prévus. Le routage /32 ne
  signifie pas ouverture automatique de tous les services.

**Attention :** ne pas supprimer l'alias /32 du RISE-1, recharger Netplan,
remplacer `AllowedIPs`, faire `nft flush ruleset`, ni modifier la route
par défaut de la passerelle pour essayer ce mode. Un basculement réel
nécessite un plan atomique, des sauvegardes, un watchdog de rollback, un
accès console de secours et des tests bidirectionnels.

## 1. État du NAT actuellement déployé

Exécuter sur RISE-1, après avoir vérifié le nom réel de l'interface WAN :

```bash
cd ~/Cerato-Network
git pull --ff-only origin main
sudo python3 scripts/preflight_public_ipv4.py \
  --role gateway --mode local-nat \
  --public-ip IP_SUPPLEMENTAIRE --peer-ip IP_VPN_DELL \
  --wan INTERFACE_WAN --tunnel wg-cerato --port 8080
```

Le diagnostic peut signaler « unknown » si une commande ou un droit est
indisponible. Les résultats « ok » décrivent une configuration locale ;
ils **ne certifient pas** une connexion Internet de bout en bout.

## 2. Préflight du mode routé (sans l'activer)

Sur RISE-1 :

```bash
sudo python3 scripts/preflight_public_ipv4.py \
  --role gateway --mode routed-wg \
  --public-ip IP_SUPPLEMENTAIRE --peer-ip IP_VPN_DELL \
  --wan INTERFACE_WAN --tunnel wg-cerato
```

Sur le Dell Ubuntu 24.04, avec le même script copié depuis la branche
approuvée :

```bash
sudo python3 scripts/preflight_public_ipv4.py \
  --role peer --mode routed-wg \
  --public-ip IP_SUPPLEMENTAIRE --peer-ip IP_VPN_DELL \
  --tunnel wg-cerato --port 8080
```

Le mode routé n'étant pas encore configuré, les alertes « attention »
sont **attendues**. Ce n'est pas une instruction de corriger manuellement
chaque alerte sur la production.

## 3. Prouver le trajet du NAT depuis l'extérieur

Faire le test TCP **depuis un réseau réellement externe**, pas depuis RISE-1
ni le Dell. Prévoir un serveur d'écoute sur le Dell (port 8080) et une
fenêtre de capture courte. Sur RISE-1, une capture à la fois :

```bash
sudo timeout 25 tcpdump -nni INTERFACE_WAN 'host IP_SUPPLEMENTAIRE and tcp port 8080'
sudo timeout 25 tcpdump -nni wg-cerato 'host IP_VPN_DELL and tcp port 8080'
```

Sur le Dell :

```bash
sudo ss -ltn '( sport = :8080 )'
sudo timeout 25 tcpdump -nni wg-cerato 'tcp port 8080'
```

De l'extérieur :

```bash
curl -v --connect-timeout 4 http://IP_SUPPLEMENTAIRE:8080/
```

L'échec HTTP **n'implique pas** l'échec du TCP : comparer les captures.

| Observation | Prochaine vérification |
|---|---|
| Aucun paquet à l'entrée WAN | Routage/attribution OVH et filtrage amont |
| WAN reçoit, WG n'émet pas | DNAT, chaîne FORWARD, ip_forward, conntrack |
| WG émet, Dell ne reçoit pas | AllowedIPs, tunnel, routes, pare-feu |
| Dell reçoit mais aucun SYN-ACK | Service en écoute, firewall du Dell |
| SYN-ACK sur Dell, pas de réponse externe | Route retour, SNAT/conntrack, rp_filter, règles FORWARD |

Ne pas présenter `wg show` (handshake) comme une preuve de routage public.

## Cas fréquent : DNAT valide mais route retour asymétrique

Si le Dell utilise sa box locale comme route par défaut et que la
passerelle effectue uniquement le DNAT (sans SNAT), les paquets entrants
peuvent parvenir au service mais les réponses dirigées vers le client
Internet repartent par le réseau local au lieu de WireGuard.
Le diagnostic `--role peer --mode local-nat` signale ce cas en lisant
la route du noyau pour une connexion de test à source VPN.
**Ce signal ne prouve pas à lui seul une panne** : la passerelle
pourrait aussi effectuer une translation SNAT, à confirmer.

Vérifier dans l'ordre, sans modifier le réseau :

1. Démarrer temporairement sur le pair un service de test TCP limité
   à son IP VPN (dans un répertoire vide) et vérifier qu'il écoute.
2. Tester depuis la passerelle directement l'adresse VPN du pair.
   Ce test contourne l'IP publique et le DNAT.
3. Tester le port publié depuis une connexion externe indépendante.
4. En cas d'échec, inspecter les compteurs nftables et faire une capture
   ciblée sur WAN, interface WireGuard de la passerelle et du pair.
5. Contrôler la route retour du pair et les éventuelles règles SNAT.
   Ne jamais remplacer sa route par défaut ni ouvrir SSH à Internet
   pour corriger un test HTTP.

Exemple de service temporaire, sur le pair, avec un répertoire vide
(suppression et arrêt après vérification) :

```bash
mkdir -p /tmp/cerato-test-empty
python3 -m http.server 8080 --bind IP_VPN_DELL --directory /tmp/cerato-test-empty
```

**Important :** le serveur HTTP de test est accessible via le port
publié pendant son fonctionnement. Il doit rester limité à une fenêtre
de diagnostic courte. Stopper avec Ctrl+C.

## 4. Critères avant d'activer réellement le mode routed-wg

1. L'Additional IPv4 est confirmée par OVH comme routée au serveur passerelle.
2. L'IPv4 supplémentaire est retirée du rôle **local** de RISE-1 lors
   d'un basculement contrôlé (avec récupération immédiate possible).
3. RISE-1 possède la route /32 vers WireGuard, l'AllowedIPs exact du
   pair, l'IPv4 forwarding, et les règles FORWARD explicites.
4. Le Dell porte la /32 sur WireGuard et dispose d'un routage par politique
   pour les paquets source /32 via ce tunnel, sans modifier le trafic
   de gestion habituel. La configuration survit au redémarrage.
5. Anti-spoofing, `rp_filter`, pare-feu sur les deux hôtes, chemin retour
   OVH et MTU sont testés ; pas d'accès administratif inutile exposé.
6. Tests entrée/sortie TCP + UDP et source IP sortante, puis
   test de reprise sur échec avec watchdog et rollback réseau.
7. Le panneau historique, la connexion SSH sur l'IP **principale**, les
   autres pairs et les règles NAT existantes restent opérationnels.

**Le code de ce préflight ne réalise aucun de ces changements.** Le moteur
de basculement distant et son rollback feront l'objet d'un développement
distinct, après revue de l'état réel des deux machines.

## 5. Releases Cerato Network

La release `v0.1.0-beta.1` publiée sur GitHub contient un overlay CSS ;
elle ne constitue pas une release du routage /32. Les versions réseau
ultérieures doivent être signées et vérifier la compatibilité avec le
backend historique RISE-1, puis être proposées dans l'interface avec
installation, contrôle de santé et rollback. Les tags `dev` nécessiteront
l'extension explicite du pipeline de publication et du catalogue signé ;
renommer le canal sans adapter le vérificateur ne suffit pas.
