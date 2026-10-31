# Basculer une Additional IPv4 OVH vers un Dell — contrat de récupération

**Statut : développement / revue uniquement. Aucune commande d'activation prête pour la production.**

## Observations réelles reçues le 31 octobre 2026

- RISE-1 : IPv4 principale `51.210.223.57` sur `enp1s0f0`; Additional IPv4 `54.37.165.151` encore gérée comme alias WAN et rétablie au redémarrage. Une publication NAT TCP `8080` vers `10.77.0.2:8080` reste enregistrée.
- Contrôleur historique RISE-1 : simulation `validated-in-memory`, rendu NAT ancien inchangé, protections INPUT conservées, règles /32 FORWARD aller/retour générées en mémoire. **Aucune exécution nftables ou WireGuard.**
- Dell R530 : `wg-cerato=10.77.0.2`, source VPN routée via table `51820`, priorité `1101` disponible, SSH publickey-only, Tailscale présent ; audit 11/11 prérequis observés et 6/6 contrôles d'exposition/cryptokey.
- Dell : WireGuard vers `10.77.0.1` possède une AllowedIPs couvrant toutes les destinations IPv4, nécessaire au futur retour par défaut du trafic public.
- Dell : UFW déclaré inactif, **deux chaînes nft INPUT** détectées, dont une prenant en charge IPv6 ; leur existence ne certifie pas une politique sécurisée.
- Dell : SSH écoute sur toutes les adresses IPv4 **et IPv6**, et une IPv6 globale existe. Cette exposition est indépendante de la future IPv4 routée.
- Dell : ports TCP `22`, `53`, `40295`, `60784` observés ; **pas de TCP 8080 en écoute** dans ce relevé. Une ancienne publication NAT 8080 ne prouve donc pas qu'un service backend 8080 fonctionne.
- Dell : UDP `53`, `68`, `546`, `38261` et `41641` détectés, mais aucun service/port public n'est autorisé automatiquement. `41641` est fréquemment utilisé par Tailscale, son attribution réelle doit être vérifiée localement.

## Règles de sécurité impératives

1. Conserver `51.210.223.57` et sa route par défaut sur RISE-1 ; préserver `eno1`, la route LAN, Tailscale et SSH sur le Dell.
2. Ne jamais appliquer la transformation via une commande isolée `ip addr del`, `wg syncconf` ou `nft -f` tant que le rollback **indépendant et déjà armé** sur les deux machines n'est pas testé.
3. Ne pas exposer les ports à écoute globale autres que TCP 22 sans autorisation explicite et justification du service. Le profil nft de `network/dell_public_firewall.py` n'est actuellement qu'un **aperçu**.
4. Une politique `table ip` ne protège **pas** l'IPv6 : auditer et sécuriser indépendamment le chemin IPv6 public vers le Dell avant toute conclusion de durcissement global.
5. Avant cutover : snapshots de la configuration Cerato, états Additional IPv4, fichiers WG privés, règles nftables et routage effectif **sur leurs machines respectives**, permissions root, manifeste de restauration signé ou validé, intégrité vérifiée, watchdogs armés et récupération console réellement testée.
6. Ne jamais considérer la présence d'un pair Tailscale comme une preuve qu'une récupération hors bande est garantie. Tester une **nouvelle** session SSH, et vérifier un accès console indépendant en cas d'échec.
7. Conserver la NAT 8080 actuelle jusqu'à la transaction de migration ; ne pas la supprimer isolément. Distinguer sa déclaration de l'état d'écoute réel du service.

## Séquence d'activation prévue (à développer)

| Phase | RISE-1 | Dell R530 | Critère de sécurité |
| --- | --- | --- | --- |
| Préparation | Sauvegarde + preuve de restauration | Sauvegarde + pare-feu public /32 + audit IPv6 | Aucun changement routé |
| Armement | Rollback autonome et persistant, minuterie | Rollback autonome et persistant, minuterie | **Deux preuves indépendantes** |
| Staging | Préparer cryptokey AllowedIPs et host-route WG | Préparer /32, règle source /32 et firewall | Protéger le LAN, SSH et Tailscale |
| Basculement | Conversion persistances, remplacement NAT par FORWARD, retirer alias WAN en dernier | Confirmer route retour publique via WG | Modifications coordonnées |
| Vérification | S'assurer que l'IP principale et la console RISE-1 restent disponibles | Connexion SSH par clé **externe** + source d'IPv4 sortante + Tailscale/console | Tests indépendants |
| Commit | Acquittement et désarmement après succès des tests | Acquittement et désarmement après succès des tests | **Pas d'acquittement partiel** |
| Défaillance/timeout | Restaurer localement alias WAN, NAT, config et filtrage historiques | Restaurer localement IP et policy rules, filtres et config | **Aucun appel à l'autre hôte requis pour restaurer chacun** |

Le code `network/two_host_cutover_contract.py` impose l'ordre logique, les preuves préalables, l'approbation opérateur et six validations avant commit. Il **ne certifie aucune preuve** et retourne toujours `authorization_to_apply=false`.

Le code `network/two_host_rollback_rehearsal.py` simule les étapes, injecte une panne après chacune, puis vérifie que les snapshots des deux hôtes sont restaurés **en mémoire**. Il ne teste ni un vrai service systemd, ni une déconnexion réseau, ni la résistance à un redémarrage.

## Travaux restant avant de proposer une activation

- Implémenter puis tester de véritables agents privilégiés à privilèges minimaux et journaux signés.
- Configurer le **rollback local persistant à expiration sur chaque hôte**, l'essayer dans un environnement isolé et tester l'interruption de la communication entre machines.
- Faire vérifier la politique nft existante du Dell et son IPv6 publique. Les ports ouverts par défaut doivent rester limités aux besoins approuvés.
- Tester l'installation transactionnelle de l'état Cerato/WireGuard/nftables et la compatibilité des services de restauration au redémarrage.
- Disposer d'une sonde extérieure indépendante pour SSH en clé uniquement, TCP/UDP explicitement approuvés et source d'IPv4 de sortie.
- Revoir les contrôles de droits OWNER/ADMIN/USER, la signature de release et le processus de déploiement.

**Ne pas déployer le code actuel sur OVH ou Dell comme agent de cutover.**

## Diagnostic réel après le premier essai temporaire (31 octobre 2026)

Un test réel a placé temporairement `54.37.165.151/32` sur
`wg-cerato` côté Dell, avec règle source table `51820`, puis
l'a routée via OVH. OVH a confirmé `dev wg-cerato`.
Malgré cela, SSH public TCP/22 depuis Windows et HTTPS sortant
depuis la source 54.37.165.151 ont expiré.

Les deux retours arrière ont ensuite fonctionné :
`cerato-ovh-rollback.service` a renvoyé `status=0/SUCCESS`,
la /32 s'est retrouvée sur `enp1s0f0`, et l'IP et la règle
source temporaires ont été retirées du Dell.

**Capture WAN après rollback** : les SYN TCP/22 de l'IP cliente
`82.67.7.118` atteignent `enp1s0f0`, destination
`54.37.165.151`. Cette observation élimine un **défaut total de
réception** de l'Additional IPv4 chez OVH, mais ne prouve ni que
les SYN traversaient WireGuard pendant l'essai routé, ni que le
Dell répondait. L'absence de réponse TCP/22 **après rollback**
est attendue : OVH porte l'IP mais la politique Cerato ne publie
historiquement que TCP/8080.

### Limitation critique des règles nftables « accept »

Un `accept` dans `table ip cerato_network / chain forward` ne
court-circuite pas les autres *base chains* du même hook. Une
chaîne `inet ... forward` plus tardive peut encore émettre
`drop`. Même principe pour le profil de pare-feu ciblé Dell
et ses autres chaînes `input`. Ne pas désactiver ces autres
chaînes à l'aveugle.

Outil ajouté : `scripts/inspect_nft_forwarding_path.py`, lecture
seule, imprime seulement les métadonnées des chaînes filtrantes
(base hooks, priorités, politiques et nombres de verdicts) sans
exposer les règles ou les adresses privées.

Depuis **OVH** :

```bash
cd ~/Cerato-Network
git fetch origin feature/public-ip-path-preflight
git show FETCH_HEAD:scripts/inspect_nft_forwarding_path.py > /tmp/cerato-nft-hooks.py
sudo python3 /tmp/cerato-nft-hooks.py --role gateway
```

Depuis le **Dell** :

```bash
cd ~/Cerato-Network-preflight
git fetch origin feature/public-ip-path-preflight
git show FETCH_HEAD:scripts/inspect_nft_forwarding_path.py > /tmp/cerato-nft-hooks.py
sudo python3 /tmp/cerato-nft-hooks.py --role peer
```

Ces deux commandes peuvent être exécutées en état NAT restauré.
Elles sont préalables au **seul** prochain essai temporaire
synchronisé avec capture sur WAN OVH / WG OVH / WG Dell.
Elles ne constituent pas une preuve de blocage : le test de trafic
doit être effectué **pendant** que l'IP est routée, en sauvegardant
les compteurs des interfaces et les paquets SYN/SYN-ACK sur les
deux hôtes. Aucune désactivation du pare-feu public ou des
protections de gestion ne doit être tentée sans cette preuve.

## Rapport nftables réel des deux machines — 31 octobre, après restauration

Le second inventaire a renvoyé les faits suivants, obtenus sur les
deux machines sans activation réseau :

- **OVH / gateway :** une seule base chain FORWARD pertinente
  `table ip cerato_network / chain forward`, hook `forward`,
  priorité `-30`, policy `accept`, 4 règles (2 `drop`,
  2 `accept`). `other_base_chains_with_possible_drop=[]`.
- **Dell / peer :** une seule base chain INPUT IPv4 pertinente
  `table ip filter / chain INPUT`, hook `input`, priorité `0`,
  policy `accept`, 1 règle sans verdict `drop` ni `reject`
  détecté. `other_base_chains_with_possible_drop=[]`.

L'hypothèse « autre chaîne *base* nftables bloquant l'ACCEPT Cerato »
**n'est pas étayée par le ruleset au repos**. Le rapport ne couvre
pas les filtres `iptables-legacy`, les programmes `tc`/`XDP`,
les `rp_filter` noyau, ni l'évolution des règles lors d'une bascule.

**Lors de l'essai précédent, aucune capture simultanée des trois
interfaces n'a été réalisée pendant que l'IP était routée**.
La trace WAN après rollback ne peut localiser la panne.

### Contrôle ciblé pendant le prochain essai expirant

Instrumenter **simultanément** :

1. OVH `enp1s0f0` : SYN de l'IP cliente vers TCP/22 du /32 ;
2. OVH `wg-cerato` : SYN transmis en clair sur le tunnel ;
3. Dell `wg-cerato` : SYN reçu et éventuel SYN-ACK émis ;
4. Pour le test HTTPS sortant depuis le Dell : progression de la
   connexion sur Dell WG, OVH WG et OVH WAN.

L'outil de capture (lecture seule) peut être `tcpdump -nn` avec
filtre `host 54.37.165.151 and tcp and (port 22 or port 443)`,
placé **avant** l'activation temporaire, puis arrêté après les
deux tests. Ne jamais couper les sessions Tailscale et SSH de
gestion. Le rollback OVH doit être armé, validé et expirer
**avant** celui du Dell. Les règles spécifiques FORWARD sur
OVH doivent avoir un `counter` pour confirmer les paquets traités,
et ne doivent jamais supprimer les règles DROP existantes.

Ne pas inférer « problème OVH », « problème Dell » ou « problème
pare-feu » tant que la trace synchronisée n'indique pas la rupture.

## Chaînes secondaires : limite de l'inventaire initial et correctif

Le Dell a déclaré une base chain `ip filter INPUT` avec **une
règle mais aucun verdict direct**. Cette règle peut être un
compteur, mais peut aussi être un `jump`/`goto` vers une chaîne
secondaire capable de rejeter les paquets. Le premier audit
`inspect_nft_forwarding_path.py` n'analysait que les verdicts
situés directement dans la base chain, donc `drop_rules=0`
**n'exclut pas** un DROP indirect.

Le second outil `scripts/inspect_nft_chain_jumps.py` parcourt
récursivement les renvois vers les chaînes du même tableau,
signale les cibles non résolues et les verdicts dynamiques.
Il ne montre aucune condition de règle ni IP privée.

Sur **le Dell uniquement** :

```bash
cd ~/Cerato-Network-preflight
git fetch origin feature/public-ip-path-preflight
git show FETCH_HEAD:scripts/inspect_nft_chain_jumps.py \
  > /tmp/cerato-nft-branches.py
sudo python3 /tmp/cerato-nft-branches.py --role peer
```

Les champs `reachable_drop_rules`, `unresolved_targets`,
`dynamic_verdicts_possible` permettront de vérifier si
le premier inventaire a manqué une sous-chaîne de filtrage.
Un DROP *atteignable structurellement* reste seulement un
risque : il faut ensuite une trace SYN/SYN-ACK pendant
un essai limité avec les rollbacks.

## Preuve 8080 WAN et diagnostic direct du noyau (31 octobre)

Nouvelle capture sur `enp1s0f0` en mode NAT restauré :
la machine Windows (`82.67.7.118`) envoie des SYN vers
`54.37.165.151:22` **et** `54.37.165.151:8080`, visibles
sur OVH. Les essais SSH et HTTP du PC expirent. **La réception
WAN de ces deux ports est donc prouvée** ; aucun filtrage amont
général n'explique les timeouts.

L'absence de réponse SSH/22 est cohérente avec la politique
historique (seul 8080 est publié). Pour 8080, la panne est
à rechercher entre DNAT, FORWARD, WG et le retour Dell.
L'ancienne capture WG ne coïncidait pas formellement avec ce
test WAN, il serait abusif de prétendre qu'elle prouve un DROP
de paquets dans OVH.

Le nouvel outil `scripts/inspect_live_nat_8080.py` interroge
en **lecture seule** le ruleset JSON chargé par le noyau,
pour vérifier une règle DNAT TCP 8080 vers `10.77.0.2:8080`,
la présence des hooks PREROUTING/FORWARD, l'ordre des règles
FORWARD, le forwarding IPv4 actif, la présence de l'alias WAN
et la route vers le Dell via WireGuard. Il n'expose aucune clé
ni les conditions détaillées des règles.

Depuis OVH :

```bash
cd ~/Cerato-Network
git fetch origin feature/public-ip-path-preflight
git show FETCH_HEAD:scripts/inspect_live_nat_8080.py > /tmp/cerato-live-nat-8080.py
sudo python3 /tmp/cerato-live-nat-8080.py
```

À compléter, **sans rebasculer l'IP**, par une capture simultanée
WAN/WG pendant un seul test Windows `curl.exe` sur 8080,
en vérifiant les paquets `82.67.7.118 -> 54.37.165.151:8080`
sur WAN et `82.67.7.118 -> 10.77.0.2:8080` sur OVH WG.

Si le DNAT est absent dans le ruleset, corriger sa génération
et sa persistance **avant** de retenter le mode routé. Si DNAT
existe mais pas de paquets WG, regarder hooks FORWARD/rp_filter.
Si WG transmet, vérifier le Dell et sa politique de retour.
