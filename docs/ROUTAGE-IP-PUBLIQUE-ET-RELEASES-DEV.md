# Cerato Network — IPv4 routée et releases Dev

## État validé sur les deux serveurs (31 octobre 2026)

Passerelle RISE-1 : IP de gestion 51.210.223.57, WAN \`enp1s0f0\`,
Additional IPv4 54.37.165.151/32 actuellement locale sur WAN,
\`wg-cerato\` 10.77.0.1, IPv4 forwarding actif.
La table nftables historique contient une publication TCP 8080
vers 10.77.0.2:8080. Le \`drop\` WAN vers l'Additional IP est dans
la chaîne **INPUT**, et ne démontre donc pas un blocage FORWARD.

Dell R530 : interface \`wg-cerato\` 10.77.0.2/32, service SSH présent
sur 22, route par défaut LAN 192.168.128.1. Un test HTTP OVH
\`curl http://10.77.0.2:8080/\` a renvoyé HTTP 200.
La règle \`from 10.77.0.2 lookup 51820\` et un
\`ip route get 1.1.1.1 from 10.77.0.2\` montrent une route source
via WireGuard. \`rp_filter=2\` sur \`all\` et sur \`wg-cerato\`.
Tailscale est toujours présent avec ses propres règles/fwmarks.

Ces observations **ne prouvent pas** l'accès public Internet -> Additional IPv4
ni l'existence d'une politique source pour 54.37.165.151.

## Objectif de produit

La machine reçoit l'IPv4 publique en /32 via WireGuard, et les services
écoutent localement sur cette IP. Le Dell gère ses ports dans son
pare-feu. La passerelle conserve **son IPv4 principale**, son tunnel
et ses accès de secours. Une IP ne doit pas être simultanément en
mode DNAT-port et en mode routé dans la configuration Cerato.

\`network/plan.py\` expose une allocation exclusive de /32 en mode routé ;
\`network/routed_readiness.py\` contrôle les exigences **avant** une
activation, sans aucune action privilégiée. Le champ
\`apply_allowed=false\` est volontaire.

### Conditions de basculement

- OVH confirme explicitement que l'Additional IPv4 est attachée et routée
  au RISE-1. Ne jamais deviner cela à partir de \`ip addr\` seulement.
- Agent Dell opérationnel et authentifié, aucune clé privée stockée dans
  les fichiers de release, permissions et renouvellement de session audités.
- Priorité IP rule libre et route source **pour 54.37.165.151/32** via
  WireGuard, sans remplacer la route par défaut LAN ni celle de Tailscale.
- AllowedIPs de la passerelle incluant la /32 publique pour le pair Dell,
  tout en conservant l'actuelle 10.77.0.2/32 et les autres pairs.
- Forwarding et pare-feu de la passerelle adaptés dans **la chaîne
  existante** et persistants après toute réapplication Cerato.
  Les connexions retour et la politique de pare-feu Dell sont vérifiées.
- Migration contrôlée de l'actuelle publication NAT TCP 8080 et de
  l'alias /32 local sur WAN, avec backup et restauration atomiques.
- Watchdogs indépendants sur OVH et Dell, avec scénario de panne
  réellement testé en préproduction. Aucune confirmation n'est demandée
  avant un test SSH/TCP/UDP **depuis Internet extérieur**.
- SSH Dell par clés, filtrage par adresse d'administration lorsque possible,
  limitation brute-force, comptes isolés. L'IP de gestion de RISE-1 ne doit
  jamais être déplacée.
- Reboot, perte de tunnel et réapplication des anciennes règles testés.
  Des tests simulés sur GitHub ne sont pas une validation de production.

**Important :** les outils de cette branche sont uniquement un préflight
et des contrats de planification. Ils n'installent pas l'agent et ne
bascultent aucune route. Il n'existe donc pas encore de commande
\`--apply\` approuvée pour RISE-1.

## Canal Dev signé : contrat initial

La chaîne de versions accepte maintenant trois canaux
\`dev\`, \`beta\`, \`stable\`, avec versions immuables :

| Canal | Exemple | Contrôles |
|---|---|---|
| Dev | \`v0.1.1-dev.1\` | Signature Ed25519, index \`dev.json/dev.sig\`, ZIP compatible |
| Bêta | \`v0.1.1-beta.1\` | Même vérification, canal séparé |
| Stable | \`v0.1.1\` | Version sans suffixe uniquement |

L'ordre sémantique à base identique est Dev < Bêta < RC < Stable.
Une version \`v0.1.0-dev.1\` est **antérieure** à l'actuelle
\`v0.1.0-beta.1\` : pour les prochains tests après cette bêta,
commencer à \`v0.1.1-dev.1\`.

Le workflow de signature sur \`main\` permet une publication Dev avec
le même environnement protégé que Bêta/Stable. Deux programmes
de renouvellement des index (\`beta\` et \`dev\`) utilisent une clé
Ed25519 approuvée. Les fichiers publics sont publiés par génération
atomique, sans exposer de clé privée sur le RISE-1.

### Limites actuelles

- La version installée en production reste \`v0.1.0-beta.1\`,
  canal \`beta\`. Elle **ne change pas** quand ce code est poussé sur
  une branche GitHub.
- Le backend et l'interface historique du RISE-1 n'ont pas encore de
  sélecteur Dev/Bêta/Stable : leur source effective est locale,
  contrôlée par \`/etc/cerato-network/release-source.json\`.
- Le pipeline signé actuel construit seulement l'overlay CSS
  compatible \`8787\`, **pas** un agent Linux, une migration réseau,
  ni une nouvelle authentification.
- Le basculement vers le canal Dev devra être une action Owner/Admin
  protégée CSRF/MFA, configurée hors bande et avec vérification du
  canal signé, sans permettre de changer librement l'URL ou la clé.
- Une publication Dev ne remplace pas les tests opérationnels réseau.

## Pour suivre le développement

PR en brouillon \`feature/public-ip-path-preflight\` :
tests Python/JavaScript et publication des index Dev sur GitHub Actions.
Ne pas fusionner puis déployer sur RISE-1 sans la migration backend, les
tests de l'agent, la sécurité Owner/Admin/User et le rollback système
indépendant.
