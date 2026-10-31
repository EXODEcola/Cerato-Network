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
