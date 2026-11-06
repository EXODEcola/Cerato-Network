# Incident de routage Dell et décalage des releases — 6 novembre 2026

## Faits confirmés

L'Additional IPv4 54.37.165.151/32 est routée de OVH RISE-1 vers dell-r530 à travers WireGuard. Les paquets TCP 22 atteignaient bien le Dell ; la route de réponse pointait par erreur sur eno1 via 192.168.128.1. La règle de routage source à priorité 1101 avait disparu.

La commande de restauration peer a rétabli le routage source via wg-cerato table 51820 et le démarrage du service persistant sur Dell a confirmé enabled et active. Depuis Windows, le test TCP 22 est redevenu positif.

Cause technique certaine : absence de la règle ip rule source. Défaut de l'installateur historique : il activait le service de restauration avec systemctl enable sans le démarrer. La cause temporelle précise ayant supprimé la règle (reload/restart WG, réapplication de configuration, reboot ou autre) n'est pas établie par les journaux et ne doit pas être inventée. Le correctif de persistance démarre désormais le service peer et vérifie la route avant de désarmer le rollback. Le script séparé scripts/install_peer_route_guard.py propose une protection optionnelle Dell-only par vérification périodique avec une restauration idempotente.

## Pourquoi l'interface n'affiche pas les nouveaux systèmes

La release GitHub réellement publiée pour la bêta au 6 novembre est v0.1.0-beta.1, datée du 31 octobre 2026. Le workflow de signature actuel ne construit que le correctif CSS Graphite. Il ne diffuse ni nouveau backend/server.py, ni nouveau web/app.js, ni le moteur de routage multi-machine, ni les agents.

Les corrections en PR GitHub sont du code non déployé ; les tests verts ne les installent pas. Le frontend historique du RISE-1 (port 8787) et le prototype autonome web/app.js du dépôt sont différents. Remplacer brutalement le frontend ou le backend live par celui du dépôt casserait potentiellement les sessions, les routes et l'authentification.

La page NAT peut légitimement rester vide : une IPv4 publique totalement routée au Dell ne requiert pas de DNAT. En revanche, les pages Adresses IPv4 et Vue d'ensemble doivent compter cette IPv4 comme utilisée et montrer le peer dall-r530. Les boutons NAT et retrait du pool doivent être désactivés pour l'adresse routée, avec protection serveur. Le correctif read-only network/routed_ui_status.py et le staging de integrations/patch_live_routed_ui.py sont prévus pour cette étape, mais ne sont pas des releases Web actuellement installées.

## Pré-requis pour une prochaine release bêta réellement installable

1. Effectuer un audit en lecture seule des sources réelles RISE-1 : scripts/audit_live_ui_deployment.py fournit uniquement les empreintes et les indicateurs de présence des fonctions, jamais le code ou les secrets.
2. Préparer un patch sur une copie des fichiers exacts du panneau live : integrations/patch_live_routed_ui.py doit refuser les sources inconnues ; revoir manuellement le diff et toutes les protections d'authentification/CSRF.
3. Tester la compatibilité des routes HTTP, les fonctionnalités IPv4/NAT, le rollback signé et le redémarrage du Web sans toucher à WireGuard/nftables.
4. Construire une archive Web 8787 compatible avec la version installée, au lieu d'une archive source générique ou CSS-only.
5. Signer avec la clé Ed25519 indépendante déjà approuvée, publier une release immuable et son index de canal beta signé, synchroniser le miroir HTTPS OVH, puis vérifier la compatibilité depuis la page Mises à jour.

Le routage public complet et automatique d'une nouvelle IP depuis le Web nécessitera aussi un agent sur les deux machines, un protocole d'activation à rollback indépendant et des contrôles de disponibilité. Il n'est pas encore réalisé par la simple correction des compteurs et du formulaire.

Aucune modification de la VM Build, ni bascule du réseau live au cours d'une mise à jour visuelle. Un rapport candidate_for_safe_staging=true n'est pas une autorisation de déploiement : la validation des fichiers live exacts reste indispensable.
