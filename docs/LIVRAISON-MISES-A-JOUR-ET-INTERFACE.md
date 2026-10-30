# Livraison de l'interface opérationnelle et des mises à jour Cerato Network

## Travail livré dans le dépôt

- Thème graphite professionnel : `themes/cerato-graphite.css`. Gris anthracite, surfaces neutres, tableaux contrastés, accents vert sauge, pas de grands aplats bleus. La même direction est appliquée au développement `web/style.css`.
- Centre **Mises à jour** du panneau historique : `integrations/patch_live_update_center.py` conserve toutes les pages réseau et propose un état de distribution explicite, la version installée, la disponibilité réelle, le canal, les signatures, les vérifications et l'historique.
- Contrôleur de releases : `updates/live_controller.py` distingue source absente, version déjà à jour, index invalide, release non compatible et release prête. Il n'annonce jamais « installable » si une vérification cryptographique ou de compatibilité manque.
- Releases visuelles : nouveau format **`cerato-network-legacy-web-visual-v1`** comprenant exclusivement `web/app.js`, `web/style.css` et `compat.json`. **Pas de backend privé** dans l'archive distribuée.
- Préparation sur copie contrôlée : `integrations/prepare_live_visual_refresh.py` vérifie les empreintes connues du RISE-1, met à niveau le rendu de la page Mises à jour et applique le style, sans toucher aux fichiers ni au réseau en production.
- `tools/compose_live_overlay.py --visual-only` prépare l'overlay à partir de la sortie de staging. Les versions de provenance sont limitées explicitement par `--from-version`.
- Retour arrière : le contrôleur sauvegarde les fichiers Web avant installation, teste la syntaxe JS et compare les empreintes des configurations réseau persistantes plutôt que les handshakes WireGuard volatils.

## Ce qui n'est PAS encore en service

Le panneau public visible sur **51.210.223.57** reste l'ancienne installation. Les nouveaux fichiers GitHub ne sont pas copiés sur l'OVH par un simple `git pull`. Le panneau affiche actuellement **Distribution non configurée**, car il manque :

1. Une source de releases disponible en **HTTPS** avec index de canal signé et fichiers immuables.
2. Une paire Ed25519 officielle gérée par un hôte de signature isolé et la clé **publique** vérifiée, épinglée localement sur le RISE-1.
3. Une release compatible `v0.0.0` au format `visual-v1`, produite depuis une **copie contrôlée** de l'installation historique.
4. La version du contrôleur root permettant les overlays visuels (le contrôleur actuellement installé peut ne reconnaître que les overlays complets). Une opération d'administration unique est nécessaire pour l'initialiser/mettre à jour avant la première installation Web.
   - Le script contrôlé `scripts/upgrade-live-update-engine.sh --check` / `--install` prépare cette transition, avec sauvegarde et retour arrière en cas d'échec. **Il n'a pas encore été exécuté sur OVH.**

**Ne pas présenter ces quatre conditions comme accomplies.** Aucune signature ou source de distribution ne doit être générée secrètement dans GitHub Actions : l'intégrité du canal de mise à jour exige un contrôle indépendant de la clé.

## Pipeline de préparation — hôte de build de confiance

1. Prendre une copie privée, vérifiée de `/opt/cerato-network/backend/server.py`, `web/app.js` et `web/style.css` **sans publier cette copie**.
2. Préparer le rendu depuis cette copie :
   ```bash
   python3 integrations/prepare_live_visual_refresh.py \
     --source /chemin/prive/console-riSE1 \
     --destination /chemin/prive/graphite-stage
   ```
   La sortie ne comprend que les deux fichiers frontend.
3. Placer les deux fichiers approuvés dans un worktree de release privé, puis :
   ```bash
   python3 tools/compose_live_overlay.py \
     --source /chemin/prive/graphite-stage \
     --destination /chemin/release-source/live-overlay \
     --from-version v0.0.0 \
     --visual-only
   ```
4. Tester le worktree et exécuter le pipeline `tools/release_pipeline.py prepare` sur le build isolé. Signature Ed25519 **par l'identité de signature distincte**, publication de l'archive immuable et de l'index signé sur un vrai HTTPS.
5. Une fois la source de confiance provisionnée sur le RISE-1, la console permet alors **Rechercher**, **Installer** et le rollback en cas d'échec. Les releases futures pourront être installées depuis le Web sans reconnexion SSH pour chaque version.

## Gardes de non-régression

Le RISE-1, WireGuard `wg-cerato`, les IP OVH, le Dell `10.77.0.2`, NAT, firewall et les routes **ne sont pas modifiés par ce travail**. Les tests automatiques tournent sur GitHub pour la branche `feature/secure-accounts`, sans clé privée de signature ni déploiement réseau. Les tests CI ne prouvent pas l'installation finale : une vérification HTTPS + signature + sauvegarde/rollback en environnement isolé reste indispensable.

## Règle produit

Aucune mention « V2 / V3 / nouvelle génération » dans les intitulés de l'interface. Les fonctions livrées font partie de Cerato Network de manière native. La palette doit rester sobre et homogène sur toutes les pages (comptes, IPv4, tunnels, NAT, pare-feu, journaux, configuration et mises à jour).
