# Centre de mises à jour intégré au panneau Cerato Network existant (RISE-1)

## Objectif

**Un seul panneau sur 127.0.0.1:8787**, conservation du contrôleur `ceratoctl`, de WireGuard, de toutes les IP, des règles NAT, du pare-feu, des sessions et de la configuration du Dell. Les nouvelles releases sont préparées et signées sur l'infrastructure de build indépendante, puis installées depuis l'interface Web. **Aucune compilation ni compression par GitHub Actions.**

**État au 30 octobre 2026 :** le code de la rubrique Web, de la vérification et du moteur de mise à jour est ajouté à la branche `feature/secure-accounts`. Ce lot n'a PAS encore passé les tests sur CERATO-BUILD-01 ou été installé sur le RISE-1. Aucune source officielle HTTPS signée n'est déployée aujourd'hui.

## 1. Fonctionnement prévu côté panneau

Nouvelle rubrique **Système → Mises à jour** :

- Version installée, version proposée, canal stable/bêta.
- Bouton **Rechercher une mise à jour** : requête serveur vers une source HTTPS préconfigurée, index Ed25519 signé, manifeste Ed25519 signé, contrôle SHA-256, téléchargement dans le cache privé de la passerelle.
- Bouton **Installer et vérifier** : uniquement lorsque le moteur confirme que l'archive signée est **spécifiquement compatible avec le panneau Cerato Network RISE-1 actuel**. La requête Web lance un service systemd séparé, qui peut survivre au redémarrage du Web.
- Sauvegarde root-only des anciens fichiers Web, vérification du Python et du JavaScript, redémarrage du seul service `cerato-network-web.service`, contrôle HTTP et vérification que le statut `ceratoctl` ne change pas.
- Si un contrôle échoue, restauration de l'ancien backend et frontend, puis tentative de redémarrage du service existant.
- Historique des mises à jour.

Le Web ne peut ni changer l'URL de la source, ni fournir une nouvelle clé publique, ni choisir un chemin arbitraire ou une commande à exécuter. Les permissions sudo sont limitées à `cerato-updatectl status`, `cerato-updatectl check` et `systemctl start --no-block cerato-network-update.service`.

## 2. Pourquoi on ne peut pas installer directement l'archive GitHub actuelle

La branche contient un **nouveau backend de développement** (`gateway/http_api.py`) dont les API réseau ne sont pas encore équivalentes à la console historique `backend/server.py` du RISE-1. Installer le ZIP générique sur le service 8787 supprimerait des fonctionnalités de NAT/IPv4/WireGuard.

Le moteur exige donc l'archive signée contenant exactement :

~~~text
cerato-network/
  live-overlay/
    compat.json
    backend/server.py
    web/app.js
    web/style.css
~~~

`compat.json` doit inclure `schema=cerato-network-legacy-web-overlay-v1`, `target=cerato-network-web-8787` et `from_versions` indiquant la version locale autorisée, initialement `v0.0.0` pour l'installation historique non numérotée. Les autres fichiers du ZIP ne seront pas exécutés par cet updater. **La signature seule ne suffit pas** : la compatibilité est obligatoire.

Pour générer l'overlay à partir d'un dossier de sources Web approuvées, sur CERATO-BUILD-01 :

~~~bash
python3 tools/compose_live_overlay.py \
  --source /chemin/source-live-verifiee \
  --destination /chemin/worktree-de-release/live-overlay \
  --from-version v0.0.0
~~~

Le worktree de release doit contenir LICENSE et README.md. Après validation du code, tester et préparer le bundle avec `tools/release_pipeline.py prepare`, puis le signer séparément avec la clé Ed25519 de release, sous une identité de signature distincte. Ne jamais signer automatiquement une PR publique.

## 3. Vérifier sur CERATO-BUILD-01 avant la production

~~~bash
cd ~/Cerato-Network
bash scripts/update-dev.sh
~~~

La nouvelle suite `tests/test_live_update_center.py` valide les endpoints, la présence des contrôles CSRF, la navigation et l'interdiction d'installer une archive source générique. **Attendre des PASS**, ne pas considérer les 64 tests précédents comme une validation de cette fonctionnalité.

## 4. Installer seulement le nouveau centre de mises à jour sur le RISE-1

Sur l'OVH, en conservant un accès console de secours :

~~~bash
cd ~/Cerato-Network
git switch feature/secure-accounts
git pull --ff-only origin feature/secure-accounts
sudo bash scripts/enable-live-updates.sh --check
~~~

**Si le contrôle de compatibilité retourne OK**, installer :

~~~bash
sudo bash scripts/enable-live-updates.sh --install
sudo systemctl is-active cerato-network-web.service
curl -fsS http://127.0.0.1:8787/ -o /dev/null
~~~

Puis Ctrl+F5 dans l'interface existante : **Système → Mises à jour**.

L'installation ajoute le nouveau service `cerato-network-update.service`, mais ne le déclenche pas et ne crée aucune règle réseau. Elle sauvegarde les fichiers Web existants sous `/var/backups/cerato-network-inplace/update-center/`, sans toucher à la configuration WireGuard. Les sessions administrateur du Web peuvent expirer suite au redémarrage de ce service.

**Au premier lancement, la page affichera “Distribution non configurée”** : c'est normal, puisque la source HTTPS de release et la clé publique officielle ne sont pas encore déployées. Le bouton Installer est désactivé. Cela ne prouve pas que la mise à jour distante complète fonctionne.

### Compatibilité avec le panneau Additional IPv4 déjà installé

Le premier essai du 30 octobre 2026 a échoué pendant le préflight `patch_live_update_center.py` :

~~~text
error: Structure frontend actuelle inconnue
~~~

Le backend actuel et son service principal `cerato-network-web.service` sont restés actifs. Le patch a été corrigé pour ne plus dépendre de l'ancienne déclaration exacte des variables JavaScript : il ajoute son état près du point d'entrée `render()`, dont l'unicité est contrôlée. Un nouveau test couvre le frontend déjà modifié par l'import IPv4.

La commande `--chec` était une faute de frappe : l'option correcte est `--check`.

Après récupération du correctif, exécuter **d'abord** :

~~~bash
cd ~/Cerato-Network
git pull --ff-only origin feature/secure-accounts
sudo bash scripts/enable-live-updates.sh --check
~~~

Le mode `--check` ne modifie pas le service. Un second échec a signalé `Table des pages incompatible` : la table des pages avait elle aussi changé. **Ce contrôle a été retiré** et la page Mises à jour est maintenant branchée sur le point d'entrée `render()` en préservant entièrement la table de pages existante. Les clics sont gérés par délégation, sans réécriture de la navigation historique.

Si un autre élément est incompatible, ne pas passer à `--install` ; relever le message exact et corriger les ancres avant déploiement. Les tests de CERATO-BUILD-01 sont une étape obligatoire préalable à l'installation.

## 5. Configuration de la confiance de signature : opération unique

Après avoir déployé un **vrai serveur HTTPS de releases** et créé une paire de signature Ed25519 sous un compte isolé :

1. Vérifier la clé publique officielle et son empreinte SHA-256 DER **par un canal indépendant** du serveur de distribution.
2. Copier seulement la clé **publique** sur le RISE-1 dans un chemin privé/contrôlé par root.
3. Provisionner une seule fois la source HTTPS et l'empreinte approuvée depuis la console SSH administrative :

~~~bash
sudo python3 tools/configure_live_release_source.py \
  --url https://RELEASES.EXEMPLE.TLD/cerato \
  --public-key /chemin/controle/release.pub \
  --fingerprint EMPREINTE_SHA256_DER_VERIFIEE \
  --channel beta
~~~

Ne pas exécuter avec les valeurs d'exemple. **Il n'existe pas encore de domaine officiel configuré pour nos releases dans ce dépôt.** La clé privée de signature ne doit jamais être copiée sur l'OVH. Une fois cette configuration établie, les vérifications et installations compatibles pourront s'effectuer depuis le panneau sans SSH pour chaque nouvelle version.

Changer la clé publique ou l'URL officielle nécessite une procédure de rotation hors bande, pas une action libre depuis le navigateur.

## 6. Limitations avant une version stable

- Le gestionnaire actuel vérifie les signatures et la compatibilité, mais les tests d'installation Web E2E sur le RISE-1 restent à réaliser.
- Une coupure électrique pendant l'écriture de plusieurs fichiers Web ne bénéficie pas encore d'un watchdog post-redémarrage système indépendant ; **ne pas déclarer le système de rollback résilient aux crashs tant qu'il n'est pas testé**.
- La migration vers la nouvelle interface et vers l'authentification owner/admin/user, Argon2id et 2FA nécessite un **overlay de migration dédié** ; ce lot ne remplace pas encore l'ancienne authentification. Les futurs overlays pourront apporter ces fonctionnalités progressivement.
- Le système de mise à jour des agents Dell/Ubuntu 24.04 et l'assignation automatique d'IP routée ne sont pas encore opérationnels.
- Le contrôle de santé Web et la comparaison des configurations réseau ne remplacent pas des tests end-to-end NAT/UDP.

## 7. Publier un port vers le Dell R530

Dans **NAT & publications → Publier un port** :
- IPv4 publique : `54.37.165.151`.
- Serveur cible : `dell-r530` (tunnel `10.77.0.2`).
- Protocole : `tcp` pour un service TCP, ou `udp` pour un service UDP.
- Port externe : port visible depuis Internet, par exemple `8080`.
- Port sur le serveur : port réellement écouté par l'application sur le Dell, par exemple `8080`.

La passerelle crée une règle de redirection ; il faut également que le service fonctionne et que le pare-feu du Dell accepte l'entrée. Pour une application utilisant TCP et UDP, publier deux règles distinctes. Tester depuis un accès externe et vérifier le retour du trafic sur WireGuard. **L'envoi d'un paquet ne prouve pas la réception ni l'accès à l'application.**

La commande `cerato-network-additional-ip.service` étant un `Type=oneshot`, `enabled` et `inactive (dead)` avant sa première exécution n'est pas forcément un problème ; la persistance réelle doit être vérifiée lors d'une fenêtre de maintenance avec accès console de secours.
