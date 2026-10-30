# RISE-1 : vraie mise à niveau du panneau unique — Additional IPv4 automatique

**Cette procédure concerne le panneau principal EXISTANT sur 127.0.0.1:8787.**
Elle ne déploie pas de second panneau et n'utilise pas le shadow 8788.
Le RISE-1 conserve le moteur ceratoctl, ses pairs WireGuard, son pool d'IP,
les règles NAT, le pare-feu OVH, Nginx et les clés existantes.

**Statut : premier lot de compatibilité IPv4, non encore testé sur le RISE-1.**
La migration de l'authentification propriétaire/admin/user et l'updater Web
sont dans d'autres composants de la branche de développement, mais ne sont
pas activés par cette mise à niveau ciblée. Il est impératif de ne pas
annoncer ce lot comme une release stable complète.

## Fonctionnalité implantée

Dans l'interface actuelle, **Adresses IPv4 → Importer une IP** :

- Saisir une Additional IPv4 déjà attribuée à la machine dans OVHcloud.
- Mode « local-nat » : l'assistant détecte la WAN, vérifie la route principale,
  interdit l'IPv4 de gestion, fait un aperçu, demande confirmation et configure
  l'adresse /32 avec iproute2 sans recharger Netplan ou l'interface réseau.
- Cerato inscrit cette IP dans son pool existant, ce qui permet la publication
  de ports via les **endpoints NAT déjà opérationnels**.
- La liste des adresses gérées est persistée dans
  `/etc/cerato-network/additional-ip-managed.json` et le service
  `cerato-network-additional-ip.service` réapplique uniquement les /32
  manquantes après le démarrage du réseau.
- La migration adopte automatiquement les IPv4 **déjà dans le pool ET présentes
  sur la WAN**. Celles absentes restent intactes.
- Les adresses en place avant la gestion de Cerato restent marquées comme
  « preexisting » : leur retrait de la gestion n'enlève pas l'adresse active.
- Le mode « routed-wg » est visible pour la conception et refusé côté backend
  tant qu'un agent compatible, la configuration Linux, le retour du trafic,
  le routage policy-based, les permissions nftables et un rollback distant
  n'ont pas été vérifiés. **Il ne doit pas dérouter une IP déjà en service.**

### Ce que Cerato peut et ne peut pas prouver actuellement

La passerelle ne peut pas déduire de la sortie `ip addr` qu'une IPv4 a été
achetée ou attachée au bon service dans OVHcloud. L'administrateur doit
**préalablement vérifier son attribution dans OVHcloud**. Une intégration
OVH API sécurisée (identifiants conservés localement, droits de lecture)
est prévue avant d'annoncer une vérification propriétaire automatique.
Aucun token OVH n'est intégré au dépôt open source.

L'adresse présente uniquement via `ip address add` n'est pas persistante.
Pour éviter les risques sur une passerelle distante, le mécanisme retenu
utilise un service systemd Cerato de restauration d'adresses plutôt qu'un
`netplan apply` immédiat, qui pourrait réinitialiser l'interface SSH.

## 1. Tester le code sur CERATO-BUILD-01 (aucune installation)

~~~bash
cd ~/Cerato-Network
bash scripts/update-dev.sh
~~~

Attendre des résultats PASS pour `tests/test_ovh_additional_ip.py` et
`tests/test_patch_existing_gateway.py`. Ces tests **ne remplacent pas le
préflight sur le RISE-1**.

## 2. Préflight sur le vrai serveur RISE-1 (lecture seule)

Depuis SSH, avec la console OVH de secours accessible :

~~~bash
cd ~/Cerato-Network
git switch feature/secure-accounts
git pull --ff-only origin feature/secure-accounts
sudo bash scripts/upgrade-live-in-place.sh --check
~~~

Le préflight lit et teste une copie de
`/opt/cerato-network/backend/server.py` et
`/opt/cerato-network/web/app.js` avant de modifier quoi que ce soit.
**Si les ancres du panneau actuel diffèrent, il REFUSE la mise à niveau.**
Ne pas forcer l'installation, ne pas remplacer directement le backend par le
serveur de développement `gateway/http_api.py`.

Il vérifie que le panneau principal est actif, que son port 8787 répond et
que le fichier WireGuard existant est présent.

## 3. Installer sur le panneau existant

**Seulement après un préflight OK, et lorsque l'accès console de secours est prêt :**

~~~bash
sudo bash scripts/upgrade-live-in-place.sh --apply
~~~

L'installateur :
1. sauvegarde le backend/frontend et une copie privée des paramètres réseau,
   y compris WireGuard (attention : cette archive peut contenir des secrets) ;
2. installe un petit helper root dont les droits sudo Web sont limités à
   `preview` et `import-local` ;
3. adopte les Additional IPv4 actuellement présentes dans le pool et la WAN ;
4. installe le service systemd de restauration d'IP, **sans le démarrer ni
   recharger Netplan, nftables ou WireGuard immédiatement** ;
5. remplace **uniquement** les deux fichiers du panneau existant, après
   compilation de contrôle ;
6. redémarre **uniquement** `cerato-network-web.service` et vérifie la
   disponibilité de `127.0.0.1:8787`.

Les sessions de l'ancien mot de passe en mémoire peuvent expirer lors du
redémarrage Web ; il faudra se reconnecter. Les comptes d'authentification
avancée restent à migrer dans une release distincte.

Le helper refusera les IP privées, la principale, les interfaces WAN
incohérentes et les adresses impossibles à valider. Les règles NAT existantes
restent enregistrées ; quand une nouvelle IPv4 est ajoutée au pool, le
moteur historique peut recharger sa **table nftables Cerato uniquement**,
donc une brève interruption de cette table est possible. Pour une IP
**déjà présente dans le pool**, aucune réapplication du NAT n'est nécessaire.

## 4. Vérifier après la mise à niveau

~~~bash
sudo systemctl is-active cerato-network-web.service
sudo systemctl is-enabled cerato-network-additional-ip.service
curl -fsS http://127.0.0.1:8787/ -o /dev/null
sudo /usr/local/sbin/cerato-ipctl status
sudo wg show wg-cerato latest-handshakes
sudo /usr/local/sbin/ceratoctl status
~~~

Le dernier appel contient les **clés publiques** et données réseau, pas la
clé privée de la gateway. Ne pas publier un dump WireGuard complet ou
des fichiers de configuration sensibles.

L'IP achetée `54.37.165.151` peut être déjà dans le pool actuel ;
si elle est toujours configurée sur la WAN, la migration devra automatiquement
l'inscrire dans le fichier des adresses persistantes, sans recréer l'alias.
Vérifier cet état dans la sortie `cerato-ipctl status`.

Ne tester la persistance après redémarrage **qu'avec une sauvegarde hôte, un
accès console de secours et une fenêtre de maintenance** ; un reboot n'est
pas nécessaire pour réaliser l'installation.

## 5. Retour arrière applicatif

~~~bash
sudo bash scripts/upgrade-live-in-place.sh --rollback
~~~

La commande restaure l'ancien backend/frontend et le relance sur 8787.
Elle **ne supprime aucune adresse ou règle réseau**, et conserve le
helper de persistance si des IP ont été gérées depuis la mise à jour.
Les sauvegardes sont sous
`/var/backups/cerato-network-inplace/`, accessibles à root seulement.

## Prochaines étapes pour la VRAIE release principale

Ce lot commence la mise à niveau unique, mais n'active pas encore les
fonctions suivantes :

- migration sans coupure de l'ancienne authentification par mot de passe
  vers `owner/admin/user` avec e-mail, Argon2id et 2FA ;
- distribution/signature des releases depuis le VPS de build et mise à jour
  **depuis la page Web** sans commande Git sur chaque panneau ;
- routage direct de l'Additional IPv4 vers un agent Dell **Ubuntu 24.04**
  (AllowedIPs côté WireGuard, IPv4 /32 sur Windows, routes aller/retour,
  anti-spoofing, forwarding, nftables, tests end-to-end et rollback) ;
- complétude des actions du pare-feu, gestion des agents et état des updates.

On ne doit donc pas appeler la branche actuelle « version finale ».
