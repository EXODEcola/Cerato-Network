# Mise à jour sur le RISE-1 existant — sans toucher au réseau fonctionnel

## Objectif immédiat

**Aucune nouvelle VM n'est nécessaire.** Le serveur RISE-1 reste la passerelle réelle et conserve le fonctionnement WireGuard, UDP, IP supplémentaires, NAT, nftables et le panneau opérationnel sur le port **127.0.0.1:8787**.

Le déploiement de transition installe **une seconde interface sur le même serveur** :

- **8787** : panneau Cerato Network existant, tous les réglages réseau fonctionnels conservés ;
- **8788** : nouveau panneau avec création du propriétaire, connexion e-mail/mot de passe, TOTP et comptes admin/viewer, permettant de visualiser le statut WireGuard réel ;
- les deux services utilisent des comptes Unix et des bases de données distincts ;
- le nouveau compte de service n'a **pas** le droit de modifier le tunnel, les IP, le NAT ou le firewall ; les seules permissions sudo sont `ceratoctl status`, `wg show wg-cerato latest-handshakes` et `wg show wg-cerato transfer` ;
- le nouveau backend ne peut pas voir la clé privée via `wg show dump` ;
- Nginx, le pare-feu OVH et le port UDP WireGuard ne sont pas modifiés par l'installateur.

**Cette étape ne remplace pas encore le panneau sur 8787**, car les opérations avancées de gestion réseau ne sont pas encore raccordées au nouveau backend. Elle constitue une vraie installation sur l'OVH permettant de valider le système de comptes avec les états réels, tout en préservant les fonctions existantes.

## 1. Commandes sur le serveur OVH RISE-1 (pas la VM de build)

Se connecter en SSH avec un compte disposant de sudo. La branche est destinée aux essais, pas à une release stable :

~~~bash
cd ~/Cerato-Network
git switch feature/secure-accounts
git pull --ff-only origin feature/secure-accounts
bash scripts/ovh-shadow.sh --check
~~~

Le contrôle vérifie que `cerato-network-web.service` est actif et que le panneau existant répond. S'il échoue, **ne pas utiliser --install** ; vérifier la configuration en place. Il ne modifie aucun service.

Ensuite seulement :

~~~bash
sudo bash scripts/ovh-shadow.sh --install
sudo bash scripts/ovh-shadow.sh --status
~~~

L'installation crée un compte système indépendant `ceratoview`, une base de comptes protégée sous `/var/lib/cerato-network-shadow/`, et le service `cerato-network-shadow.service`. Elle sauvegarde le backend, le frontend et le dossier `/etc/cerato-network` sous `/root/cerato-network-shadow-backups` avec des permissions privées. **Ces sauvegardes peuvent contenir des secrets** et ne doivent jamais être copiées sur GitHub.

Le service de préproduction écoute uniquement sur **127.0.0.1:8788**, sans publication Internet ni nouvelle règle pare-feu.

## 2. Créer le propriétaire principal sur l'OVH

Sur la session SSH RISE-1, exécuter :

~~~bash
sudo -u ceratoview \
  /opt/cerato-network-shadow/current/venv/bin/python \
  /opt/cerato-network-shadow/current/security/cli.py \
  --database /var/lib/cerato-network-shadow/accounts.sqlite3 bootstrap-token
~~~

Un code valable 15 minutes, utilisable une seule fois, s'affiche sur le terminal SSH. Ce n'est **pas** un mot de passe prédéfini. Ne pas le publier dans les logs, le chat ou GitHub.

## 3. Accès au nouveau panneau depuis Windows

Dans **PowerShell sur Windows**, ouvrir un tunnel vers le serveur OVH :

~~~powershell
ssh -N -L 8788:127.0.0.1:8788 ubuntu@ADRESSE_SSH_DU_RISE_1
~~~

Adapter le compte SSH, le port et l'adresse à ceux qui fonctionnent déjà sur ton serveur. Ouvrir dans le navigateur **http://127.0.0.1:8788**.

La session HTTP passe **dans le tunnel SSH chiffré**. Ce mode HTTP est temporaire et réservé à la préproduction sur le serveur OVH. Il ne doit pas être rendu publiquement accessible ; pour la production, le panneau devra passer derrière Nginx HTTPS avec cookies Secure et migration validée.

L'interface demande le code initial, l'adresse e-mail et le mot de passe choisis par le propriétaire, puis configure obligatoirement le TOTP et affiche les codes de récupération une seule fois.

## 4. Tests réellement possibles sur le même OVH

- Connexion initiale owner, changement d'e-mail/mot de passe, TOTP et codes de secours.
- Création d'administrateurs supplémentaires et d'utilisateurs en lecture seule.
- Interdiction pour un co-admin de modifier le propriétaire principal.
- **Lecture du véritable statut WireGuard** : dernières activités et compteurs des pairs, sans lire la clé privée.
- Vérification que le panneau existant 8787 et ses opérations UDP/NAT fonctionnent encore.
- Vérification du catalogue de mises à jour ; installation réseau désactivée sur ce panneau de transition.

**Test express non destructif :**

~~~bash
sudo systemctl is-active cerato-network-web.service
sudo systemctl is-active cerato-network-shadow.service
curl -fsS http://127.0.0.1:8787/ -o /dev/null
curl -fsS http://127.0.0.1:8788/api/auth/setup-status
sudo wg show wg-cerato latest-handshakes
~~~

Ces commandes sont de lecture seule. Ne pas coller les secrets, clés ou configurations complètes dans un ticket public.

## 5. Corriger ou mettre à jour le panneau de transition (provisoire)

Depuis le checkout déjà présent sur l'OVH :

~~~bash
cd ~/Cerato-Network
git pull --ff-only origin feature/secure-accounts
sudo bash scripts/ovh-shadow.sh --update
~~~

La mise à jour place les nouveaux fichiers dans un **répertoire versionné**, change un lien atomique, redémarre **uniquement** `cerato-network-shadow.service`, vérifie son endpoint de santé et restaure automatiquement la version précédente si le test échoue. Les comptes de l'interface shadow restent conservés.

**Il s'agit encore d'une procédure de transition depuis les sources, pas du futur moteur de releases signées piloté par le bouton Web.** Le client signé, le moteur de sauvegarde/rollback et le centre Web sont en cours d'intégration : on ne doit pas présenter la mise à jour automatique comme fonctionnelle avant ce raccordement.

## 6. Revenir en arrière immédiatement

Pour désactiver le nouveau panneau sans modifier le principal :

~~~bash
sudo bash scripts/ovh-shadow.sh --remove
~~~

Cela arrête et retire **uniquement** le service shadow et son autorisation de consultation. Les sauvegardes, comptes et versions du shadow sont conservés volontairement pour une reprise éventuelle. Le panneau original 8787, WireGuard et les règles NAT restent inchangés.

## 7. Avant de remplacer réellement le panneau principal

Le jour du basculement sur le port 8787, il faudra impérativement :
1. connecter au nouveau backend les opérations validées `ceratoctl` avec permissions owner/admin et validations strictes côté serveur ;
2. restaurer les sections de gestion des IP, NAT, pare-feu, tunnels, agents et diagnostic dans la nouvelle interface ;
3. intégrer un updater Web à releases signées, avec santé réelle du service, snapshot et rollback watchdog ;
4. prouver par test que toutes les fonctions du panneau ancien restent accessibles ;
5. sauvegarder les comptes et configurations, puis remplacer le service principal pendant une fenêtre contrôlée.

**Ne pas écraser le backend 8787 avec `gateway/http_api.py` aujourd'hui : ce code n'est pas encore un remplaçant fonctionnel complet.**
