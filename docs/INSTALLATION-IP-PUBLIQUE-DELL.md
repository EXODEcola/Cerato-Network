# Installation contrôlée — Additional IPv4 54.37.165.151 vers Dell R530

**Préparation complète, non encore validée en production.** Les scripts utilisent
un timer de rollback systemd indépendant par serveur et doivent refuser tout état
inattendu. Ils n'utilisent pas OVHcloud API : attendre la confirmation définitive
de suppression de la MAC virtuelle et sa propagation.

Les scripts sont épinglés à ce commit de développement :
`0a7a4f43829d7659667310fffc6b6063f09a7466`.
Garder deux consoles SSH séparées, OVH `51.210.223.57` et Dell via Tailscale
`100.74.84.71`. Ne pas redémarrer pendant l'activation.

## Après un précédent rollback Dell réussi (1er novembre)

Le premier essai géré sur Dell s'est terminé par `status=restored`,
sans erreur, et le /32 n'est plus présent sur `wg-cerato`. OVH ne
possède pas de fichier de préparation et conserve la /32 sur sa WAN.

Le logiciel précédent conservait volontairement le dossier d'état
`/var/lib/cerato-network/routed-54-37-165-151`, ce qui
bloquait tout nouveau `prepare` même si le rollback était achevé.
La nouvelle commande `reset` vérifie que l'ancienne règle 1101,
le pare-feu temporaire, le /32 sur Dell et le watchdog sont absents ;
elle **archive** les sauvegardes d'origine sous root puis libère
l'emplacement pour la préparation suivante.

Sur Dell, avant toute nouvelle préparation, installer le
nouveau script révisé puis :

```bash
sudo /usr/local/sbin/cerato-routed-cutover reset --role peer
```

N'exécuter `reset` **ni sur OVH** (pas de migration préparée), ni
sur le Dell si son état n'est pas `restored`. Ce correctif n'active
ni l'IP ni un service. Il ne dispense pas d'attendre la
**suppression effective** de la MAC virtuelle chez OVHcloud.

## Installation du script sans dépendre de l'ancien dépôt Git local

Si `git show` répond « path does not exist » alors que le commit
existe sur GitHub, récupérer uniquement le script depuis l'URL
immuable du commit, avec HTTPS et arrêt immédiat en cas d'échec.
Cette opération **n'active pas le réseau** :

```bash
REV=0a7a4f43829d7659667310fffc6b6063f09a7466
curl --fail --location --show-error --silent \
  "https://raw.githubusercontent.com/EXODEcola/Cerato-Network/$REV/scripts/managed_routed_cutover.py" \
  --output /tmp/cerato-routed-cutover.py
python3 -m py_compile /tmp/cerato-routed-cutover.py
sudo install -o root -g root -m 0755 \
  /tmp/cerato-routed-cutover.py /usr/local/sbin/cerato-routed-cutover
```

Sur le Dell qui est déjà en état `restored` (rollback sans erreurs) :

```bash
sudo /usr/local/sbin/cerato-routed-cutover reset --role peer
```

La commande doit archiver le dossier `routed-54-37-165-151`.
Si le statut est autre que `reset_to_prepared_state`, ne pas
commencer les étapes d'activation.

## 1. Dell — préparer et activer temporairement l'adresse

```bash
set -euo pipefail
cd ~/Cerato-Network-preflight
git fetch origin feature/public-ip-path-preflight
REV=0a7a4f43829d7659667310fffc6b6063f09a7466
git cat-file -e "$REV^{commit}"
git show "$REV:scripts/managed_routed_cutover.py" | sudo tee /usr/local/sbin/cerato-routed-cutover >/dev/null
sudo chmod 755 /usr/local/sbin/cerato-routed-cutover
sudo /usr/local/sbin/cerato-routed-cutover prepare --role peer
sudo /usr/local/sbin/cerato-routed-cutover activate --role peer
```

Timer de retour arrière Dell : **45 minutes**. Le profil de firewall
autorise SSH TCP 22 sur la /32, puis bloque les autres ports non
explicitement publiés. Le LAN, Tailscale et l'IPv6 ne sont pas modifiés.

## Récupération d'une préparation orpheline sur OVH

Le 1er novembre 2026, le nouveau `prepare --role gateway` a refusé
`Préparation existante : statut/rollback avant nouvel essai`.
La vérification précédente avait confirmé l'absence de `state.json`
et l'Additional IPv4 encore sur `enp1s0f0`. Il s'agit donc
possiblement d'un dossier de préparation ancien ou interrompu, pas d'un
routage activé par le bloc qui a échoué.

Dans la version du script référencée ci-dessus, une commande
**`recover-orphan --role gateway`** a été ajoutée pour ce cas strict.
Elle refuse si `state.json` existe, si un watchdog existe ou fonctionne,
si les sauvegardes ne correspondent pas aux fichiers live, si
WireGuard route déjà la /32, ou si le contrôleur/DNAT d'origine diffère.
Elle archive le dossier mais **ne modifie pas le réseau**. Appeler
cette commande avant `prepare --role gateway`, uniquement si
une ancienne préparation sans état bloque l'opération.

Le Dell est actuellement activé en essai : le watchdog du Dell est
programmé à **2026-11-01T11:52:22Z (12:52:22 Paris)**. Si ce délai
est dépassé, le rollback aura restauré l'état initial : **ne pas
activer OVH vers un Dell qui ne possède plus la /32**.

## 2. OVH — convertir Cerato, WireGuard et la route

```bash
set -euo pipefail
cd ~/Cerato-Network
git fetch origin feature/public-ip-path-preflight
REV=0a7a4f43829d7659667310fffc6b6063f09a7466
git cat-file -e "$REV^{commit}"
SUPPORT="$(sudo mktemp -d /root/cerato-routed-support.XXXXXXXX)"
for f in live_routed_compat.py routed_nft_inject.py routed_firewall.py; do
  git show "$REV:network/$f" | sudo tee "$SUPPORT/$f" >/dev/null
done
git show "$REV:scripts/stage_live_routed_controller.py" | sudo tee "$SUPPORT/stage_live_routed_controller.py" >/dev/null
git show "$REV:scripts/managed_routed_cutover.py" | sudo tee /usr/local/sbin/cerato-routed-cutover >/dev/null
sudo chmod 755 /usr/local/sbin/cerato-routed-cutover
sudo /usr/local/sbin/cerato-routed-cutover prepare --role gateway --support-dir "$SUPPORT"
sudo /usr/local/sbin/cerato-routed-cutover activate --role gateway
```

Le contrôleur live ne peut être transformé que si son empreinte SHA256
est exactement celle déjà validée sur RISE-1. Le générateur nftables
subit une vérification syntaxique avant toute modification.
Les configurations Cerato sont sauvegardées, la publication NAT TCP8080
est convertie vers un routage /32, WireGuard est étendu et l'alias WAN
est retiré en dernier. Rollback OVH autonome : **25 minutes**.

## 3. Windows — preuve Internet automatique unique

```powershell
ssh -i "$env:USERPROFILE\.ssh\id_ed25519" -o IdentitiesOnly=yes -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o ConnectTimeout=12 ceratoadmin@54.37.165.151 'curl -4fsS --connect-timeout 8 --max-time 15 --interface 54.37.165.151 https://api.ipify.org | grep -Fx 54.37.165.151'
if ($LASTEXITCODE -ne 0) { throw "Échec du SSH public ou de la sortie IP ; ne pas confirmer la migration." }
```

Cette commande effectue, sans diagnostic interactif répété, les deux
vérifications indispensables : SSH depuis Internet et IPv4 source
de sortie Dell. Si elle échoue, **ne pas continuer**, et laisser les
timers restaurer ou lancer les commandes de rollback ci-dessous.

## 4. Rendre les configurations persistantes

Dans la session **Dell**, uniquement après succès Windows :

```bash
sudo /usr/local/sbin/cerato-routed-cutover persist --role peer
```

Puis dans la session **OVH** :

```bash
sudo /usr/local/sbin/cerato-routed-cutover persist --role gateway
```

Le script installe un service systemd de restauration au démarrage
sur chaque hôte et désarme ensuite le watchdog de cet hôte.
Ne pas redémarrer volontairement les serveurs avant une maintenance
où la restauration systemd pourra être observée.

## En cas d'échec

D'abord sur **OVH** :

```bash
sudo /usr/local/sbin/cerato-routed-cutover rollback --role gateway
```

Puis sur **Dell** :

```bash
sudo /usr/local/sbin/cerato-routed-cutover rollback --role peer
```

Une restauration échouée conserve le statut `rollback_failed`
et ne doit pas être masquée en interrompant les watchdogs.

## Portée précise de « IPv4 principale »

La /32 devient l'IPv4 publique du Dell pour SSH et les services qui
écoutent sur cette adresse ou sur `0.0.0.0` **si leurs ports sont
autorises dans le firewall**. La sortie Internet avec cette IP est
disponible aux processus qui la sélectionnent explicitement
(ex. `curl --interface 54.37.165.151`). **La route IPv4 par défaut
globale du Dell reste sur le LAN** afin de conserver Tailscale, DNS,
ses services et les sessions d'administration. Faire utiliser cette IP
en sortie par *tous* les processus nécessiterait une autre politique de
routage, non incluse dans ce déploiement.

**Statut :** tests CI synthétiques, aucun déploiement réel de cet
installateur exécuté par l'assistant. Les refus de prérequis sont
volontaires et doivent être investigués, jamais contournés.
