# Réparer l'interface Cerato Network après migration /32, sans toucher au réseau

## Incident confirmé

Le générateur `stage_live_routed_controller.py` utilisait
`ast.unparse(...)`, qui supprime les commentaires, notamment
`#!/usr/bin/env python3`. Le contrôleur routé compilait en
Python et avait été installé exécutable, mais le système le lançait
en shell et renvoyait `from: not found`, `import: not found`
dans l'interface Web.

L'adresse `54.37.165.151/32` avait été validée en SSH direct
depuis Windows et en sortie publique depuis Dell avant cette
réparation. **Il ne faut ni annuler la migration, ni restaurer
un ancien fichier de configuration réseau, ni relancer
`ceratoctl apply` sans diagnostic.**

## Hotfix conservateur à partir du commit validé

Sur OVH RISE-1 seulement, avec SSH par l'IPv4 de gestion
`51.210.223.57` :

```bash
set -euo pipefail
REV=INSERT_PINNED_REV
FILE="$(mktemp /tmp/cerato-shebang.XXXXXXXX.py)"
curl -fLsS --retry 3 \
  "https://raw.githubusercontent.com/EXODEcola/Cerato-Network/$REV/scripts/repair_live_ceratoctl_shebang.py" \
  -o "$FILE"
python3 -m py_compile "$FILE"
sudo python3 "$FILE" check
sudo python3 "$FILE" install
sudo /usr/local/sbin/ceratoctl status | python3 -m json.tool >/dev/null
sudo systemctl is-active cerato-network-web.service
rm -f "$FILE"
```

Le correctif :
- n'accepte que l'empreinte SHA256 **exacte** du contrôleur
  Python modifié connu (ou la version déjà corrigée) ;
- appelle d'abord le contrôleur en utilisant explicitement Python
  et vérifie que `status` retourne du JSON ;
- crée une sauvegarde root-only sous
  `/var/backups/cerato-network-inplace/ceratoctl-shebang/` ;
- préfixe une seule ligne `#!/usr/bin/env python3`, remplace
  atomiquement le fichier, puis vérifie l'exécution **directe** ;
- restaure les octets originaux en cas d'échec de validation.
- ne touche ni aux services, ni aux routes, ni aux fichiers WireGuard,
  ni à nftables, ni aux clés d'authentification, ni à la DB.

L'interface doit être rafraîchie après correction, sans redémarrer
le réseau ou le panneau Web. Si le correctif refuse une empreinte,
conserver le journal et ne jamais écraser manuellement le contrôleur
par une version de développement.

## Mises à jour signées depuis le panneau

Le moteur actuel `cerato-updatectl` est **distinct** de
`ceratoctl`. Il applique des releases signées Ed25519 et
compatibles avec **le panneau Web existant** : backend/server.py,
web/app.js, web/style.css. Il ne remplace pas automatiquement le
noyau réseau ni les agents Dell. Les nouveautés en dehors de
ce périmètre nécessitent encore leur propre distribution sécurisée.

Après réparation du contrôleur, vérification **lecture seule**
sur OVH :

```bash
sudo /usr/local/sbin/cerato-updatectl status
sudo /usr/local/sbin/cerato-updatectl check
sudo systemctl is-enabled cerato-network-web.service
sudo systemctl is-enabled cerato-routed-gateway.service
```

Les commandes `status` et `check` permettent de déterminer si
la clé publique de distribution, la source HTTPS, les canaux
stable/beta/dev et une release signée installable sont bien présents.
Si `status` refuse « Distribution ... non configurée », il faut
activer le canal de releases **avec une clé Ed25519 approuvée**, pas
forcer une mise à jour non signée.

Le script `scripts/finalize-ovh-web-updates.sh --check`
peut vérifier sans changement une installation ancienne, mais
nécessite les sources correspondantes sur le serveur OVH.
La mise à jour Web dans le panneau ne doit devenir « installable »
que lorsqu'une release compatible a été réellement publiée et
signée. Pas de promesse de MAJ automatique des agents ou des
fonctionnalités réseau encore absentes des releases.

## Dell Ubuntu 24.04 — source APT Ookla 404

Le dépôt packagecloud `ookla/speedtest-cli/ubuntu noble` renvoie
404. Ne pas réessayer l'ancien installateur, ne pas changer de
distribution vers jammy pour forcer la compatibilité. Désactiver
seulement cette source, puis utiliser le paquet fourni par Ubuntu :

```bash
if [ -f /etc/apt/sources.list.d/ookla_speedtest-cli.list ]; then
  sudo mv /etc/apt/sources.list.d/ookla_speedtest-cli.list \
    /etc/apt/sources.list.d/ookla_speedtest-cli.list.disabled
fi
sudo apt-get update
sudo apt-get install -y speedtest-cli
speedtest-cli --secure --source 192.168.129.92 --simple
speedtest-cli --secure --source 54.37.165.151 --simple
```

L'outil Python `speedtest-cli` n'est **pas** le binaire
d'Ookla et ses estimations peuvent différer de Speedtest officiel.
Comparer au même serveur lorsque possible et utiliser `iperf3`
sur le tunnel pour isoler les goulots d'étranglement.
