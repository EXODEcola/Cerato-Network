#!/usr/bin/env bash
# Patch only the existing RISE-1 web/app.js to refresh signed update status.
# Preserves network/backend, saves rollback, refuses unknown UI structures.
set -Eeuo pipefail
umask 077
MODE="${1:---check}"
[[ "$MODE" == "--check" || "$MODE" == "--install" ]] || {
  echo "Usage : --check | --install" >&2; exit 2;
}
[[ "$EUID" -eq 0 ]] || { echo "sudo requis sur RISE-1." >&2; exit 2; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIVE=/opt/cerato-network
TARGET="$LIVE/web/app.js"
SERVICE=cerato-network-web.service
UPDATER=cerato-network-update.service
BACKUPS=/var/backups/cerato-network-inplace/update-ui-refresh
PATCHER="$ROOT/integrations/repair_live_update_refresh.py"

[[ -f "$TARGET" && ! -L "$TARGET" && "$(stat -c %u "$TARGET")" == 0 ]] || {
  echo "Frontend root attendu absent ou symbolique." >&2; exit 2;
}
[[ -f "$PATCHER" && ! -L "$PATCHER" ]] || {
  echo "Source du correctif inconnue." >&2; exit 2;
}
command -v node >/dev/null 2>&1 || { echo "Node.js requis." >&2; exit 2; }
systemctl is-active --quiet "$SERVICE" || {
  echo "Service Web arrêté ; correctif refusé." >&2; exit 2;
}
if systemctl is-active --quiet "$UPDATER"; then
  echo "Une installation Web est déjà en cours ; correctif refusé." >&2; exit 2;
fi
curl -fsS --max-time 6 -o /dev/null http://127.0.0.1:8787/ || {
  echo "Panneau HTTP local inaccessible." >&2; exit 2;
}
network_hash(){
  for path in /etc/cerato-network/config.json /etc/wireguard/wg-cerato.conf; do
    [[ -f "$path" && ! -L "$path" ]] || return 2
  done
  sha256sum /etc/cerato-network/config.json /etc/wireguard/wg-cerato.conf |
    sha256sum | cut -d' ' -f1
}
BEFORE="$(network_hash)" || { echo "Configuration réseau inattendue." >&2; exit 2; }
SCRATCH="$(mktemp -d -t cerato-ui-refresh-XXXXXXXX)"
cleanup(){ rm -rf -- "$SCRATCH"; }
trap cleanup EXIT
python3 "$PATCHER" --source "$TARGET" --destination "$SCRATCH/app.js"
node --check "$SCRATCH/app.js"
if [[ "$MODE" == "--check" ]]; then
  echo "Précontrôle OK : rafraîchissement des mises à jour prêt, aucune modification."
  exit 0
fi
install -d -o root -g root -m 0700 "$BACKUPS"
BACKUP="$BACKUPS/$(date -u +%Y%m%dT%H%M%SZ)-$$.js"
cp -p -- "$TARGET" "$BACKUP"
CHANGED=0
rollback(){
  code=$?
  trap - ERR
  if [[ "$CHANGED" -eq 1 ]]; then
    echo "Restauration de l'ancien frontend." >&2
    cp -p -- "$BACKUP" "$TARGET" || true
    systemctl restart "$SERVICE" || true
  fi
  exit "$code"
}
trap rollback ERR
CHANGED=1
install -o root -g root -m 0644 "$SCRATCH/app.js" "$TARGET"
systemctl restart "$SERVICE"
for n in 1 2 3 4 5 6 7 8 9 10; do
  if systemctl is-active --quiet "$SERVICE" &&
     curl -fsS --max-time 3 -o /dev/null http://127.0.0.1:8787/; then
    break
  fi
  sleep 1
done
systemctl is-active --quiet "$SERVICE"
curl -fsS --max-time 6 -o /dev/null http://127.0.0.1:8787/
node --check "$TARGET"
[[ "$(network_hash)" == "$BEFORE" ]] || {
  echo "Empreinte réseau inattendue après la mise à jour UI." >&2; false;
}
CHANGED=0
trap - ERR
echo "Rafraîchissement du centre de mises à jour installé ; réseau inchangé."
echo "Sauvegarde : $BACKUP"
echo "Actualiser le navigateur avec Ctrl+Maj+R, puis ouvrir Mises à jour."
