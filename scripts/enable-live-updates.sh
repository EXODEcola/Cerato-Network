#!/usr/bin/env bash
# Add a verified in-panel update center to the EXISTING RISE-1 Web UI on 8787.
# No second server. No WireGuard, routing, NAT, DHCP, Netplan or nftables writes.
# Exact configuration of the trusted signing key and release host is separate.
#
# First: sudo bash scripts/enable-live-updates.sh --check
# Then:  sudo bash scripts/enable-live-updates.sh --install
set -Eeuo pipefail
umask 077
MODE="${1:---check}"
[[ "$MODE" == "--check" || "$MODE" == "--install" ]] || {
  echo "Usage: --check | --install" >&2; exit 2;
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOME_DIR=/opt/cerato-network
ENGINE="$HOME_DIR/updater"
WEB_SERVICE=cerato-network-web.service
UPDATE_SERVICE=cerato-network-update.service
WEB_USER=ceratonet
BACKUP_ROOT=/var/backups/cerato-network-inplace/update-center
SUDOERS=/etc/sudoers.d/cerato-update-center
CTL=/usr/local/sbin/cerato-updatectl
[[ "$EUID" -eq 0 ]] || { echo "Lancer avec sudo, y compris --check." >&2; exit 1; }
for file in integrations/patch_live_update_center.py updates/live_controller.py updates/remote.py tools/build_release.py; do
  [[ -f "$ROOT/$file" ]] || { echo "Fichier manquant : $file" >&2; exit 1; }
done
for file in backend/server.py web/app.js web/style.css; do
  [[ -f "$HOME_DIR/$file" && ! -L "$HOME_DIR/$file" ]] ||
    { echo "Installation Web existante introuvable ou symbolique : $file" >&2; exit 1; }
done
systemctl is-active --quiet "$WEB_SERVICE" || {
  echo "Panneau principal inactif : installation refusée." >&2; exit 1;
}
[[ "$(systemctl show "$WEB_SERVICE" --property=User --value)" == "$WEB_USER" ]] || {
  echo "Compte du service Web inattendu; refus." >&2; exit 1;
}
curl -fsS --max-time 5 -o /dev/null http://127.0.0.1:8787/ || {
  echo "Le panneau 8787 ne répond pas." >&2; exit 1;
}
command -v openssl >/dev/null 2>&1 || { echo "OpenSSL requis." >&2; exit 1; }
command -v node >/dev/null 2>&1 || {
  echo "Node.js requis pour vérifier le JavaScript avant mise en production." >&2; exit 1;
}
command -v visudo >/dev/null 2>&1 || { echo "visudo requis." >&2; exit 1; }

TMP="$(mktemp -d -t cerato-web-update-check-XXXXXXXX)"
cleanup(){ rm -rf -- "$TMP"; }
trap cleanup EXIT
python3 "$ROOT/integrations/patch_live_update_center.py" \
  --source "$HOME_DIR" --destination "$TMP"
python3 -m py_compile "$TMP/backend/server.py"
node --check "$TMP/web/app.js"
# Verify existing service/network status WITHOUT revealing private keys.
STATUS_BEFORE="$(/usr/local/sbin/ceratoctl status)"
printf '%s' "$STATUS_BEFORE" | python3 -c 'import json,sys;s=json.load(sys.stdin);print("Peers:",list(s.get("peers",{})),"Pool:",s.get("pool",[]),"NAT:",len(s.get("mappings",[])))'
echo "Préflight de mise à jour Web : OK"
if [[ "$MODE" == "--check" ]]; then
  echo "Aucun service ou fichier système n'a été modifié."
  exit 0
fi

[[ ! -e "$CTL" && ! -L "$CTL" ]] || {
  echo "Contrôleur d'update déjà présent : refuser d'écraser une installation inconnue." >&2; exit 1;
}
[[ ! -e "/etc/systemd/system/$UPDATE_SERVICE" ]] || {
  echo "Service d'update déjà présent : installation initiale refusée." >&2; exit 1;
}

STAMP="$(date -u +%Y%m%dT%H%M%SZ)-$$"
BACKUP="$BACKUP_ROOT/$STAMP"
install -d -m 0700 "$BACKUP"
for file in backend/server.py web/app.js web/style.css; do
  mkdir -p "$BACKUP/$(dirname "$file")"
  cp -p "$HOME_DIR/$file" "$BACKUP/$file"
done

# Never copy private WireGuard keys or configuration into Web release space.
install -d -o root -g root -m 0755 "$ENGINE" "$ENGINE/tools" "$ENGINE/updates"
install -d -o root -g root -m 0700 /var/lib/cerato-network-updates
install -m 0644 "$ROOT/tools/build_release.py" "$ENGINE/tools/build_release.py"
install -m 0644 "$ROOT/updates/remote.py" "$ENGINE/updates/remote.py"
install -m 0755 "$ROOT/updates/live_controller.py" "$ENGINE/updates/live_controller.py"
ln -s "$ENGINE/updates/live_controller.py" "$CTL"

cat > "/etc/systemd/system/$UPDATE_SERVICE" <<'UNIT'
[Unit]
Description=Cerato Network - install approved signed Web release with rollback
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
User=root
ExecStart=/usr/local/sbin/cerato-updatectl apply
TimeoutStartSec=120
UMask=0077
ProtectSystem=strict
ReadWritePaths=/opt/cerato-network/backend /opt/cerato-network/web /var/lib/cerato-network-updates
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
UNIT

cat > "$SUDOERS" <<'SUDO'
Defaults:ceratonet env_reset
ceratonet ALL=(root) NOPASSWD: /usr/local/sbin/cerato-updatectl status, /usr/local/sbin/cerato-updatectl check
ceratonet ALL=(root) NOPASSWD: /usr/bin/systemctl start --no-block cerato-network-update.service
SUDO
chmod 0440 "$SUDOERS"
visudo -cf "$SUDOERS" >/dev/null

rollback(){
  echo "ÉCHEC : restauration du panneau Web précédent." >&2
  for file in backend/server.py web/app.js; do
    cp -p "$BACKUP/$file" "$HOME_DIR/$file" || true
  done
  systemctl restart "$WEB_SERVICE" || true
}
trap rollback ERR

systemctl daemon-reload
install -m 0644 "$TMP/backend/server.py" "$HOME_DIR/backend/server.py"
install -m 0644 "$TMP/web/app.js" "$HOME_DIR/web/app.js"
systemctl restart "$WEB_SERVICE"
sleep 1
systemctl is-active --quiet "$WEB_SERVICE"
curl -fsS --max-time 8 -o /dev/null http://127.0.0.1:8787/
STATUS_AFTER="$(/usr/local/sbin/ceratoctl status)"
[[ "$STATUS_BEFORE" == "$STATUS_AFTER" ]] || {
  echo "État de configuration réseau modifié pendant le déploiement." >&2; exit 1;
}
trap - ERR
echo "Mises à jour Web intégrées au panneau existant 8787."
echo "Distribution : non configurée tant que le fournisseur HTTPS et la clé publique ne sont pas approuvés."
echo "Aucune release générique ne peut remplacer la console RISE-1."
echo "Sauvegarde locale : $BACKUP"
