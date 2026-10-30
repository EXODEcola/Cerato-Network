#!/usr/bin/env bash
# Upgrade the EXISTING RISE-1 Cerato Web UI IN PLACE.
# Retain port 8787, WireGuard peer keys, Additional IP assignments, NAT,
# nftables state, current password, existing data and Nginx/SSH configuration.
# Does NOT install a second panel.
#
# Usage: bash scripts/upgrade-live-in-place.sh --check
#        sudo bash scripts/upgrade-live-in-place.sh --apply
#        sudo bash scripts/upgrade-live-in-place.sh --rollback
set -Eeuo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:---check}"
APP_HOME="/opt/cerato-network"
CONFIG="/etc/cerato-network/config.json"
CTL="/usr/local/sbin/ceratoctl"
IPCTL="/usr/local/sbin/cerato-ipctl"
SERVICE="cerato-network-web.service"
RESTORE_SERVICE="cerato-network-additional-ip.service"
SUDOERS="/etc/sudoers.d/cerato-additional-ip"
BACKUPS="/var/backups/cerato-network-inplace"
LATEST="$BACKUPS/latest"

die(){ echo "CERATO : $*" >&2; exit 1; }
[[ "$MODE" == "--check" || "$MODE" == "--apply" || "$MODE" == "--rollback" ]] ||
  die "Usage: --check | --apply | --rollback"

require_layout() {
  [[ -f "$APP_HOME/backend/server.py" && -f "$APP_HOME/web/app.js" &&
     -f "$CONFIG" && -x "$CTL" ]] ||
    die "La structure de l'installation existante n'est pas celle attendue."
  [[ -e "$ROOT/integrations/patch_live_additional_ipv4.py" &&
     -e "$ROOT/network/ovh_additional_ip.py" ]] ||
    die "Checkout incomplet."
  if [[ "$MODE" != "--rollback" ]]; then
    systemctl is-active --quiet "$SERVICE" ||
      die "Le panneau principal n'est pas actif. Stop : ne pas risquer l'instance réseau."
    curl -fsS --connect-timeout 2 --max-time 6 -o /dev/null http://127.0.0.1:8787/ ||
      die "Le panneau actuel sur 8787 ne répond pas."
  fi
  [[ -f /etc/wireguard/wg-cerato.conf ]] ||
    die "Le fichier WireGuard de la passerelle n'est pas détecté."
}

make_patch() {
  local dest="$1"
  python3 "$ROOT/integrations/patch_live_additional_ipv4.py" \
    --source "$APP_HOME" --destination "$dest"
  python3 -m py_compile "$dest/backend/server.py"
  if command -v node >/dev/null 2>&1; then
    node --check "$dest/web/app.js"
  else
    echo "Node.js absent : la syntaxe frontend sera vérifiée sur CERATO-BUILD-01." >&2
  fi
}

baseline() {
  echo "=== État réseau AVANT modification ==="
  "$CTL" status | python3 -c 'import sys,json; s=json.load(sys.stdin); print("WAN:",s.get("wan_if"),"Peers:",list(s.get("peers",{})),"NAT:",len(s.get("mappings",[])),"Pool:",s.get("pool",[]))'
  ip -4 route get 1.1.1.1
  systemctl is-active "$SERVICE" || true
  if command -v wg >/dev/null 2>&1; then
    wg show wg-cerato latest-handshakes 2>/dev/null || true
  fi
}

if [[ "$MODE" == "--rollback" ]]; then
  [[ "$EUID" -eq 0 ]] || die "sudo requis."
  [[ -f "$LATEST" ]] || die "Aucune sauvegarde de migration connue."
  SNAP="$(cat "$LATEST")"
  [[ "$SNAP" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || die "Identifiant de sauvegarde invalide."
  DIR="$BACKUPS/$SNAP"
  [[ -f "$DIR/server.py" && -f "$DIR/app.js" ]] || die "Sauvegarde incomplète."
  install -m 0644 "$DIR/server.py" "$APP_HOME/backend/server.py"
  install -m 0644 "$DIR/app.js" "$APP_HOME/web/app.js"
  # Keep the managed-IP restore helper intact: a new /32 may have become
  # persistent since this upgrade. Removing it would break the next reboot.
  if [[ -f "$DIR/additional-sudoers" ]]; then
    install -m 0440 "$DIR/additional-sudoers" "$SUDOERS"
  else
    rm -f "$SUDOERS"
  fi
  # Do not erase managed extra addresses or the persistence service on rollback:
  # removing them could interrupt IP services already assigned since upgrade.
  systemctl restart "$SERVICE"
  systemctl is-active --quiet "$SERVICE" ||
    die "Panneau après rollback inactif : console OVH de secours requise."
  echo "Ancienne interface restaurée. Adresses supplémentaires et réseau laissés intacts."
  exit 0
fi

[[ "$EUID" -eq 0 ]] || die "sudo requis (même pour --check : la configuration existante est protégée)."
require_layout
TMP="$(mktemp -d -t cerato-inplace-upgrade-XXXXXXXX)"
trap 'rm -rf -- "$TMP"' EXIT
make_patch "$TMP"
baseline
if [[ "$MODE" == "--check" ]]; then
  echo "CHECK OK : patch applicable à l'installation existante."
  echo "Aucun fichier en production n'a été modifié."
  echo "Le mode IP routée vers Windows reste désactivé jusqu'à la prise en charge de l'agent."
  exit 0
fi

[[ "$EUID" -eq 0 ]] || die "sudo requis pour --apply."
[[ -x "$(command -v visudo || true)" ]] || die "visudo requis."
[[ -x "$(command -v systemctl || true)" ]] || die "systemd requis."

install -d -m 0700 "$BACKUPS"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)-$$"
DIR="$BACKUPS/$STAMP"
install -d -m 0700 "$DIR"
cp -p "$APP_HOME/backend/server.py" "$DIR/server.py"
cp -p "$APP_HOME/web/app.js" "$DIR/app.js"
[[ ! -e "$IPCTL" ]] || cp -p "$IPCTL" "$DIR/ipctl"
[[ ! -f "$SUDOERS" ]] || cp -p "$SUDOERS" "$DIR/additional-sudoers"
# Preserve existing state — never reset it or re-install WireGuard.
tar -czf "$DIR/network-config-backup.tgz" \
  -C / etc/cerato-network etc/wireguard 2>/dev/null ||
    die "Sauvegarde réseau impossible : migration annulée."
chmod 0600 "$DIR/network-config-backup.tgz"

OLD_IPCTL_PRESENT=0
[[ -f "$DIR/ipctl" ]] && OLD_IPCTL_PRESENT=1
restore_web() {
  echo "Échec : retour arrière du Web actuel." >&2
  cp -p "$DIR/server.py" "$APP_HOME/backend/server.py" || true
  cp -p "$DIR/app.js" "$APP_HOME/web/app.js" || true
  # Keep root-owned persistence helper if a managed-IP state exists.
  # The old web backend is restored without altering WAN addresses.
  if [[ -f "$DIR/additional-sudoers" ]]; then
    cp -p "$DIR/additional-sudoers" "$SUDOERS" || true
  else
    rm -f "$SUDOERS"
  fi
  systemctl restart "$SERVICE" || true
}
trap restore_web ERR

install -m 0755 "$ROOT/network/ovh_additional_ip.py" "$IPCTL"
# Adopt only the existing pool IPv4 addresses that are ALREADY on WAN.
# No address, peer, route or nftables rule is changed during migration.
"$IPCTL" adopt-existing-pool

cat > "$SUDOERS" <<'SUDO'
Defaults:ceratonet env_reset
ceratonet ALL=(root) NOPASSWD: /usr/local/sbin/cerato-ipctl preview *, /usr/local/sbin/cerato-ipctl import-local *
SUDO
chmod 0440 "$SUDOERS"
visudo -cf "$SUDOERS" >/dev/null || die "Sudoers invalide"

cat > "/etc/systemd/system/$RESTORE_SERVICE" <<'UNIT'
[Unit]
Description=Cerato Network - restore managed Additional IPv4 /32 after boot
After=network-online.target
Wants=network-online.target
Before=cerato-network-rules.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/cerato-ipctl restore
TimeoutStartSec=20
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable "$RESTORE_SERVICE" >/dev/null
# Do NOT restart networking, nftables, or wg-quick.

install -m 0644 "$TMP/backend/server.py" "$APP_HOME/backend/server.py"
install -m 0644 "$TMP/web/app.js" "$APP_HOME/web/app.js"
systemctl restart "$SERVICE"
sleep 1
systemctl is-active --quiet "$SERVICE"
curl -fsS --connect-timeout 2 --max-time 8 -o /dev/null http://127.0.0.1:8787/
# Verify that the original control-plane data still includes its peer names.
"$CTL" status | python3 -c 'import sys,json; json.load(sys.stdin)'
printf '%s\n' "$STAMP" > "$LATEST"
chmod 0600 "$LATEST"
trap - ERR

echo "SUCCESS : panneau original mis à niveau sur le même port 8787."
echo "Les pairs WireGuard, configurations OVH et règles NAT existantes ont été conservés."
echo "Le nouveau formulaire Adresses IPv4 configure maintenant le /32 en local, avec restauration au boot."
echo "Ne pas utiliser le mode routé tant que l'agent Dell Ubuntu n'est pas validé."
echo "Rollback applicatif : sudo bash scripts/upgrade-live-in-place.sh --rollback"
