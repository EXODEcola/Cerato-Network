#!/usr/bin/env bash
# Upgrade ONLY the existing trusted updater controller to support signed
# visual-only overlays. Does not modify the live web panel or network.
# One-time bootstrap by a privileged RISE-1 operator.
set -Eeuo pipefail
umask 077
MODE="--check"
if (( $# > 0 )); then MODE="$1"; fi
[[ "$MODE" == "--check" || "$MODE" == "--install" ]] || {
  echo "Usage: --check | --install" >&2; exit 2;
}
[[ "$EUID" -eq 0 ]] || { echo "Ce contrôle exige root." >&2; exit 1; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONTROLLER=/opt/cerato-network/updater/updates/live_controller.py
SOURCE="$ROOT/updates/live_controller.py"
WRAPPER=/usr/local/sbin/cerato-updatectl
SERVICE=cerato-network-web.service
[[ -f "$SOURCE" && ! -L "$SOURCE" && -f "$CONTROLLER" && ! -L "$CONTROLLER" ]] || {
  echo "Contrôleur source ou installation historique absent." >&2; exit 1;
}
[[ -f "$WRAPPER" && ! -L "$WRAPPER" && -x "$WRAPPER" ]] || {
  echo "Service d'update non configuré : aucun remplacement effectué." >&2; exit 1;
}
systemctl -q is-active "$SERVICE" || {
  echo "Le panneau Web n'est pas actif : remplacement interdit." >&2; exit 1;
}
if systemctl -q is-active cerato-network-update.service; then
  echo "Une installation de release est en cours : opération interdite." >&2
  exit 1
fi
[[ "$(stat -c %u "$CONTROLLER")" == 0 ]] || {
  echo "Contrôleur installé non possédé par root." >&2; exit 1;
}
TEMPDIR="$(mktemp -d -t cerato-controller-preflight-XXXXXXXX)"
trap 'rm -rf "$TEMPDIR"' EXIT
cp "$SOURCE" "$TEMPDIR/live_controller.py"
python3 -m py_compile "$TEMPDIR/live_controller.py"
grep -q "VISUAL_SCHEMA=" "$TEMPDIR/live_controller.py" || {
  echo "Version de contrôleur ne prenant pas en charge les releases visuelles." >&2
  exit 1
}
grep -q 'VISUAL_FILES=' "$TEMPDIR/live_controller.py" || {
  echo "Format visuel non reconnu." >&2; exit 1
}
echo "Contrôleur de mises à jour : préflight réussi."
if [[ "$MODE" == "--check" ]]; then
  echo "Aucun fichier de production modifié."
  exit 0
fi

BACKUP_DIR=/var/backups/cerato-network-updater
install -d -o root -g root -m 0700 "$BACKUP_DIR"
SNAPSHOT="$BACKUP_DIR/controller-$(date -u +%Y%m%dT%H%M%SZ)-$$.py"
cp -p "$CONTROLLER" "$SNAPSHOT"
install -o root -g root -m 0755 "$SOURCE" "$CONTROLLER"
rollback(){
  echo "Validation échouée : restauration de l'ancien contrôleur." >&2
  cp -p "$SNAPSHOT" "$CONTROLLER"
}
trap rollback ERR
"$WRAPPER" status | python3 -c 'import json,sys; d=json.load(sys.stdin); assert isinstance(d,dict) and "installed_version" in d'
trap - ERR
echo "Moteur de release mis à niveau. Le Web sur 8787 et le réseau n'ont pas été redémarrés."
echo "Référence de retour arrière : $SNAPSHOT"
