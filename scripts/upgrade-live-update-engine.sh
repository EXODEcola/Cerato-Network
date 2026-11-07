#!/usr/bin/env bash
# Root-only one-time upgrade of the approved Web UPDATE ENGINE and local
# routed-IPv4 patcher. Does not install an unsigned Web release or touch network.
set -Eeuo pipefail
umask 077
MODE="${1:---check}"
[[ "$MODE" == "--check" || "$MODE" == "--install" ]] || {
  echo "Usage: --check | --install" >&2; exit 2;
}
[[ "$EUID" -eq 0 ]] || { echo "Root requis." >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET=/opt/cerato-network/updater
WEB_SERVICE=cerato-network-web.service
WRAPPER=/usr/local/sbin/cerato-updatectl
# Upgrade the signed-release HTTPS mirror validator alongside the Web updater.
# Otherwise GitHub has the beta but the OVH mirror refuses its routed-ui schema.
RELS=(
  updates/live_controller.py
  integrations/patch_live_routed_ui.py
  network/routed_ui_status.py
  tools/stage_signed_static_release.py
)
[[ -f "$TARGET/updates/live_controller.py" && ! -L "$TARGET/updates/live_controller.py" ]] || {
  echo "Moteur de mises à jour initial non détecté" >&2; exit 1;
}
[[ -x "$WRAPPER" && ! -L "$WRAPPER" ]] || {
  echo "Contrôleur d'updates manquant" >&2; exit 1;
}
systemctl is-active --quiet "$WEB_SERVICE" || {
  echo "Panneau existant inactif : refus" >&2; exit 1;
}
if systemctl is-active --quiet cerato-network-update.service; then
  echo "Une installation signée est en cours : refus" >&2; exit 1
fi
for rel in "${RELS[@]}"; do
  [[ -f "$ROOT/$rel" && ! -L "$ROOT/$rel" ]] || {
    echo "Fichier source absent ou symbolique : $rel" >&2; exit 1;
  }
  python3 -m py_compile "$ROOT/$rel"
  if [[ -e "$TARGET/$rel" || -L "$TARGET/$rel" ]]; then
    [[ -f "$TARGET/$rel" && ! -L "$TARGET/$rel" &&
       "$(stat -c %u "$TARGET/$rel")" == "0" ]] || {
      echo "Destination inconnue : $rel" >&2; exit 1;
    }
  fi
done
grep -q 'ROUTED_SCHEMA=' "$ROOT/updates/live_controller.py"
grep -q 'ROUTED_SCHEMA=' "$ROOT/tools/stage_signed_static_release.py"
grep -q 'def stage(' "$ROOT/integrations/patch_live_routed_ui.py"
grep -q 'def summarize(' "$ROOT/network/routed_ui_status.py"
"$WRAPPER" status | python3 -c 'import json,sys; assert "installed_version" in json.load(sys.stdin)'
echo "Prérequis moteur de mise à jour et correctif IPv4 : OK"
if [[ "$MODE" == "--check" ]]; then
  echo "Aucun fichier, réseau ou service modifié."
  exit 0
fi
BACKUP="/var/backups/cerato-network-updater/routed-$(date -u +%Y%m%dT%H%M%SZ)-$$"
install -d -o root -g root -m 0700 "$BACKUP"
for rel in "${RELS[@]}"; do
  if [[ -f "$TARGET/$rel" ]]; then
    install -d -m 0700 "$BACKUP/$(dirname "$rel")"
    cp -p "$TARGET/$rel" "$BACKUP/$rel"
  fi
done
rollback() {
  echo "Échec : restauration du moteur précédent" >&2
  for rel in "${RELS[@]}"; do
    if [[ -f "$BACKUP/$rel" ]]; then
      cp -p "$BACKUP/$rel" "$TARGET/$rel" || true
    else
      rm -f "$TARGET/$rel" || true
    fi
  done
}
trap rollback ERR
install -d -o root -g root -m 0755 "$TARGET/integrations" "$TARGET/network" "$TARGET/tools"
for rel in "${RELS[@]}"; do
  install -o root -g root -m 0644 "$ROOT/$rel" "$TARGET/$rel"
done
"$WRAPPER" status | python3 -c 'import json,sys; assert "installed_version" in json.load(sys.stdin)'
trap - ERR
echo "Updater, patcher IPv4 et validateur du miroir signé approuvés installés ; aucun service redémarré."
echo "Sauvegarde : $BACKUP"
