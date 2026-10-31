#!/usr/bin/env bash
# One-time RISE-1 engine refresh + signed-source activation.
# No changes to Build, WireGuard, nftables, addresses, NAT, login or Nginx.
set -Eeuo pipefail
umask 077
MODE="${1:---check}"
if (( $# > 0 )); then shift; fi
[[ "$MODE" == "--check" || "$MODE" == "--install" ]] || {
  echo "Usage: --check | --install [--public-key PATH --fingerprint SHA256_DER]" >&2; exit 2;
}
[[ "$EUID" -eq 0 ]] || { echo "sudo requis sur OVH RISE-1." >&2; exit 2; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENGINE=/opt/cerato-network/updater
CTL=/usr/local/sbin/cerato-updatectl
TRUST=/etc/cerato-network/release-source.json
BACKUPS=/var/backups/cerato-network-inplace/update-engine-final
ARGS=("$@")
if (( ${#ARGS[@]} > 0 )); then
  [[ ${#ARGS[@]} == 4 && "${ARGS[0]}" == "--public-key" && "${ARGS[2]}" == "--fingerprint" ]] || {
    echo "Clé et empreinte à fournir ensemble et dans cet ordre." >&2; exit 2;
  }
fi
for rel in updates/live_controller.py updates/remote.py tools/build_release.py; do
  [[ -f "$ROOT/$rel" && ! -L "$ROOT/$rel" && -f "$ENGINE/$rel" && ! -L "$ENGINE/$rel" ]] || {
    echo "Moteur source ou installé absent : $rel" >&2; exit 2;
  }
  [[ "$(stat -c %u "$ENGINE/$rel")" == 0 ]] || {
    echo "Moteur non détenu par root : $rel" >&2; exit 2;
  }
done
[[ -x "$CTL" && ! -L "$CTL" ]] || {
  echo "cerato-updatectl non installé." >&2; exit 2;
}
[[ -f /opt/cerato-network/backend/server.py && ! -L /opt/cerato-network/backend/server.py ]] || {
  echo "Backend OVH absent." >&2; exit 2;
}
systemctl is-active --quiet cerato-network-web.service || {
  echo "Web 8787 arrêté." >&2; exit 2;
}
if systemctl is-active --quiet cerato-network-update.service; then
  echo "Installation de release en cours : opération refusée." >&2; exit 2;
fi
curl -fsS --max-time 6 -o /dev/null http://127.0.0.1:8787/ || {
  echo "Panneau HTTP local indisponible." >&2; exit 2;
}
python3 -m py_compile "$ROOT/updates/live_controller.py" \
  "$ROOT/updates/remote.py" "$ROOT/tools/build_release.py" \
  "$ROOT/integrations/activate_live_updates.py"
bash -n "$ROOT/scripts/enable-live-update-check.timer.sh"
"$CTL" status | python3 -c 'import json,sys; s=json.load(sys.stdin);assert "installed_version" in s'

if [[ "$MODE" == "--check" ]]; then
  if [[ ! -f "$TRUST" ]]; then
    echo "BLOQUÉ : clé publique de distribution non épinglée." >&2
  else
    echo "Source de distribution présente ; contrôler sa signature." >&2
  fi
  echo "Aucun changement en mode précontrôle."
  exit 0
fi
if [[ ! -f "$TRUST" && ${#ARGS[@]} == 0 ]]; then
  echo "BLOQUÉ : aucune clé Ed25519 approuvée sur OVH." >&2
  echo "La première release ne peut pas être inventée à partir de l'adresse HTTPS." >&2
  exit 3
fi
if [[ -e "$TRUST" && ${#ARGS[@]} -gt 0 ]]; then
  echo "Clé déjà épinglée : remplacement interdit." >&2
  exit 2
fi

net_hash(){
  for path in /etc/wireguard/wg-cerato.conf /etc/cerato-network/config.json; do
    [[ -f "$path" && ! -L "$path" ]] || return 2
  done
  sha256sum /etc/wireguard/wg-cerato.conf /etc/cerato-network/config.json |
    sha256sum | cut -d' ' -f1
}
BEFORE="$(net_hash)" || { echo "Configuration réseau introuvable." >&2; exit 2; }
STAMP="$(date -u +%Y%m%dT%H%M%SZ)-$$"
BACKUP="$BACKUPS/$STAMP"
install -d -o root -g root -m 0700 "$BACKUPS" "$BACKUP"
for rel in updates/live_controller.py updates/remote.py tools/build_release.py; do
  mkdir -p "$BACKUP/$(dirname "$rel")"
  cp -p "$ENGINE/$rel" "$BACKUP/$rel"
done
CHANGED=0
rollback(){
  local rc=$?
  trap - ERR
  if (( CHANGED )); then
    echo "Échec : restauration du précédent moteur d'updates." >&2
    for rel in updates/live_controller.py updates/remote.py tools/build_release.py; do
      cp -p "$BACKUP/$rel" "$ENGINE/$rel" || true
    done
  fi
  exit "$rc"
}
trap rollback ERR
CHANGED=1
install -o root -g root -m 0755 "$ROOT/updates/live_controller.py" \
  "$ENGINE/updates/live_controller.py"
install -o root -g root -m 0644 "$ROOT/updates/remote.py" \
  "$ENGINE/updates/remote.py"
install -o root -g root -m 0644 "$ROOT/tools/build_release.py" \
  "$ENGINE/tools/build_release.py"
"$CTL" status | python3 -c 'import json,sys; s=json.load(sys.stdin);assert "installed_version" in s'
python3 "$ROOT/integrations/activate_live_updates.py" --install "${ARGS[@]}"
AFTER="$(net_hash)" || false
[[ "$BEFORE" == "$AFTER" ]] || {
  echo "Empreinte réseau différente, annulation." >&2
  false
}
CHANGED=0
trap - ERR
echo "Moteur à jour ; réseau inchangé. Sauvegarde : $BACKUP"
echo "Une release reste installable uniquement si le canal Ed25519 est valide."
