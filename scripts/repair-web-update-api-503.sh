#!/usr/bin/env bash
# Minimal remediation of Cerato Network /api/updates HTTP 503 on RISE-1.
# The root-owned updater opens a writable lock in /var/lib/cerato-network-updates.
# ProtectSystem=strict on the Web unit blocks it, even after sudo succeeds.
# Do not disable sandboxing: permit this ONE root-owned private directory.
set -Eeuo pipefail
umask 077
MODE="${1:---check}"
[[ "$MODE" == "--check" || "$MODE" == "--install" ]] || {
  echo "Usage : --check | --install" >&2; exit 2;
}
[[ "$EUID" -eq 0 ]] || { echo "sudo requis sur OVH RISE-1." >&2; exit 2; }

UNIT=cerato-network-web.service
UPDATER_UNIT=cerato-network-update.service
WEB_USER=ceratonet
STORE=/var/lib/cerato-network-updates
CTL=/usr/local/sbin/cerato-updatectl
DROPIN_DIR=/etc/systemd/system/cerato-network-web.service.d
DROPIN="$DROPIN_DIR/60-cerato-update-store.conf"
CONFIG_TEXT="$(cat <<'UNITFILE'
[Service]
# Root-owned Ed25519 controller needs O_RDWR flock on its private lock file.
# ceratonet cannot write here (directory remains owned by root, mode 0700).
ReadWritePaths=/var/lib/cerato-network-updates
UNITFILE
)"

[[ "$(systemctl show "$UNIT" -p User --value)" == "$WEB_USER" ]] || {
  echo "Utilisateur système Web inattendu." >&2; exit 2;
}
[[ "$(systemctl show "$UNIT" -p ProtectSystem --value)" == "strict" ]] || {
  echo "Sandbox Web différent de ProtectSystem=strict ; aucun changement." >&2; exit 2;
}
[[ "$(systemctl show "$UNIT" -p NoNewPrivileges --value)" == "no" ]] || {
  echo "NoNewPrivileges du service a changé ; aucun contournement." >&2; exit 2;
}
systemctl is-active --quiet "$UNIT" || {
  echo "Panneau arrêté avant modification." >&2; exit 2;
}
if systemctl is-active --quiet "$UPDATER_UNIT"; then
  echo "Une installation signée est en cours ; opération refusée." >&2; exit 2;
fi
[[ -x "$CTL" && ! -L "$CTL" ]] || {
  echo "Contrôleur root absent ou symbolique." >&2; exit 2;
}
[[ -d "$STORE" && ! -L "$STORE" && "$(stat -c %u "$STORE")" == 0 ]] || {
  echo "Stockage privé de l'updater invalide." >&2; exit 2;
}
[[ "$(stat -c %a "$STORE")" == 700 ]] || {
  echo "Stockage d'updates non privé (0700 requis). Refus." >&2; exit 2;
}
if [[ -e "$STORE/.update.lock" || -L "$STORE/.update.lock" ]]; then
  [[ -f "$STORE/.update.lock" && ! -L "$STORE/.update.lock" &&
     "$(stat -c %u "$STORE/.update.lock")" == 0 ]] || {
    echo "Verrou de mise à jour non approuvé." >&2; exit 2;
  }
fi
[[ ! -L "$DROPIN_DIR" && ! -L "$DROPIN" ]] || {
  echo "Drop-in symbolique non autorisé." >&2; exit 2;
}
if [[ -e "$DROPIN" ]]; then
  [[ -f "$DROPIN" && "$(stat -c %u "$DROPIN")" == 0 &&
     "$(cat "$DROPIN")" == "$CONFIG_TEXT" ]] || {
    echo "Fichier drop-in existant différent : refus de l'écraser." >&2; exit 2;
  }
fi
# This exact command has already succeeded from SSH. It must continue to
# succeed without requiring broader sudoers or credential changes.
sudo -u "$WEB_USER" sudo -n "$CTL" status >/dev/null
curl -fsS --max-time 6 -o /dev/null http://127.0.0.1:8787/ || {
  echo "Panneau local 8787 indisponible avant modification." >&2; exit 2;
}
network_hash() {
  local f
  for f in /etc/cerato-network/config.json /etc/wireguard/wg-cerato.conf; do
    [[ -f "$f" && ! -L "$f" ]] || return 2
  done
  sha256sum /etc/cerato-network/config.json /etc/wireguard/wg-cerato.conf |
    sha256sum | cut -d' ' -f1
}
BEFORE="$(network_hash)" || { echo "Empreinte réseau inaccessible." >&2; exit 2; }

if [[ "$MODE" == "--check" ]]; then
  echo "Précontrôle OK : droits d'écriture limités au stockage privé de l'updater."
  echo "ProtectSystem=strict, sudoers et environnement Web inchangés."
  echo "Aucune modification de fichiers ou services."
  exit 0
fi

CREATED=0
CHANGED=0
rollback() {
  local code=$?
  trap - ERR
  if [[ "$CHANGED" == 1 ]]; then
    if [[ "$CREATED" == 1 ]]; then
      rm -f -- "$DROPIN"
      systemctl daemon-reload || true
    fi
    systemctl restart "$UNIT" || true
    echo "Échec de validation : retour à la configuration Web précédente." >&2
  fi
  exit "$code"
}
trap rollback ERR
if [[ ! -e "$DROPIN" ]]; then
  install -d -o root -g root -m 0755 "$DROPIN_DIR"
  TEMP="$(mktemp "$DROPIN_DIR/.60-cerato-update-store.XXXXXXXX")"
  printf '%s\n' "$CONFIG_TEXT" > "$TEMP"
  chmod 0644 "$TEMP"
  mv -n -- "$TEMP" "$DROPIN"
  CREATED=1
fi
CHANGED=1
systemctl daemon-reload
systemctl restart "$UNIT"
for i in 1 2 3 4 5 6 7 8 9 10; do
  if systemctl is-active --quiet "$UNIT" &&
    curl -fsS --max-time 3 -o /dev/null http://127.0.0.1:8787/; then
    break
  fi
  sleep 1
done
systemctl is-active --quiet "$UNIT"
curl -fsS --max-time 6 -o /dev/null http://127.0.0.1:8787/
systemctl show "$UNIT" -p ReadWritePaths --value | grep -Fq "$STORE"
[[ "$(systemctl show "$UNIT" -p ProtectSystem --value)" == "strict" ]]
[[ "$(systemctl show "$UNIT" -p NoNewPrivileges --value)" == "no" ]]
[[ "$(network_hash)" == "$BEFORE" ]] || {
  echo "Empreinte réseau modifiée : rollback du Web." >&2
  false
}
# The existing root-owned updatectl must remain available as ceratonet.
sudo -u "$WEB_USER" sudo -n "$CTL" status | python3 -c '
import json,sys
s=json.load(sys.stdin)
assert s.get("configured") and s.get("can_check"), "La source de confiance a changé"
print("Release reconnue : ",s.get("available_version"),"installable:",s.get("installable"))
'
CHANGED=0
trap - ERR
echo "Sandbox Web corrigée : ReadWritePaths=$STORE (0700 root conservé)."
echo "Actualiser Cerato Network puis ouvrir Mises à jour."
