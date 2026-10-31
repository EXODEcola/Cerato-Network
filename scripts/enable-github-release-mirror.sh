#!/usr/bin/env bash
# OVH-only, root-owned GitHub Release mirror for SIGNED public artifacts.
# Never installs an application update; publication happens only after verify.
set -Eeuo pipefail
umask 077
MODE="${1:---check}"
[[ "$MODE" == "--check" || "$MODE" == "--install" ]] || { echo "Usage: --check | --install" >&2; exit 2; }
[[ "$EUID" -eq 0 ]] || { echo "sudo requis." >&2; exit 2; }
TRUST=/etc/cerato-network/release-source.json
MIRROR=/opt/cerato-network/updater/tools/sync_github_signed_release.py
ROOT=/srv/cerato-releases/public/cerato-releases
SERVICE=/etc/systemd/system/cerato-network-github-mirror.service
TIMER=/etc/systemd/system/cerato-network-github-mirror.timer
[[ -f "$TRUST" && ! -L "$TRUST" && -f "$MIRROR" && ! -L "$MIRROR" ]] || {
  echo "Source de confiance ou miroir sécurisé absent." >&2; exit 2;
}
[[ -d "$ROOT" && ! -L "$ROOT" ]] || { echo "Distribution statique absente." >&2; exit 2; }

SERVICE_TEXT="$(cat <<'UNIT'
[Unit]
Description=Cerato Network - mirror of pinned signed GitHub releases
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 /opt/cerato-network/updater/tools/sync_github_signed_release.py --install
TimeoutStartSec=160
UMask=0077
ProtectSystem=strict
ReadWritePaths=/srv/cerato-releases/public/cerato-releases
PrivateTmp=true
ProtectHome=true
NoNewPrivileges=true
UNIT
)"
TIMER_TEXT="$(cat <<'UNIT'
[Unit]
Description=Cerato Network - synchronisation des releases officielles

[Timer]
OnBootSec=5min
OnUnitInactiveSec=4h
RandomizedDelaySec=10min
Persistent=true
Unit=cerato-network-github-mirror.service

[Install]
WantedBy=timers.target
UNIT
)"
for path in "$SERVICE" "$TIMER"; do
  if [[ -e "$path" || -L "$path" ]]; then
    [[ -f "$path" && ! -L "$path" ]] || { echo "Unité symbolique ou invalide." >&2; exit 2; }
  fi
done
[[ ! -e "$SERVICE" || "$(cat "$SERVICE")" = "$SERVICE_TEXT" ]] || {
  echo "Service existant incompatible." >&2; exit 2;
}
[[ ! -e "$TIMER" || "$(cat "$TIMER")" = "$TIMER_TEXT" ]] || {
  echo "Timer existant incompatible." >&2; exit 2;
}
if [[ "$MODE" == "--check" ]]; then
  echo "Miroir signé prêt : aucun fichier modifié."
  exit 0
fi
S_NEW=0
T_NEW=0
rollback(){
  code=$?
  trap - ERR
  if [[ "$T_NEW" -eq 1 ]]; then
    systemctl disable --now cerato-network-github-mirror.timer >/dev/null 2>&1 || true
    rm -f -- "$TIMER"
  fi
  if [[ "$S_NEW" -eq 1 ]]; then rm -f -- "$SERVICE"; fi
  systemctl daemon-reload || true
  exit "$code"
}
trap rollback ERR
if [[ ! -f "$SERVICE" ]]; then
  printf '%s\n' "$SERVICE_TEXT" | install -o root -g root -m 0644 /dev/stdin "$SERVICE"
  S_NEW=1
fi
if [[ ! -f "$TIMER" ]]; then
  printf '%s\n' "$TIMER_TEXT" | install -o root -g root -m 0644 /dev/stdin "$TIMER"
  T_NEW=1
fi
systemctl daemon-reload
systemctl enable --now cerato-network-github-mirror.timer
trap - ERR
echo "Miroir signé programmé toutes les 4 heures ; aucune installation de code automatique."
