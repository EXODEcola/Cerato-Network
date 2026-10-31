#!/usr/bin/env bash
# Safe periodic signed-update CHECK. Never starts an installation.
# Called once on RISE-1 after the public Ed25519 trust anchor is configured.
set -Eeuo pipefail
umask 077
ACTION="--check"
if (( $# > 0 )); then ACTION="$1"; fi
[[ "$ACTION" = "--check" || "$ACTION" = "--install" ]] || {
  echo "Usage: --check | --install" >&2; exit 2;
}
[[ "$EUID" -eq 0 ]] || { echo "Exécuter avec sudo sur RISE-1." >&2; exit 2; }

CTL=/usr/local/sbin/cerato-updatectl
TRUST=/etc/cerato-network/release-source.json
SERVICE=/etc/systemd/system/cerato-network-update-check.service
TIMER=/etc/systemd/system/cerato-network-update-check.timer

[[ -f "$CTL" && -x "$CTL" && ! -L "$CTL" ]] || {
  echo "Moteur d'update existant manquant." >&2; exit 2;
}
[[ -f "$TRUST" && ! -L "$TRUST" ]] || {
  echo "Clé publique et source HTTPS non configurées." >&2; exit 2;
}
"$CTL" status | python3 -c 'import json,sys; state=json.load(sys.stdin); assert state.get("configured") and state.get("can_check"), "Source non approuvée"'

SERVICE_TEXT="$(cat <<'UNIT'
[Unit]
Description=Cerato Network - contrôle périodique de releases signées
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/sbin/cerato-updatectl check
TimeoutStartSec=90
UMask=0077
ProtectSystem=strict
ReadWritePaths=/var/lib/cerato-network-updates
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
UNIT
)"
TIMER_TEXT="$(cat <<'UNIT'
[Unit]
Description=Cerato Network - recherche des mises à jour signées

[Timer]
OnBootSec=10min
OnUnitInactiveSec=6h
RandomizedDelaySec=15min
Persistent=true
Unit=cerato-network-update-check.service

[Install]
WantedBy=timers.target
UNIT
)"
# Refuse unknown units; re-running our own version is safe.
if [[ -e "$SERVICE" || -L "$SERVICE" ]]; then
  [[ -f "$SERVICE" && ! -L "$SERVICE" && "$(cat "$SERVICE")" = "$SERVICE_TEXT" ]] || {
    echo "Un service existant de contrôle est incompatible ; aucun remplacement." >&2; exit 2;
  }
fi
if [[ -e "$TIMER" || -L "$TIMER" ]]; then
  [[ -f "$TIMER" && ! -L "$TIMER" && "$(cat "$TIMER")" = "$TIMER_TEXT" ]] || {
    echo "Un timer existant de contrôle est incompatible ; aucun remplacement." >&2; exit 2;
  }
fi

if [[ "$ACTION" = "--check" ]]; then
  echo "Contrôle périodique prêt. Aucune modification ni installation de release."
  exit 0
fi
SERVICE_NEW=0
TIMER_NEW=0
rollback(){
  code=$?
  trap - ERR
  if [[ "$SERVICE_NEW" = 1 ]]; then rm -f -- "$SERVICE"; fi
  if [[ "$TIMER_NEW" = 1 ]]; then rm -f -- "$TIMER"; fi
  systemctl daemon-reload || true
  exit "$code"
}
trap rollback ERR
if [[ ! -e "$SERVICE" ]]; then
  install -o root -g root -m 0644 /dev/stdin "$SERVICE" <<<"$SERVICE_TEXT"
  SERVICE_NEW=1
fi
if [[ ! -e "$TIMER" ]]; then
  install -o root -g root -m 0644 /dev/stdin "$TIMER" <<<"$TIMER_TEXT"
  TIMER_NEW=1
fi
systemctl daemon-reload
systemctl enable --now cerato-network-update-check.timer
trap - ERR
echo "Contrôle périodique activé : recherche de releases signées toutes les 6 h."
echo "Aucune installation automatique ; l'administrateur installe depuis le panneau Web."
