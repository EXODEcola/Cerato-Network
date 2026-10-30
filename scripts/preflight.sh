#!/usr/bin/env bash
# Read-only host preflight for Cerato Network Linux deployments.
# No apt, service changes, firewall or routes are modified.
set -Eeuo pipefail

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  source /etc/os-release
  echo "Système : ${PRETTY_NAME:-Linux inconnu}"
else
  echo "Système : Linux (distribution non détectée)"
fi
echo "Architecture : $(uname -m)"
echo "Noyau : $(uname -r)"
echo ""

echo "=== Dépendances ==="
for bin in git python3 openssl curl wg nft ip nginx systemctl; do
  if command -v "$bin" >/dev/null 2>&1; then
    printf 'OK       %s\n' "$bin"
  else
    printf 'MANQUANT %s\n' "$bin"
  fi
done
echo ""

echo "=== État des services (lecture seule) ==="
if command -v systemctl >/dev/null 2>&1; then
  for svc in cerato-network-web.service nginx.service wg-quick@wg-cerato.service; do
    if systemctl -q is-active "$svc"; then
      printf 'ACTIF  %s\n' "$svc"
    else
      printf 'INACTIF ou absent  %s\n' "$svc"
    fi
  done
fi
echo ""

echo "=== Installation déjà présente ==="
for path in /opt/cerato-network /var/lib/cerato-network /etc/wireguard /etc/nginx/sites-enabled; do
  if [[ -e "$path" ]]; then
    printf 'PRÉSENT %s\n' "$path"
  else
    printf 'ABSENT  %s\n' "$path"
  fi
done

echo ""
echo "Préflight terminé. Aucune modification réseau ou système effectuée."
echo "Ne pas lancer de migration automatiquement si un service existant est détecté."
