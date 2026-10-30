#!/usr/bin/env bash
# REAL loopback preproduction integration test on CERATO-BUILD-01.
# It opens 127.0.0.1 ephemeral HTTPS/HTTP sockets ONLY; no external network,
# no OS services, routing tables, nftables, WireGuard or privileged operations.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "${EUID}" -eq 0 ]]; then
  echo "Refus : les tests de préproduction ne s'exécutent pas en root." >&2
  exit 1
fi

if command -v systemctl >/dev/null 2>&1 && systemctl -q is-active cerato-network-web.service; then
  echo "Refus : le moteur Cerato Network est actif ici. Utilise CERATO-BUILD-01." >&2
  exit 1
fi

if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
  echo "Environnement .venv absent. Lancer bash scripts/bootstrap-dev.sh sur la VM isolée." >&2
  exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "OpenSSL requis pour les certificats TLS et signatures des tests." >&2
  exit 1
fi

source "$ROOT/.venv/bin/activate"

echo "=== Phase 1 : tests unitaires et API ==="
bash scripts/test-on-vps.sh

echo "=== Phase 2 : vrais services HTTPS/HTTP sur 127.0.0.1 (ports éphémères) ==="
python -m unittest discover -s integration -p 'test_*.py' -v

echo "=== Préproduction locale validée ==="
echo "Aucun service en production, pare-feu, route, tunnel WireGuard ou machine liée n'a été modifié."
