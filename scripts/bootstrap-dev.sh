#!/usr/bin/env bash
# Cerato Network — bootstrap developer/test dependencies on an isolated build VPS.
# This is NOT the production gateway installer. Never deploy to RISE-1 with this.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "${EUID}" -eq 0 ]]; then
  echo "Refus : exécute ce bootstrap avec un compte non root (sudo sera demandé si nécessaire)." >&2
  exit 1
fi
if command -v systemctl >/dev/null 2>&1 &&
   systemctl -q is-active cerato-network-web.service; then
  echo "Refus : le panneau Cerato Network est actif sur cet hôte." >&2
  echo "Utiliser une machine de build/test isolée. Aucune modification du service n'a été effectuée." >&2
  exit 1
fi
if ! command -v apt-get >/dev/null 2>&1; then
  echo "Ce bootstrap de développement prend actuellement en charge Debian/Ubuntu (apt)." >&2
  exit 1
fi

missing=()
command -v python3 >/dev/null 2>&1 || missing+=(python3)
command -v git >/dev/null 2>&1 || missing+=(git)
command -v openssl >/dev/null 2>&1 || missing+=(openssl)
command -v node >/dev/null 2>&1 || missing+=(nodejs)

# On Ubuntu/Debian, venv can exist as a Python module without ensurepip.
if ! python3 -m venv --help >/dev/null 2>&1; then
  missing+=(python3-venv)
fi

if (("${#missing[@]}")); then
  if ! command -v sudo >/dev/null 2>&1; then
    echo "sudo absent : installe les dépendances à l'aide d'un administrateur." >&2
    exit 1
  fi
  echo "Installation automatique des paquets manquants : ${missing[*]}"
  sudo apt-get update
  sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
fi

if ! python3 -m venv .venv; then
  echo "L'environnement Python manque de ensurepip : réparation python3-venv..."
  sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3-venv
  python3 -m venv --clear .venv
fi

# All Python dependencies remain inside the project venv.
. .venv/bin/activate
python -m pip install -r security/requirements.txt

echo "=== Tests Cerato Network sur machine de build ==="
bash scripts/test-on-vps.sh
echo "Succès : le bootstrap de développement et les tests sont terminés."
echo "Aucun service Cerato, tunnel WireGuard, pare-feu ou route réseau n'a été modifié."
