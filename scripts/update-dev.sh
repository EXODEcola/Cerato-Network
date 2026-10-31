#!/usr/bin/env bash
# Cerato Network developer workflow: reuse checkout; never clone inside clone.
# Only on a dedicated development/build VPS, never on a live network gateway.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "${EUID}" -eq 0 ]]; then
  echo "Refus d'exécuter du code de développement sous root." >&2
  exit 1
fi
if command -v systemctl >/dev/null 2>&1 && systemctl -q is-active cerato-network-web.service; then
  echo "Refus : Cerato Network est actif. Utiliser le VPS de build isolé." >&2
  exit 1
fi
if [[ "$(git rev-parse --show-toplevel)" != "$ROOT" ]]; then
  echo "Chemin du dépôt incohérent ; opération annulée." >&2
  exit 1
fi
current="$(git branch --show-current)"
if [[ "$current" != "feature/secure-accounts" ]]; then
  echo "Branche inattendue ($current). Basculer volontairement sur feature/secure-accounts." >&2
  exit 1
fi
if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
  echo "Modifications locales détectées. Aucun pull automatique pour ne pas les écraser." >&2
  exit 1
fi

git pull --ff-only origin feature/secure-accounts
bash "$ROOT/scripts/bootstrap-dev.sh"
