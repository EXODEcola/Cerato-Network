#!/usr/bin/env bash
# Auth-only tests on CERATO-BUILD-01. Never install on the live RISE-1 gateway.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
if [[ "$EUID" -eq 0 ]]; then
  echo "Refus des tests d'authentification sous root." >&2
  exit 2
fi
if command -v systemctl >/dev/null 2>&1 && systemctl -q is-active cerato-network-web.service; then
  echo "Refus : RISE-1 actif ; exécuter uniquement sur CERATO-BUILD-01." >&2
  exit 2
fi
PYTHON="$ROOT/.venv/bin/python"
if [[ ! -x "$PYTHON" ]]; then
  echo "Environnement de test absent. Sur CERATO-BUILD-01 :" >&2
  echo "  python3 -m venv .venv" >&2
  echo "  .venv/bin/python -m pip install -r security/requirements.txt" >&2
  exit 2
fi
if ! "$PYTHON" -c 'import argon2, cryptography' >/dev/null 2>&1; then
  echo "Dépendances de sécurité absentes dans .venv." >&2
  echo "  .venv/bin/python -m pip install -r security/requirements.txt" >&2
  exit 2
fi
for suite in \
  test_live_auth_cutover.py \
  test_live_handler_flow.py \
  test_live_handler_delegation.py \
  test_legacy_auth_api.py \
  test_live_session_guard.py \
  test_legacy_policy.py; do
  "$PYTHON" -m unittest discover -s tests -p "$suite" -v
done
echo "Suites d'authentification terminées. Le basculement en production reste interdit."
