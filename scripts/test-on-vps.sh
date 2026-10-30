#!/usr/bin/env bash
# Run on CERATO-BUILD-01 or any isolated Linux build machine.
# This script does NOT run on GitHub Actions and does NOT touch the OS network.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "${EUID}" -eq 0 ]]; then
  echo "Refus : les tests ne doivent pas être exécutés sous root." >&2
  exit 1
fi
python3 --version
python3 -m compileall -q security gateway network updates tools tests
if command -v node >/dev/null 2>&1; then
  node --check web/app.js
else
  echo "Node.js absent : vérification JavaScript non exécutée." >&2
  exit 1
fi
python3 -m unittest discover -s tests -p 'test_*.py' -v
echo "Tests techniques terminés. Cela ne remplace pas une revue de sécurité ni les tests en production."
