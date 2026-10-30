#!/usr/bin/env bash
# Isolated interactive Cerato Network login demo on a dedicated build VM.
# Starts only localhost HTTP 8788, with a TEMPORARY SQLite database.
# Forward its port over SSH to open in your own browser. Do not put on Internet.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
if [[ "$EUID" -eq 0 ]]; then
  echo "Refus : cette démonstration ne doit pas être lancée sous root." >&2
  exit 1
fi
if command -v systemctl >/dev/null 2>&1 && systemctl -q is-active cerato-network-web.service; then
  echo "Refus : la passerelle Cerato Network de production est active sur cet hôte." >&2
  exit 1
fi
if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
  echo "Lancer bash scripts/bootstrap-dev.sh sur CERATO-BUILD-01." >&2
  exit 1
fi
if command -v ss >/dev/null 2>&1 && ss -Hltn 'sport = :8788' | grep -q .; then
  echo "Port 8788 déjà utilisé. Vérifier le service local avant le test." >&2
  exit 1
fi

umask 077
WORKDIR="$(mktemp -d -t cerato-demo-login-XXXXXXXX)"
cleanup() { rm -rf -- "$WORKDIR"; }
trap cleanup EXIT

source "$ROOT/.venv/bin/activate"
export CERATO_DEV_AUTH_ONLY=1
export CERATO_DEV_LOOPBACK_HTTP=1
export CERATO_AUTH_DB="$WORKDIR/accounts.sqlite3"
export CERATO_PORT=8788
export CERATO_WEB_ORIGIN="https://network.example.org"
unset CERATO_TRUST_LOCAL_PROXY CERATO_DEV_STAGE_ENABLED

printf '\n=== Démonstration de connexion Cerato Network ===\n'
printf 'Une base de test temporaire vient d’être créée.\n'
printf 'Copie le code ci-dessous uniquement dans le formulaire initial :\n\n'
python security/cli.py --database "$CERATO_AUTH_DB" bootstrap-token

printf '\nDémarrage : http://127.0.0.1:8788 (sur la VM uniquement)\n'
printf 'Depuis ton PC, utilise un tunnel SSH vers cette VM pour ouvrir le port.\n'
printf 'Ctrl+C arrête la démonstration et efface sa base et sa clé MFA temporaire.\n\n'
exec python gateway/http_api.py
