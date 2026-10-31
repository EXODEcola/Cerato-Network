#!/usr/bin/env bash
# Final OVH-only command after release approval in GitHub Actions.
# Takes an independently verified DER fingerprint from GitHub Environment.
# Does not contact Cerato Build or access private keys.
set -Eeuo pipefail
umask 077
[[ "$EUID" -eq 0 ]] || { echo "sudo requis sur RISE-1" >&2; exit 2; }
FINGERPRINT="${1:-}"
[[ "$FINGERPRINT" =~ ^[a-f0-9]{64}$ ]] || {
  echo "Une empreinte SHA-256 DER approuvée (64 caractères hex) est requise." >&2; exit 2;
}
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d -t cerato-verified-pub-XXXXXXXX)"
cleanup(){ rm -rf -- "$TMP"; }
trap cleanup EXIT
python3 "$ROOT/tools/prepare_trusted_github_public.py" \
  --fingerprint "$FINGERPRINT" --output "$TMP/approved.pub" --channel beta
# Must pin the public key before accepting any GitHub-hosted release.
bash "$ROOT/scripts/finalize-ovh-web-updates.sh" --install \
  --public-key "$TMP/approved.pub" --fingerprint "$FINGERPRINT"
# Mirror signed and immutable release assets onto the already configured HTTPS IP.
python3 /opt/cerato-network/updater/tools/sync_github_signed_release.py --install
# Keep checking the repository for new signed releases, no SSH credential.
bash "$ROOT/scripts/enable-github-release-mirror.sh" --install
# Verify availability from the very same HTTPS source the browser uses.
STATUS="$(/usr/local/sbin/cerato-updatectl check)"
printf '%s\n' "$STATUS" | python3 -c 'import json,sys; d=json.load(sys.stdin);assert d.get("configured");print(json.dumps({k:d.get(k) for k in ("installed_version","available_version","installable","reason_code","channel")},sort_keys=True))'
echo "Distribution signée activée. Les INSTALLATIONS se font depuis l'interface Cerato Network."
