#!/usr/bin/env bash
# Root-only OVH repair: validate signed files, fix public modes, upgrade
# the mirror publisher. No nginx reload, networking or Build VM changes.
set -Eeuo pipefail
umask 077
[[ "$EUID" -eq 0 ]] || { echo "sudo requis sur Cerato Network OVH." >&2; exit 2; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$ROOT/tools/publish_signed_release.py"
TARGET=/opt/cerato-network/updater/tools/publish_signed_release.py
BACKUPS=/var/backups/cerato-network-inplace/signed-release-permissions

[[ -f "$SOURCE" && ! -L "$SOURCE" && -f "$TARGET" && ! -L "$TARGET" ]] || {
  echo "Publisher installé inconnu : refus." >&2; exit 2;
}
[[ "$(stat -c %u "$TARGET")" = 0 ]] || {
  echo "Le publisher installé n'appartient pas à root." >&2; exit 2;
}
[[ -f /etc/cerato-network/release-source.json &&
   -f /etc/cerato-network/release-verification.pub ]] || {
  echo "Identité de signature OVH non épinglée." >&2; exit 2;
}
# Validate signed data before ANY chmod or module replacement.
python3 "$ROOT/tools/repair_published_signed_permissions.py"
python3 -m py_compile "$SOURCE" "$ROOT/tools/repair_published_signed_permissions.py"
install -d -o root -g root -m 0700 "$BACKUPS"
BACKUP="$BACKUPS/$(date -u +%Y%m%dT%H%M%SZ)-$$.py"
cp -p -- "$TARGET" "$BACKUP"
SWAPPED=0
rollback(){
  code=$?
  trap - ERR
  if [[ "$SWAPPED" -eq 1 ]]; then
    cp -p -- "$BACKUP" "$TARGET" || true
    echo "Publisher précédent restauré : $BACKUP" >&2
  fi
  exit "$code"
}
trap rollback ERR
install -o root -g root -m 0644 -- "$SOURCE" "$TARGET"
SWAPPED=1
python3 "$ROOT/tools/repair_published_signed_permissions.py" --install
trap - ERR
SWAPPED=0

# Nothing is restarted: mirror worker imports the repaired publisher on next run.
echo "=== HTTPS public (réponse attendue 200) ==="
for rel in \
  channels/beta.json \
  channels/beta.sig \
  releases/v0.1.0-beta.1/manifest.json \
  releases/v0.1.0-beta.1/manifest.sig \
  releases/v0.1.0-beta.1/cerato-network-release.zip
do
  code="$(curl --silent --show-error --proto '=https' --max-time 12 \
    --output /dev/null --write-out '%{http_code}' \
    "https://51.210.223.57/cerato-releases/$rel")"
  printf '%s : HTTP %s\n' "$rel" "$code"
  [[ "$code" == 200 ]] || {
    echo "HTTPS reste indisponible : vérifier Nginx avant Installer." >&2
    exit 4
  }
done
echo "=== Vérification du canal signé par le moteur ==="
STATUS="$(/usr/local/sbin/cerato-updatectl check)"
printf '%s\n' "$STATUS" | python3 -c '
import json,sys
result=json.load(sys.stdin)
print(json.dumps({k:result.get(k) for k in
    ("installed_version","available_version","installable","reason_code","channel")},
    sort_keys=True))
assert result.get("reason_code")=="release_ready" and result.get("installable") is True, \
    "La release n est pas encore installable dans le panneau."
'
echo "Distribution HTTPS réparée. Installer uniquement depuis le panneau Cerato Network."
echo "Sauvegarde publisher : $BACKUP"
