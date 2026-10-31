#!/usr/bin/env bash
# Prepare an EMPTY, public-read-only directory for signed releases on OVH.
# No nginx edit, signing, restart, auth change, NAT, WireGuard or IP change.
# sudo bash scripts/prepare-same-host-releases.sh --check|--prepare
set -Eeuo pipefail
MODE="--check"
if (( $# > 0 )); then MODE="$1"; fi
[[ "$MODE" = "--check" || "$MODE" = "--prepare" ]] || { echo "Mode invalide." >&2; exit 2; }
BASE=/srv/cerato-releases/public/cerato-releases
for path in /srv/cerato-releases /srv/cerato-releases/public "$BASE" "$BASE/channels" "$BASE/releases"; do
    if [[ -L "$path" ]]; then
        echo "Chemin symbolique refusé : $path" >&2
        exit 1
    fi
    if [[ -e "$path" && ! -d "$path" ]]; then
        echo "Chemin non répertoire refusé : $path" >&2
        exit 1
    fi
done
echo "Destination statique : $BASE"
echo "URL prévue : https://51.210.223.57/cerato-releases/"
echo "Aucune release ni clé de signature générée."
if [[ "$MODE" = "--check" ]]; then
    echo "Contrôle terminé, aucune modification."
    exit 0
fi
if [[ "$EUID" -ne 0 ]]; then
    echo "Le mode --prepare requiert root." >&2
    exit 1
fi
install -d -o root -g root -m 0755 \
  /srv/cerato-releases \
  /srv/cerato-releases/public \
  "$BASE" "$BASE/channels" "$BASE/releases"
echo "Répertoires créés ou vérifiés. Nginx n'a pas été modifié."
echo "Ne servir que des releases signées et approuvées, jamais la clé privée."
