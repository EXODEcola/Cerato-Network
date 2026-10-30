#!/usr/bin/env bash
# Build VM only. Prepare a release from an APPROVED, SIGNED Git tag.
# This script never handles a private release signing key and never deploys.
set -Eeuo pipefail

usage() {
  echo "Usage: bash scripts/prepare-approved-tag.sh vX.Y.Z /outside-checkout/output" >&2
  exit 2
}
[[ "$#" -eq 2 ]] || usage
VERSION="$1"
OUTPUT="$2"
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-((beta|rc)\.[0-9]+))?$ ]] || usage
[[ "$OUTPUT" == /* ]] || { echo "La destination doit être absolue." >&2; exit 2; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
[[ "$EUID" -ne 0 ]] || { echo "Refus : pas de build en root." >&2; exit 1; }
if command -v systemctl >/dev/null 2>&1 && systemctl -q is-active cerato-network-web.service; then
  echo "Refus : passerelle Cerato Network en cours d'exécution sur cet hôte." >&2
  exit 1
fi

[[ "$(git rev-parse --show-toplevel)" == "$ROOT" ]] || {
  echo "Le dépôt Git est inattendu." >&2; exit 1;
}

# The tag must be signed by an already-trusted maintainer key.
# No bypass flag; do not sign unapproved branches automatically.
git fetch --tags --prune --quiet origin
if ! git tag -v "$VERSION" >/dev/null 2>&1; then
  echo "Tag non signé ou signature GPG du mainteneur non approuvée : $VERSION" >&2
  exit 1
fi

HEAD_COMMIT="$(git rev-parse HEAD^{commit})"
TAG_COMMIT="$(git rev-parse "refs/tags/$VERSION^{commit}")"
[[ "$HEAD_COMMIT" == "$TAG_COMMIT" ]] || {
  echo "HEAD ne correspond pas au tag approuvé $VERSION." >&2; exit 1;
}

if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
  echo "Changements locaux suivis par Git : release refusée." >&2
  exit 1
fi

if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
  echo "Environnement .venv absent : lancer scripts/bootstrap-dev.sh sur le VPS de build." >&2
  exit 1
fi

echo "Tests complets pour le tag signé $VERSION..."
source "$ROOT/.venv/bin/activate"
bash "$ROOT/scripts/test-on-vps.sh"

# Packaging occurs only AFTER tests, without any private signing key.
python "$ROOT/tools/release_pipeline.py" prepare \
  --source "$ROOT" --output "$OUTPUT" --version "$VERSION"

echo "Archive sans signature préparée dans $OUTPUT."
echo "La revue et la signature sont des étapes séparées sous une identité autorisée."
echo "Ne PAS publier cette archive comme release tant qu'elle n'est pas signée et vérifiée."
