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
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-((dev|beta|rc)\.[0-9]+))?$ ]] || usage
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

# Require an out-of-band pinned fingerprint, never learn signing trust
# from the public repository or a freshly fetched arbitrary GPG key.
TRUSTED_FP="${CERATO_TRUSTED_TAG_FINGERPRINT:-}"
[[ "$TRUSTED_FP" =~ ^[A-Fa-f0-9]{40}([A-Fa-f0-9]{24})?$ ]] || {
  echo "CERATO_TRUSTED_TAG_FINGERPRINT doit contenir l'empreinte GPG approuvée." >&2
  exit 1
}
TRUSTED_FP="${TRUSTED_FP^^}"
git fetch --tags --prune --quiet origin
VERIFY_OUTPUT="$(git verify-tag --raw "$VERSION" 2>&1)" || {
  echo "Tag non signé ou signature GPG invalide : $VERSION" >&2
  exit 1
}
if ! printf '%s\n' "$VERIFY_OUTPUT" | grep -Eq "\\[GNUPG:\\] VALIDSIG ${TRUSTED_FP}([[:space:]]|$)"; then
  echo "Signature non liée à la clé GPG explicitement approuvée." >&2
  exit 1
fi

HEAD_COMMIT="$(git rev-parse HEAD^{commit})"
TAG_COMMIT="$(git rev-parse "refs/tags/$VERSION^{commit}")"
[[ "$HEAD_COMMIT" == "$TAG_COMMIT" ]] || {
  echo "HEAD ne correspond pas au tag approuvé $VERSION." >&2; exit 1;
}

if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
  echo "Changements locaux détectés : release refusée." >&2
  exit 1
fi

# The existing VPS can keep its .venv; an Actions runner must use an isolated
# venv OUTSIDE the checkout, since actions/checkout may clean untracked files.
BUILD_PYTHON="${CERATO_BUILD_PYTHON:-$ROOT/.venv/bin/python}"
if [[ ! -x "$BUILD_PYTHON" ]]; then
  echo "Python de build isolé manquant ; utiliser CERATO_BUILD_PYTHON vers un venv approuvé." >&2
  exit 1
fi
BUILD_PYTHON="$(realpath "$BUILD_PYTHON")"
if [[ "$BUILD_PYTHON" == "$ROOT/"* ]] && [[ "${CERATO_BUILD_PYTHON:-}" != "" ]]; then
  echo "Le Python explicite d'un runner doit résider hors du checkout." >&2
  exit 1
fi

# A signed Git tag identifies an exact committed tree. Only that tree must be
# tested and packaged; NEVER package arbitrary checkout files or ignored data.
WORKTREE="$(mktemp -d -t cerato-approved-tag-XXXXXXXX)"
cleanup() { rm -rf -- "$WORKTREE"; }
trap cleanup EXIT

echo "Extraction isolée du tag signé $VERSION..."
git archive --format=tar "$VERSION" | tar -xf - -C "$WORKTREE"

echo "Tests complets sur les fichiers exacts du tag approuvé..."
export PATH="$(dirname "$BUILD_PYTHON"):$PATH"
bash "$WORKTREE/scripts/test-on-vps.sh"

# The approved snapshot, not the git working directory, becomes the ZIP.
"$BUILD_PYTHON" "$WORKTREE/tools/release_pipeline.py" prepare \
  --source "$WORKTREE" --output "$OUTPUT" --version "$VERSION"

echo "Archive sans signature préparée dans $OUTPUT."
echo "La revue et la signature sont des étapes séparées sous une identité autorisée."
echo "Ne PAS publier cette archive comme release tant qu'elle n'est pas signée et vérifiée."
