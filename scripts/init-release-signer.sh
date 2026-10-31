#!/usr/bin/env bash
# ONE TIME: create the official release key on an isolated signing host,
# never on RISE-1, GitHub Actions, or the public HTTPS artifact server.
set -Eeuo pipefail
umask 077

MODE="${1:---check}"
[[ "$MODE" == "--check" || "$MODE" == "--init" ]] || {
  echo "Usage: --check | --init" >&2; exit 2;
}
[[ "$EUID" != 0 ]] || {
  echo "Refus : utiliser un compte de signature non-root dédié." >&2; exit 2;
}
# Refuse obvious attempts to create the private key on the OVH router.
if [[ -f /opt/cerato-network/backend/server.py ]] ||
   { command -v ip >/dev/null && ip -4 addr show 2>/dev/null | grep -q '51[.]210[.]223[.]57'; }; then
  echo "Refus : exécuter uniquement sur un signataire distinct du RISE-1." >&2
  exit 2
fi
command -v openssl >/dev/null || { echo "OpenSSL est requis." >&2; exit 2; }

STORE="$HOME/.local/share/cerato-network-signing"
PRIVATE="$STORE/release-ed25519.key"
PUBLIC="$STORE/release-ed25519.pub"
if [[ "$MODE" == "--check" ]]; then
  if [[ ! -f "$PUBLIC" || ! -f "$PRIVATE" ]]; then
    echo "Clé non initialisée sur ce signataire."
    exit 0
  fi
else
  if [[ -e "$PRIVATE" || -L "$PRIVATE" || -e "$PUBLIC" || -L "$PUBLIC" ]]; then
    echo "Une clé existe déjà. Rotation et récupération nécessitent une procédure contrôlée." >&2
    exit 2
  fi
  install -d -m 0700 "$STORE"
  [[ ! -L "$STORE" ]] || { echo "Répertoire symbolique refusé." >&2; exit 2; }
  PART_KEY="$STORE/.release-key-$$"
  PART_PUB="$STORE/.release-pub-$$"
  trap 'rm -f -- "$PART_KEY" "$PART_PUB"' EXIT
  openssl genpkey -algorithm Ed25519 -out "$PART_KEY"
  chmod 0600 "$PART_KEY"
  openssl pkey -in "$PART_KEY" -pubout -out "$PART_PUB"
  chmod 0644 "$PART_PUB"
  mv -n -- "$PART_KEY" "$PRIVATE"
  mv -n -- "$PART_PUB" "$PUBLIC"
fi
[[ -f "$PRIVATE" && ! -L "$PRIVATE" && -f "$PUBLIC" && ! -L "$PUBLIC" ]] || {
  echo "Fichiers de signature invalides." >&2; exit 2;
}
[[ "$(stat -c %a "$PRIVATE")" == 600 ]] || {
  echo "Permissions de la clé privée invalides (0600 requis)." >&2; exit 2;
}
FINGERPRINT="$(openssl pkey -pubin -in "$PUBLIC" -outform DER | sha256sum | cut -d' ' -f1)"
echo "Clé publique : $PUBLIC"
echo "Empreinte SHA-256 DER à vérifier indépendamment : $FINGERPRINT"
echo "La clé PRIVÉE reste sur cette machine ; ne jamais la copier sur OVH ou GitHub."
