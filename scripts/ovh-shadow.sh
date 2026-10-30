#!/usr/bin/env bash
# Cerato Network: transitional SHADOW deployment on the SAME OVH gateway.
# Installs only a SECOND Web service on 127.0.0.1:8788.
# Absolutely NO writes to WireGuard, nftables, routes, primary Web service,
# DNS, Nginx or OVH public-IP configuration.
#
# Usage (sudo from a trusted, reviewed Git checkout):
#   bash scripts/ovh-shadow.sh --check
#   sudo bash scripts/ovh-shadow.sh --install
#   sudo bash scripts/ovh-shadow.sh --update
#   sudo bash scripts/ovh-shadow.sh --status
#   sudo bash scripts/ovh-shadow.sh --remove
set -Eeuo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:---check}"
BASE="/opt/cerato-network-shadow"
RELEASES="$BASE/releases"
CURRENT="$BASE/current"
DATA="/var/lib/cerato-network-shadow"
USER_NAME="ceratoview"
SERVICE="cerato-network-shadow.service"
EXISTING_SERVICE="cerato-network-web.service"
SUDOERS="/etc/sudoers.d/cerato-network-shadow-readonly"
BACKUPS="/root/cerato-network-shadow-backups"
PORT=8788

usage() {
  echo "Usage: bash scripts/ovh-shadow.sh --check|--install|--update|--status|--remove" >&2
  exit 2
}

[[ "$MODE" =~ ^--(check|install|update|status|remove)$ ]] || usage

status() {
  echo "=== CERATO NETWORK : ETAT ACTUEL ==="
  systemctl is-active "$EXISTING_SERVICE" 2>/dev/null || true
  systemctl is-active "$SERVICE" 2>/dev/null || true
  if command -v wg >/dev/null 2>&1; then
    # No private keys, no WG config dump.
    wg show wg-cerato latest-handshakes 2>/dev/null || true
  fi
  if command -v curl >/dev/null 2>&1; then
    curl --max-time 3 -fsS http://127.0.0.1:8787/ -o /dev/null &&
      echo "Panneau existant 8787 : OK" || echo "Panneau existant : INDISPONIBLE"
    curl --max-time 3 -fsS http://127.0.0.1:$PORT/api/auth/setup-status &&
      echo || echo "Nouveau panneau 8788 : INDISPONIBLE"
  fi
  if [[ -L "$CURRENT" ]]; then
    echo "Shadow version: $(readlink "$CURRENT")"
  fi
}

preflight() {
  [[ -f "$ROOT/gateway/http_api.py" && -f "$ROOT/security/auth_store.py" &&
     -f "$ROOT/security/requirements.txt" && -f "$ROOT/web/app.js" ]] || {
    echo "Checkout incomplet. Opération refusée." >&2; exit 1;
  }
  if command -v git >/dev/null 2>&1; then
    local branch
    branch="$(git -C "$ROOT" branch --show-current 2>/dev/null || true)"
    echo "Branche source : ${branch:-non suivie}"
  fi
  if [[ -L "$ROOT" ]]; then
    echo "Checkout symbolique refusé." >&2; exit 1
  fi
  if ! systemctl -q is-active "$EXISTING_SERVICE"; then
    echo "REFUS : le panneau existant est inactif ou non détecté ($EXISTING_SERVICE)." >&2
    echo "On n'installe pas de nouvelle version avant diagnostic du service en production." >&2
    exit 1
  fi
  if ! curl -fsS --connect-timeout 2 --max-time 5 -o /dev/null http://127.0.0.1:8787/; then
    echo "REFUS : le panneau existant 8787 ne répond pas." >&2
    exit 1
  fi
  if [[ -e "$BASE" && -L "$BASE" || -e "$DATA" && -L "$DATA" ]]; then
    echo "Répertoire d'installation symbolique refusé." >&2; exit 1
  fi
  if [[ "$MODE" == "--install" && ( -e "$CURRENT" || -L "$CURRENT" ) ]]; then
    echo "Le panneau shadow est déjà installé. Utiliser --update." >&2; exit 1
  fi
  if [[ "$MODE" == "--update" && ! -L "$CURRENT" ]]; then
    echo "Aucun panneau shadow installé. Utiliser --install." >&2; exit 1
  fi
  if command -v ss >/dev/null 2>&1 && [[ "$MODE" == "--install" ]]; then
    if ss -Hltn 'sport = :8788' | grep -q .; then
      echo "REFUS : port 8788 déjà utilisé." >&2; exit 1
    fi
  fi
  echo "Vérification OK : service existant préservé, aucune règle réseau modifiée."
}

if [[ "$MODE" == "--check" ]]; then
  preflight
  status
  exit 0
fi
[[ "$EUID" == 0 ]] || { echo "Utiliser sudo pour $MODE" >&2; exit 1; }
if [[ "$MODE" == "--status" ]]; then status;exit 0;fi

if [[ "$MODE" == "--remove" ]]; then
  systemctl disable --now "$SERVICE" 2>/dev/null || true
  rm -f "/etc/systemd/system/$SERVICE" "$SUDOERS"
  systemctl daemon-reload
  echo "Service shadow supprimé. Les données de comptes, sauvegardes et versions restent conservées."
  echo "Le panneau principal, WireGuard et nftables n'ont pas été touchés."
  exit 0
fi

preflight
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python3 absent : installation refusée." >&2; exit 1
fi
if ! python3 -m venv --help >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3-venv
fi
if ! command -v sudo >/dev/null 2>&1; then
  echo "sudo requis pour les diagnostics lecture seule du moteur existant." >&2; exit 1
fi
if [[ ! -x /usr/local/sbin/ceratoctl ]]; then
  echo "REFUS : moteur existant ceratoctl introuvable." >&2; exit 1
fi
WG_BIN="$(command -v wg || true)"
if [[ "$WG_BIN" != "/usr/bin/wg" && "$WG_BIN" != "/usr/sbin/wg" ]]; then
  echo "REFUS : binaire WireGuard inattendu. Vérifier son emplacement." >&2; exit 1
fi
if ! id "$USER_NAME" >/dev/null 2>&1; then
  useradd --system --home "$DATA" --shell /usr/sbin/nologin "$USER_NAME"
fi
install -d -o "$USER_NAME" -g "$USER_NAME" -m 0700 "$DATA"
install -d -o root -g root -m 0755 "$BASE" "$RELEASES"
install -d -m 0700 "$BACKUPS"

# Read-only sudoers: the new Web service can never publish, remove peers,
# edit NAT or apply firewall configurations.
cat > "$SUDOERS" <<SUDO
Defaults:ceratoview env_reset
ceratoview ALL=(root) NOPASSWD: /usr/local/sbin/ceratoctl status
ceratoview ALL=(root) NOPASSWD: $WG_BIN show wg-cerato latest-handshakes, $WG_BIN show wg-cerato transfer
SUDO
chmod 0440 "$SUDOERS"
visudo -cf "$SUDOERS" >/dev/null

STAMP="$(date -u +%Y%m%dT%H%M%SZ)-$$"
NEW="$RELEASES/$STAMP"
mkdir -m 0755 "$NEW"
old=""
[[ ! -L "$CURRENT" ]] || old="$(readlink "$CURRENT")"
rollback() {
  echo "ÉCHEC : restauration du panneau shadow précédent." >&2
  if [[ -n "$old" ]]; then
    ln -sfn "$old" "$BASE/.restore-$$"
    mv -Tf "$BASE/.restore-$$" "$CURRENT"
    systemctl restart "$SERVICE" || true
  else
    systemctl disable --now "$SERVICE" 2>/dev/null || true
    rm -f "$CURRENT"
  fi
}
trap rollback ERR

# Backup of current management files only; never publish on GitHub.
if [[ "$MODE" == "--install" ]]; then
  tar -czf "$BACKUPS/pre-shadow-$STAMP.tgz" \
    -C / opt/cerato-network/backend opt/cerato-network/web \
    etc/cerato-network 2>/dev/null || {
      echo "Sauvegarde de l'existant échouée. Annulation." >&2; exit 1;
    }
  chmod 0600 "$BACKUPS/pre-shadow-$STAMP.tgz"
fi

cp -a "$ROOT"/gateway "$ROOT"/security "$ROOT"/updates "$ROOT"/network \
      "$ROOT"/tools "$ROOT"/web "$NEW"/
if find "$NEW" -type l -print -quit | grep -q .; then
  echo "Fichiers symboliques inattendus dans la source. Refus." >&2; exit 1
fi
python3 -m venv "$NEW/venv" || {
  echo "python3-venv absent : installation automatique de python3-venv."
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3-venv
  python3 -m venv --clear "$NEW/venv"
}
"$NEW/venv/bin/python" -m pip install --disable-pip-version-check \
  --only-binary=:all: -r "$NEW/security/requirements.txt"
"$NEW/venv/bin/python" -m compileall -q "$NEW"/gateway "$NEW"/security "$NEW"/updates
if command -v node >/dev/null 2>&1; then node --check "$NEW/web/app.js"; fi

if [[ ! -f "/etc/systemd/system/$SERVICE" ]]; then
  cat > "/etc/systemd/system/$SERVICE" <<UNIT
[Unit]
Description=Cerato Network Shadow - authenticated Web preview on existing gateway
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=$USER_NAME
Group=$USER_NAME
WorkingDirectory=$CURRENT
Environment=CERATO_DEV_AUTH_ONLY=1
Environment=CERATO_DEV_LOOPBACK_HTTP=1
Environment=CERATO_PORT=$PORT
Environment=CERATO_AUTH_DB=$DATA/accounts.sqlite3
Environment=CERATO_WEB_ORIGIN=https://network.example.org
Environment=CERATOCTL_BIN=/usr/local/sbin/ceratoctl
Environment=CERATO_WG_BIN=$WG_BIN
ExecStart=$CURRENT/venv/bin/python $CURRENT/gateway/http_api.py
Restart=on-failure
RestartSec=3
UMask=0077
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=$DATA
[Install]
WantedBy=multi-user.target
UNIT
fi
# Atomic symlink to a new code directory, without modifying the old panel.
ln -s "releases/$STAMP" "$BASE/.next-$$"
mv -Tf "$BASE/.next-$$" "$CURRENT"
systemctl daemon-reload
systemctl enable --now "$SERVICE"
systemctl restart "$SERVICE"
sleep 1
systemctl is-active --quiet "$SERVICE"
curl -fsS --connect-timeout 2 --max-time 8 "http://127.0.0.1:$PORT/api/auth/setup-status" >/dev/null
# Recheck original Web service after the new service has started.
systemctl is-active --quiet "$EXISTING_SERVICE"
curl -fsS --connect-timeout 2 --max-time 8 -o /dev/null http://127.0.0.1:8787/
trap - ERR

echo "CERATO NETWORK SHADOW : VERSION INSTALLÉE SUR LE MÊME OVH"
echo "Ancien panneau 127.0.0.1:8787 : CONSERVÉ"
echo "Nouveau panneau 127.0.0.1:$PORT : OK"
echo "Données du nouveau compte : $DATA (privé)"
echo "Commande du code initial :"
echo "sudo -u $USER_NAME $CURRENT/venv/bin/python $CURRENT/security/cli.py --database $DATA/accounts.sqlite3 bootstrap-token"
echo "Accès depuis Windows : tunnel SSH local 8788 -> 127.0.0.1:8788"
echo "Pour les prochaines mises à jour provisoires : git pull sur OVH puis sudo bash scripts/ovh-shadow.sh --update"
echo "La chaîne de releases signées est encore en cours d'intégration."
