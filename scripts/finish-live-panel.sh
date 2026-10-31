#!/usr/bin/env bash
# One-time controlled graphite + signed-updater engine bootstrap on RISE-1.
# Does not modify /etc/wireguard, /etc/cerato-network, IPs, NAT or nftables.
# sudo bash scripts/finish-live-panel.sh --check | --install
set -Eeuo pipefail
umask 077
MODE="--check"
if (( $# > 0 )); then MODE="$1"; fi
[[ "$MODE" == "--check" || "$MODE" == "--install" ]] || { echo "Usage: --check | --install" >&2; exit 2; }
[[ "$EUID" -eq 0 ]] || { echo "Cette commande requiert sudo." >&2; exit 2; }

REPO="$(cd "$(dirname "$0")/.." && pwd)"
LIVE=/opt/cerato-network
ENGINE="$LIVE/updater"
SERVICE=cerato-network-web.service
UPDATE_SERVICE=cerato-network-update.service
BACKUP_ROOT=/var/backups/cerato-network-inplace/graphite-bootstrap

# The HTTP process may start later than systemctl reports active.
# Keep probes local and never print the sensitive web response.
wait_for_panel(){
  local count
  for ((count=1;count<=30;count++)); do
    if systemctl is-active --quiet "$SERVICE" &&
       curl -fsS --max-time 2 -o /dev/null http://127.0.0.1:8787/; then
      echo "Port 8787 disponible après $count contrôle(s)."
      return 0
    fi
    if systemctl is-failed --quiet "$SERVICE"; then
      echo "Service Web en échec pendant le démarrage." >&2
      return 1
    fi
    sleep 1
  done
  echo "Le panneau n'a pas répondu sur 127.0.0.1:8787 après 30 contrôles." >&2
  return 1
}

for rel in backend/server.py web/app.js web/style.css; do
  [[ -f "$LIVE/$rel" && ! -L "$LIVE/$rel" ]] || {
    echo "Panneau existant absent ou lien symbolique : $rel" >&2; exit 2;
  }
done
for rel in integrations/prepare_live_visual_refresh.py \
           integrations/patch_live_update_center.py \
           integrations/check_live_auth_cutover.py \
           integrations/rise1_2026-10-30_baseline.json \
           themes/cerato-graphite.css \
           updates/live_controller.py updates/remote.py tools/build_release.py; do
  [[ -f "$REPO/$rel" && ! -L "$REPO/$rel" ]] || {
    echo "Code de préparation manquant : $rel" >&2; exit 2;
  }
done
for rel in updates/live_controller.py updates/remote.py tools/build_release.py; do
  [[ -f "$ENGINE/$rel" && ! -L "$ENGINE/$rel" ]] || {
    echo "Moteur de releases initial non présent : $rel" >&2; exit 2;
  }
done
[[ -x /usr/local/sbin/cerato-updatectl && ! -L /usr/local/sbin/cerato-updatectl ]] || {
  echo "Contrôleur d'updates non installé." >&2; exit 2;
}
command -v node >/dev/null 2>&1 || { echo "Node.js requis pour valider le JavaScript." >&2; exit 2; }
systemctl is-active --quiet "$SERVICE" || { echo "Panneau 8787 arrêté : opération refusée." >&2; exit 2; }
if systemctl -q is-active "$UPDATE_SERVICE"; then
  echo "Installation de release en cours : opération refusée." >&2; exit 2;
fi
curl -fsS --max-time 6 -o /dev/null http://127.0.0.1:8787/ || {
  echo "Le panneau existant ne répond pas sur 8787 avant modification." >&2; exit 2;
}
for rel in backend/server.py web/app.js web/style.css; do
  [[ "$(stat -c '%u' "$LIVE/$rel")" == 0 ]] || {
    echo "Le fichier Web n'appartient pas à root : $rel" >&2; exit 2;
  }
done
[[ "$(stat -c '%u' "$ENGINE/updates/live_controller.py")" == 0 ]] || {
  echo "Le contrôleur existant n'appartient pas à root." >&2; exit 2;
}

SCRATCH="$(mktemp -d -t cerato-graphite-stage-XXXXXXXX)"
cleanup(){ rm -rf -- "$SCRATCH"; }
trap cleanup EXIT
python3 "$REPO/integrations/prepare_live_visual_refresh.py" \
  --source "$LIVE" --destination "$SCRATCH/staged"
node --check "$SCRATCH/staged/web/app.js"
python3 -m py_compile "$REPO/updates/live_controller.py" "$REPO/updates/remote.py" "$REPO/tools/build_release.py"

config_hashes(){
  for file in /etc/cerato-network/config.json /etc/wireguard/wg-cerato.conf; do
    [[ -f "$file" && ! -L "$file" ]] || {
      echo "Source de vérité réseau absente : $file" >&2; return 2;
    }
  done
  sha256sum /etc/cerato-network/config.json /etc/wireguard/wg-cerato.conf | sha256sum | awk '{print $1}'
}
NETWORK_BEFORE="$(config_hashes)"
echo "Contrôle de compatibilité : OK."
echo "Fichiers prévus : web/app.js, web/style.css, moteur de mises à jour (3 fichiers)."
echo "Configuration réseau avant : $NETWORK_BEFORE"
if [[ "$MODE" == "--check" ]]; then
  echo "Aucun fichier de production modifié. Pour appliquer : --install"
  exit 0
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)-$$"
BACKUP="$BACKUP_ROOT/$STAMP"
install -d -o root -g root -m 0700 "$BACKUP_ROOT" "$BACKUP"
while IFS='|' read -r source target; do
  mkdir -p "$BACKUP/$(dirname "$target")"
  cp -p "$source" "$BACKUP/$target"
done <<EOF
$LIVE/web/app.js|web/app.js
$LIVE/web/style.css|web/style.css
$ENGINE/updates/live_controller.py|updater/updates/live_controller.py
$ENGINE/updates/remote.py|updater/updates/remote.py
$ENGINE/tools/build_release.py|updater/tools/build_release.py
EOF

CHANGED=0
rollback(){
  code="$?"
  trap - ERR
  if [[ "$CHANGED" -eq 1 ]]; then
    echo "Erreur : restauration des fichiers Web et du moteur précédent." >&2
    for rel in web/app.js web/style.css; do
      cp -p "$BACKUP/$rel" "$LIVE/$rel" || true
    done
    for rel in updates/live_controller.py updates/remote.py tools/build_release.py; do
      cp -p "$BACKUP/updater/$rel" "$ENGINE/$rel" || true
    done
    if ! systemctl restart "$SERVICE"; then
      echo "AVERTISSEMENT : le redémarrage après restauration a échoué." >&2
    fi
    if ! wait_for_panel; then
      echo "La restauration des fichiers est terminée mais la disponibilité HTTP reste à vérifier via la console OVH." >&2
      systemctl show "$SERVICE" -p ActiveState -p SubState -p Result -p ExecMainStatus --no-pager >&2 || true
    else
      echo "Ancienne interface restaurée et HTTP 8787 à nouveau disponible." >&2
    fi
  fi
  exit "$code"
}
trap rollback ERR

CHANGED=1
install -o root -g root -m 0644 "$SCRATCH/staged/web/app.js" "$LIVE/web/app.js"
install -o root -g root -m 0644 "$SCRATCH/staged/web/style.css" "$LIVE/web/style.css"
install -o root -g root -m 0755 "$REPO/updates/live_controller.py" "$ENGINE/updates/live_controller.py"
install -o root -g root -m 0644 "$REPO/updates/remote.py" "$ENGINE/updates/remote.py"
install -o root -g root -m 0644 "$REPO/tools/build_release.py" "$ENGINE/tools/build_release.py"
systemctl restart "$SERVICE"
if ! wait_for_panel; then
  echo "Échec du contrôle après déploiement ; état systemd (sans secrets) :" >&2
  systemctl show "$SERVICE" -p ActiveState -p SubState -p Result -p ExecMainStatus --no-pager >&2 || true
  false
fi
node --check "$LIVE/web/app.js"
python3 -m py_compile "$LIVE/backend/server.py"
[[ "$(config_hashes)" == "$NETWORK_BEFORE" ]] || {
  echo "Empreintes de configurations réseau différentes : déploiement annulé." >&2
  false
}
"/usr/local/sbin/cerato-updatectl" status |
  python3 -c 'import json,sys; s=json.load(sys.stdin); assert "installed_version" in s and "configured" in s'
CHANGED=0
trap - ERR
echo "Interface Graphite et moteur de mises à jour installés sur le Web 8787."
echo "Sauvegarde locale : $BACKUP"
echo "IMPORTANT : le canal HTTPS signé n'est pas activé par ce bootstrap."
