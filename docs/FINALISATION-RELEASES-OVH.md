# Dernière étape — publication des releases sur l'IP OVH

## État réellement confirmé sur RISE-1 au 31 octobre 2026

Le résultat retourné par `install_same_host_releases.py --install` confirme :

- `selected_vhosts=1`
- `trusted_ip_certificate=true`
- `config_modified=true`
- `https://51.210.223.57/cerato-releases/` configuré dans Nginx
- sauvegarde : `/var/backups/cerato-network-inplace/nginx-releases/20261031T110532Z`
- **aucune** release signée publiée
- **aucune** clé de signature créée

Il ne faut pas relancer l'installateur Nginx : il refusera à juste
titre une deuxième insertion. L'URL du canal peut renvoyer **404** tant
qu'aucune publication n'a été faite.

## Workflow réel de distribution

1. **Préparer** le code Web compatible `RISE-1 / 8787` sur une copie privée
   des fichiers approuvés. Préparer un overlay de seulement
   `web/app.js`, `web/style.css` et `compat.json`, avec un
   `from_versions` cohérent avec l'état affiché par l'updater
   (actuellement `v0.0.0` pour « Installation historique »).
2. **Construire** sur CERATO-BUILD-01 une archive et un manifeste non signés,
   avec `tools/release_pipeline.py prepare`, en conservant le répertoire de
   sortie privé (`chmod 700`).
3. **Approuver et signer** la release sur un hôte ou compte de signature
   indépendant : `tools/release_pipeline.py sign`, puis
   `tools/channel_index.py` pour produire `beta.json` et `beta.sig`.
   Ne jamais transférer la clé privée sur le serveur OVH ou dans GitHub.
4. **Vérifier le lot public**, avant publication, sur l'hôte de build :
   ```bash
   python3 tools/stage_signed_static_release.py \
     --release /CHEMIN/SIGNATURES-APPROUVEES/v0.1.0-beta.1 \
     --channels /CHEMIN/SIGNATURES-APPROUVEES/channels \
     --public-key /CHEMIN/CLE-PUBLIQUE-APPROUVEE.pub \
     --channel beta \
     --destination /CHEMIN/NOUVEAU-LOT-PUBLIC
   ```
   Cette commande **ne copie rien sur OVH**. Elle refuse les signatures
   incorrectes, les index expirés et les ZIP qui ne correspondent pas
   exactement à une release visuelle RISE-1. Le chemin de sortie ne doit
   pas exister. Elle n'utilise pas la clé privée.
5. **Publier** le dossier `releases/<version>/` en lecture seule sur
   `/srv/cerato-releases/public/cerato-releases/releases/`, puis publier
   la paire `channels/beta.json` / `channels/beta.sig` comme un instantané
   cohérent. Les deux fichiers du canal doivent rester signés et
   correspondre au manifeste. Une version publiée ne doit jamais changer.
6. **Initialiser une fois** sur OVH la source et la clé publique
   vérifiée indépendamment (empreinte SHA-256 du DER OpenSSL) :
   ```bash
   sudo python3 ~/Cerato-Network/tools/configure_live_release_source.py \
     --url https://51.210.223.57/cerato-releases \
     --public-key /CHEMIN/CLE-PUBLIQUE-APPROUVEE.pub \
     --fingerprint EMPREINTE-DER-SHA256-APPROUVEE \
     --channel beta
   ```
7. **Tester sans installer** via `sudo /usr/local/sbin/cerato-updatectl check`,
   puis vérifier dans le navigateur
   **Mises à jour → Rechercher une mise à jour**. Le bouton Installer ne
   devient actif qu'après vérification cryptographique du paquet et du
   format de compatibilité.

**Toutes les valeurs /CHEMIN/ et l'empreinte sont des exemples, pas des clés
existantes. Ne pas exécuter ces commandes en remplaçant par des fichiers
inventés.** La clé publique doit être approuvée séparément.

## Points qui empêchent encore de déclarer « terminé »

- Aucune vraie clé de signature indépendante n'a été provisionnée.
- Aucune release de l'interface historique actuellement en service n'a été
  approuvée, signée et publiée.
- Le premier test d'installation puis rollback depuis l'interface Cerato n'a
  pas été réalisé.
- Le basculement Owner/Admin/User + TOTP est un chantier distinct toujours
  en préproduction. Ne pas désactiver HTTP Basic ni l'ancienne connexion
  avant les tests HTTP de toutes les routes et une restauration prouvée.

Une fois la clé et le canal mis en service, les versions ultérieures compatibles
pourront être installées depuis l'onglet Mises à jour, sans connexion SSH
récurrente.
