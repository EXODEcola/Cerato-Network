# Correction permissions Nginx (release signée déjà publiée)

Le miroir OVH exécuté avec `UMask=0077` crée les fichiers signés
en mode `0600` et les répertoires de générations en `0700`.
Nginx `www-data` ne peut donc pas ouvrir `channels/beta.json`
(404) ni les manifestes (403), malgré une validation Ed25519 correcte.

**Correctif pérenne** : `tools/publish_signed_release.py` force
`0644` sur les cinq artefacts publiés (manifeste, signature, ZIP,
index et signature de canal) et `0755` sur les répertoires publics
de génération, même avec `umask 077`.

**Réparation de l'existant** :
`tools/repair_published_signed_permissions.py` exige d'abord la
validation cryptographique de la release et de l'index contre la clé
publique locale épinglée, l'index non expiré, l'absence de symlinks
arbitraires et la propriété root. Il ne fait que changer les modes
de la génération active et de la release signée (jamais `chmod -R`).

Depuis le SSH **Cerato Network OVH seulement** :

```bash
cd ~/Cerato-Network && git pull --ff-only origin main && \
sudo bash scripts/repair-signed-public-downloads.sh
```

Le script sauvegarde et remplace uniquement le module Python de
publication dans l'updater déjà installé, puis applique le correctif
aux fichiers publics **après validation cryptographique**. Il réalise
le contrôle HTTP(S) et la recherche des mises à jour. Il ne modifie
pas Nginx, WireGuard, NAT, IP, authentification ou la VM Cerato Build.

**Ne cliquer sur Installer** dans l'interface qu'après obtention de
`HTTP 200` sur `beta.json`, `beta.sig` et le manifeste, puis
`installable: true` dans `cerato-updatectl check`.
