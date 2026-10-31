# Héberger les releases signées sur la même IP HTTPS que Cerato Network

**Adresse administrative existante :** `https://51.210.223.57/`  
**Base de distribution choisie :** `https://51.210.223.57/cerato-releases/`

Ce choix est compatible avec le client de distribution actuel
(`updates/remote.py` et `tools/configure_live_release_source.py`).
Il **n'existe pas encore** de distribution à cette URL : la page d'accueil du
panneau n'est pas un dépôt de releases.

## Séparation des rôles

| Service | Hôte | Ce qui est autorisé |
| --- | --- | --- |
| Panneau Web | OVH RISE-1, port 443 vers service 8787 | Administration, protégée par authentification |
| Fichiers de releases | Nginx existant sur la même IP, sous `/cerato-releases/` | Téléchargement public **en lecture seule** des artefacts signés |
| Signataire Ed25519 | Hôte de signature distinct | Garde la clé **privée** et signe les index, manifestes et ZIP approuvés |
| Client des releases | RISE-1 | Possède seulement la clé **publique épinglée** par empreinte vérifiée |

L'absence de domaine supplémentaire ne change pas les contraintes de
**certificat TLS**. La connexion HTTPS sur l'IP doit présenter un certificat
public valide **pour l'adresse IP 51.210.223.57** (SAN de type IP). Une
exception ajoutée dans un navigateur ne suffit pas pour le client Python.
Ne pas utiliser `curl -k` ni désactiver la vérification TLS.

## Travail livré dans le dépôt (préparation, sans déploiement)

- `deploy/releases.same-host-location.conf` : **snippet** Nginx à inclure
  **dans le bloc HTTPS existant**, jamais comme deuxième serveur
  `listen 443`. Il autorise seulement les chemins des index, signatures,
  manifestes et ZIP de releases. Aucun script exécutable ni répertoire privé
  n'y est servi. Le `auth_basic off` est limité à cet emplacement public,
  pas aux pages et API Cerato.
- `scripts/prepare-same-host-releases.sh` : prépare uniquement les
  répertoires statiques vides, possédés par root. Ce script ne touche pas à
  Nginx, au service Web, à WireGuard, aux comptes ni aux routes.
- `tests/test_same_host_releases.py` : vérification de l'URL HTTPS
  supportée, des chemins attendus et de l'absence de reconfiguration réseau.

La mise en production Nginx **nécessite une vérification du bloc HTTPS
actuel** pour éviter d'écraser l'authentification ou la console existante.
Ne pas modifier le bloc serveur à l'aveugle.

## Préparation non destructive sur RISE-1

```bash
cd ~/Cerato-Network
git pull --ff-only origin feature/secure-accounts
sudo bash scripts/prepare-same-host-releases.sh --check
sudo bash scripts/prepare-same-host-releases.sh --prepare
```

Le chemin statique sera
`/srv/cerato-releases/public/cerato-releases/`. La création des répertoires
n'active pas le service public et **ne crée aucune release**.

Après revue du bloc HTTPS actif, incorporer le snippet
`deploy/releases.same-host-location.conf` **dans ce même bloc 443**.
Vérifier `sudo nginx -t` avant tout rechargement. Garder le rollback du
fichier Nginx, afin de revenir immédiatement à sa version antérieure.

Les fichiers signés publiés de manière atomique seront par exemple :

```text
https://51.210.223.57/cerato-releases/channels/beta.json
https://51.210.223.57/cerato-releases/channels/beta.sig
https://51.210.223.57/cerato-releases/releases/v0.1.0-beta.1/manifest.json
https://51.210.223.57/cerato-releases/releases/v0.1.0-beta.1/manifest.sig
https://51.210.223.57/cerato-releases/releases/v0.1.0-beta.1/cerato-network-release.zip
```

Ce sont des **formats de chemins** ; ils ne prouvent pas que les fichiers
existent. Il faut d'abord produire une release réellement compatible avec
le backend RISE-1, approuver et signer ses manifestes et son index sur
l'hôte de signature, puis publier un instantané de fichiers en lecture seule.
Ne jamais modifier les octets d'une release publiée sous le même numéro.

La mise à jour du panneau via son interface requiert ensuite un
provisionnement root **unique** de la source et de la clé publique,
après vérification indépendante de l'empreinte de la clé :

```bash
sudo python3 tools/configure_live_release_source.py \
  --url https://51.210.223.57/cerato-releases \
  --public-key /CHEMIN/CLE-PUBLIQUE-CONTROLEE.pub \
  --fingerprint EMPREINTE_SHA256_DER_VERIFIEE \
  --channel beta
```

Les deux derniers paramètres sont **des emplacements à remplacer par des
valeurs réellement approuvées**, jamais un identifiant inventé. Ne lancez
pas cette commande avant que les fichiers publics, la clé et le certificat
TLS soient validés. La clé privée ne doit jamais être copiée sur OVH.

## Ce qui ne doit pas être confondu avec la distribution

- Un domaine/IP HTTPS et une page de connexion ne constituent pas un index
  de releases, ni une signature Ed25519.
- Une URL en `https://` avec certificat invalide ne devient pas sûre
  simplement parce que le navigateur accepte l'exception.
- Le canal doit être renouvelé avant expiration de son index signé
  (maximum 7 jours, souvent 24 h), y compris quand aucune nouvelle
  version ne sort.
- Aucun code Owner/Admin/User ou 2FA en staging ne sera automatiquement
  installé via ces seuls répertoires.
- Le tunnel Dell `10.77.0.2`, l'Additional IP `54.37.165.151`,
  le NAT, le pare-feu et le backend actuel ne sont pas modifiés.
