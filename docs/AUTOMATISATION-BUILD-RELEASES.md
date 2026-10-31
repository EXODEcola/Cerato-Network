# Cerato Network : liaison de build sans SSH par mise à jour

## Ce qui fonctionne déjà
La pull request vers `main` est testée par GitHub Actions. Une archive
**de sources non signées** n'est produite qu'après validation des tests.
Deux exécutions identiques pour un même push/PR ont été supprimées.

## Automatisation du Build (mise en veille par défaut)
`.github/workflows/cerato-build.yml` se déclenche lors de la publication d'un
**tag annoté GPG** `vX.Y.Z` ou `vX.Y.Z-beta.N`.
Il n'utilise `CERATO-BUILD-01` que si :
- un runner GitHub Actions **self-hosted, Linux, X64, cerato-build** y est réellement enregistré ;
- la variable GitHub Actions `CERATO_NETWORK_BUILD_ENABLED` vaut `true` ;
- `CERATO_TRUSTED_TAG_FINGERPRINT` contient une empreinte GPG déjà
  approuvée et importée dans la trousse de confiance du compte runner.

**Aucune de ces trois conditions n'est prouvée par la configuration actuelle**
du dépôt. Nous n'avons pas configuré à distance ta VM ni changé son agent.
Sans ces prérequis, le job est volontairement **ignoré**, pas laissé en
file d'attente infinie et sans message trompeur « release publiée ».

Quand l'intégration existante est établie et activée, chaque nouveau tag
**approuvé** entraîne automatiquement le test et le paquetage sur
Cerato Build, sans demande de commande SSH à chaque mise à jour.
Le runner construit une **archive non signée**, à partir des octets du
tag ; aucune clé Ed25519 ne lui est transmise.

## Publication finale (reste distincte)
Une vraie release installable exige ensuite :
1. une **validation humaine** du paquet et de sa compatibilité RISE-1 ;
2. une signature Ed25519 sur une identité de signature indépendante ;
3. la publication de `manifest.json`, `manifest.sig`, archive et
   index de canal signé sur le HTTPS OVH ;
4. la clé publique épinglée sur RISE-1 et une vérification
   `cerato-updatectl check`.

Ce n'est qu'après ces étapes que le panneau
**Mises à jour → Rechercher → Installer** peut fonctionner. 
Le tag de source ne doit **jamais** être automatiquement interprété comme une
version de l'overlay 8787 actuel : le dépôt `web/` est différent de
l'interface Graphite déjà installée sur RISE-1. L'installer sans une
adaptation contrôlée pourrait casser l'interface.

**Politique** : aucune écriture WireGuard, NAT, firewall, IP,
backend historique, Nginx ou création de clé privée n'est réalisée par
les workflows de build. On ne fusionne pas une branche d'authentification
dont le cutover Owner/Admin/User + TOTP reste inachevé simplement
pour « avoir une nouvelle version ».
