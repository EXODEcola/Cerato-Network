# Déploiement et releases — Cerato Network

## Responsabilités

| Système | Responsabilité |
|---|---|
| GitHub `EXODEcola/Cerato-Network` | Git, branches `main` et `develop`, revues, tags, changelog |
| `CERATO-BUILD-01` (VPS/VM de compilation existant) | Tests, compilation, compression, manifestes, signatures |
| Stockage HTTPS des artefacts (à configurer) | Diffusion des releases déjà préparées par le VPS |
| Serveur RISE-1 | Vérification de signature, sauvegarde, installation, healthcheck, restauration |
| Machines Dell et autres nœuds | Installation initiale et mises à jour des agents |

**Interdiction de compiler, compresser ou signer sur GitHub Actions.** Aucun workflow GitHub Actions n'est requis pour la publication.

## Flux cible

1. Développer sur `develop`, tester sur une instance non productive, puis valider le passage sur `main`.
2. Créer un tag `vX.Y.Z` dans GitHub.
3. Le service de build, exécuté sur `CERATO-BUILD-01`, récupère le tag exact par accès GitHub en lecture seule.
4. Le service lance les tests, compile et génère une archive immuable.
5. Le service calcule SHA-256, produit un manifeste de version, puis le signe avec Ed25519.
6. La machine de build publie l'archive et le manifeste signé sur le stockage HTTPS prévu.
7. L'updater du RISE-1 vérifie provenance, signature, SHA-256, compatibilité, espace disque, puis sauvegarde et applique la mise à jour.
8. Si le service ne redémarre pas correctement, restauration immédiate. Les fichiers WireGuard, règles NAT et pare-feu ne sont jamais écrasés par une simple mise à jour de l'interface.

**État au 30 octobre 2026 :** document d'architecture. Le service de build Cerato Network, le stockage HTTPS et le client updater externe ne sont pas encore déployés ni testés ensemble. L'ancien kit local doit être adapté car il faisait appel à GitHub Releases/Actions.

## Accès minimaux à prévoir

- GitHub : accès **lecture** du dépôt pour la machine de build et droits d'écriture GitHub pour les développeurs uniquement.
- Build VPS : un compte de service dédié, sans mot de passe réutilisé, une clé de signature Ed25519 hors du dépôt et permissions de publication sur le stockage HTTPS.
- RISE-1 : seulement la **clé publique de vérification**, un accès HTTPS en lecture au stockage et un service updater local restreint.
- Aucune clé privée, aucun mot de passe SSH ou token à transmettre dans le chat ni à mettre dans le dépôt.

## Séparation des canaux

- Stable : tags `vX.Y.Z`, publication après validation.
- Bêta : tags `vX.Y.Z-beta.N`, opt-in explicite depuis Cerato Network.
- Retour arrière : restauration de la sauvegarde locale sans réinitialiser le réseau.

## Préconditions production

- Capturer l'état actuel de Cerato Network et vérifier les sauvegardes.
- Tester `check`, téléchargement, signature, installation et rollback sur une machine de développement.
- Conserver l'accès de secours SSH/console OVH.
- Ne pas lier le déploiement de l'interface au dépannage UDP du RISE-1.
