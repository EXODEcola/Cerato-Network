# Cerato Network — automatisation de développement et mise à jour OVH

## CERATO-BUILD-01 reste indépendant

**Aucune commande ni nouveau runner GitHub Actions ne doit être déployé sur
CERATO-BUILD-01.** Le workflow de build sur un runner `self-hosted` proposé
auparavant a été retiré du dépôt. L'automatisation Cerato Build existante
reste inchangée et ne peut pas être attestée à partir du seul dépôt GitHub.

Le workflow `.github/workflows/tests.yml` vérifie les commits et crée
uniquement un artefact de sources **non signé et non installable**, après
réussite des tests. Un échec de CI interdit cet artefact.

## Installation et mises à jour : RISE-1 uniquement

Le panneau historique OVH expose déjà `/cerato-releases/` via un HTTPS
valide. Un script de finalisation est publié :
`scripts/finalize-ovh-web-updates.sh`.

Il peut mettre à niveau les trois fichiers du moteur existant avec
sauvegarde et rollback, puis activer la source de confiance et un contrôle
périodique toutes les 6 heures. Le script refuse de modifier le serveur
quand une clé publique Ed25519 officielle n'a pas été approuvée.

### Précontrôle sans modification

```bash
cd ~/Cerato-Network && git pull --ff-only origin feature/secure-accounts && sudo bash scripts/finalize-ovh-web-updates.sh --check
```

Si une source est déjà approuvée et enregistrée, l'installation sur OVH
peut alors être déclenchée via une commande unique `--install`. Sinon,
fournir explicitement `--public-key` et `--fingerprint`, correspondant
à une clé publique officiellement approuvée (la **clé privée n'est jamais
installée sur OVH**). Un HTTP 200 ou un `git pull` ne constitue pas une
signature, et la clé ne peut pas être inventée pour débloquer l'interface.

Les releases visuelles **signées et compatibles** s'installent ensuite
depuis le panneau. Les contrôles périodiques sont en lecture seule et
n'installent jamais sans validation de l'administrateur.

Cette configuration ne modifie pas WireGuard, le Dell, les Additional IPv4,
NAT, le pare-feu, Nginx ou la double authentification historique.

## État de validation

Les scripts de contrôle, de vérification Ed25519 et de restauration sont
testés sur GitHub. Aucun déploiement signé de bout en bout n'est prouvé
sur RISE-1 tant que la véritable clé publique approuvée et la première
release signée ne sont pas disponibles. Les tests CI n'attestent pas
l'exécution sur un OVH ou sur une VM Cerato Build.
