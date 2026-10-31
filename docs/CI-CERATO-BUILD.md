# Validation GitHub et liaison Cerato Build — état vérifié

## Pourquoi des e-mails « Run failed » ont été reçus

Le commit `4806d02` du 31 octobre 2026 a introduit un test
`tests/test_live_visual_install_rollback.py`. GitHub Actions a signalé
un **échec de test Python**, sans aucun déploiement : le mock du statut de
l'updater retournait une configuration dépourvue du champ `channel`,
requis par `updates/live_controller.status()`. Cette erreur de
fixture a été réparée dans les commits suivants.

L'ancien `.github/workflows/tests.yml` se déclenchait **deux fois**
pour la même modification : sur `push` de
`feature/secure-accounts` et sur la pull request ouverte vers
`main`. Cela multipliait les notifications, y compris pour une
même erreur de test.

## Nouveau comportement, sans intervention sur la VM

- **PR vers main** : une validation automatique par commit ; plus de
  déclencheur supplémentaire sur chaque push de la branche de travail.
- **Push sur main** : revalidation du code effectivement fusionné.
- **workflow_dispatch** : contrôle manuel possible, mais jamais requis
  pour le cycle normal des PR.
- **Tests verts obligatoires** avant le job `build-handoff`.
- **build-handoff** crée automatiquement un instantané Git
  `cerato-network-source.tar.gz` et une preuve de provenance
  `handoff.json` (SHA du commit et SHA-256 de l'archive).
  Ces fichiers sont des **sources non signées et non installables**,
  conservées sept jours en artefact GitHub Actions.

L'archive est fabriquée avec `git archive HEAD`, donc uniquement depuis
les fichiers versionnés du commit testé. Elle ne contient pas les secrets
déployés sur le RISE-1. Le job n'a aucune clé de signature, aucun accès SSH
à CERATO-BUILD-01 ou à l'OVH et aucune permission d'écriture dans GitHub.

## Limite de l'automatisation

**Le dépôt Cerato-Network ne définit actuellement aucun job sur un runner
`self-hosted`, aucun appel à une API Cerato Build ni aucun workflow
de publication signée.** Son intégration réelle avec la VM de build peut
exister via un service externe, mais elle ne peut pas être vérifiée à partir
des seuls fichiers GitHub.

Ainsi, la réussite du job `build-handoff` signifie que les sources sont
prêtes à être consommées par la chaîne de build, **pas** qu'une compilation
a eu lieu sur la VM, qu'une clé de signature officielle existe, qu'une
release a été publiée sur OVH ou que le bouton Installer est disponible.

La bonne suite consiste à raccorder **le service automatique déjà présent
sur Cerato Build** à cet événement/artefact GitHub, après contrôle
des permissions et de la provenance. Ne pas demander à l'utilisateur de
générer des clés ou d'exécuter un script de build à chaque commit. Les
opérations de provisionnement des identités de signature restent
administratives et distinctes du fonctionnement récurrent.

## Conditions de déploiement toujours obligatoires

- Source et signatures Ed25519 valides, avec clé privée **hors OVH**.
- Release approuvée et exactement compatible avec le panneau
  historique RISE-1 / 8787.
- Sauvegarde et rollback fonctionnels.
- Aucun changement du Dell R530, WireGuard, Additional IPv4, NAT ou du
  firewall lors de la validation.
- La migration Owner/Admin/User + 2FA reste séparée et non activée en
  production tant que le basculement n'est pas intégralement testé.

Ne pas masquer ni désactiver les tests qui échouent : il faut corriger
le code avant la publication d'une release. Les notifications GitHub
sur une véritable erreur sont utiles, mais leur duplication ne l'est pas.
