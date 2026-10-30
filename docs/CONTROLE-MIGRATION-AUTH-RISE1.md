# Migration Owner/Admin/User — contrôle de compatibilité du RISE-1

**Statut : développement seulement.** Les scripts de ce lot n'activent pas les comptes, ne modifient ni le service Web 8787 ni le réseau, et ne publient aucune release.

## Résultat de l'inventaire du 30 octobre 2026

- Le panneau réel possède `do_GET`, `do_POST`, `check_session`, `read_body` et `send_json`.
- Il expose 19 routes API et neuf sections réseau : vue d'ensemble, IPv4, machines, NAT, pare-feu, topologie, logs, paramètres et mises à jour.
- Les routes historiques `/api/login` et `/api/logout` devront être entièrement désactivées au basculement ; elles ne doivent pas être un chemin secondaire vers l'administration.
- Les empreintes du backend et du frontend observées sont consignées dans `integrations/rise1_2026-10-30_baseline.json`. Un changement d'empreinte impose une revue préalable, même si les noms de routes restent identiques.

## Contrôle de compatibilité, lecture seule

Sur le RISE-1 (pas d'installation, pas de sudo) :

```bash
cd ~/Cerato-Network
git pull --ff-only origin feature/secure-accounts
python3 integrations/check_live_auth_cutover.py
```

`adapter_design_ready=true` signifie uniquement que la structure correspond à l'inventaire vérifié. Le script retourne **toujours** `production_cutover_ready=false` : les preuves de sécurité et de non-régression manquent encore. Le contrôle signale les routes manquantes, les routes inattendues (sans afficher leurs noms), les fonctions absentes et une dérive des empreintes.

Sur CERATO-BUILD-01, exécuter les tests isolés :

```bash
python3 -m unittest discover -s tests -p 'test_live_auth_cutover.py' -v
python3 -m unittest discover -s tests -p 'test_live_session_guard.py' -v
python3 -m unittest discover -s tests -p 'test_legacy_policy.py' -v
```

## Préparation backend

`security/live_session_guard.py` fournit `authorize_legacy_request` et `project_legacy_status`. Son intégration au service 8787 doit être réalisée **avant** chaque action `ceratoctl`, `ipctl`, NAT, tunnel, IP, mise à jour ou export. Le backend doit extraire une nouvelle session depuis un cookie sûr, vérifier l'origine/CSRF puis appeler la fonction de garde. Le service ne doit pas utiliser l'ancienne session pour créer un acteur Owner/Admin/User.

Le rôle `user` ne peut lire que `/api/status` après projection **côté serveur**. Les routes sensibles et toutes les mutations sont refusées. `AuthStore.actor()` vérifie l'activation du 2FA des sessions administrateur et propriétaire avant de retourner leur identité.

**Limite actuelle :** la source en production `/opt/cerato-network/backend/server.py` n'est pas dans le dépôt de développement. L'inventaire ne révèle que des noms de routes et des points d'entrée, pas leurs conditions d'exécution. Il est impossible de garantir l'intégration sans audit manuel local du backend actuel.

## Conditions du basculement contrôlé

1. Auditer localement les handlers `check_session`, `do_GET`, `do_POST`, `send_json` et leurs chemins secondaires, sans exporter code sensible ni secrets.
2. Connecter AuthStore et la politique RBAC à **toutes** les routes du panneau réel ; refuser par défaut les routes non revues.
3. Tester owner (unique), admin, user lecture seule, MFA/TOTP, CSRF, ancien mot de passe, ancienne session, révocation, anonymisation des réponses, restauration et rollback.
4. Adapter la nouvelle interface à toutes les pages réseau actuelles (IPv4, NAT, pare-feu, machines et tunnels, topologie, mises à jour), sans remplacer le backend par `gateway/http_api.py`.
5. Construire sur CERATO-BUILD-01 un overlay compatible avec le service existant, approuver puis signer une release, et valider sa restauration automatique en cas d'échec.
6. Seulement ensuite, basculer atomiquement le système de session et retirer l'authentification historique. Ne jamais activer l'assistant owner sur le panneau actuel sans la migration éprouvée.

**Hors périmètre :** IP principale OVH, Additional IP `54.37.165.151` en mode `local-nat`, WireGuard `wg-cerato`, tunnel Dell `10.77.0.2`, nftables, règles NAT, routes, accès SSH et bases de données actuelles.

Ne pas relancer d'installateur et ne pas remplacer le backend live avec les composants de développement de cette branche.
