# Contrôles d'authentification Cerato Network après l'audit RISE-1

## Résultats observés le 30 octobre 2026

RISE-1 : `source_hashes_match=true` et `adapter_design_ready=true`. L'ancien analyseur voyait le `do_GET` mais indiquait 13 routes non classées dans `do_POST`. Cela pouvait être dû à une délégation des requêtes dans une autre fonction, et **ne prouve ni l'absence des routes ni leur sécurité**.

CERATO-BUILD-01 : les 2 tests d'analyse des handlers ont réussi. Les tests `test_legacy_auth_api.py` et `test_live_session_guard.py` ne se lançaient pas avec le Python système en raison du module manquant `argon2`. Le script d'inspection live lancé sur BUILD-01 a correctement refusé de fonctionner, car le backend en production existe seulement sur RISE-1.

## A. Sur CERATO-BUILD-01 uniquement

```bash
cd ~/Cerato-Network
git pull --ff-only origin feature/secure-accounts
python3 -m venv .venv
.venv/bin/python -m pip install -r security/requirements.txt
bash scripts/test-auth-on-vps.sh
```

Les dépendances sont installées dans `.venv`, pas globalement. Si `venv` manque, installer `python3-venv` sur **le VPS de build uniquement**, puis recréer l'environnement. Ne jamais lancer `scripts/bootstrap-dev.sh` sur RISE-1.

Si tous les tests du lot réussissent, cela valide seulement les simulations. Les tests réseau/intégration, l'authentification réelle et le rollback restent à prouver.

## B. Sur le serveur OVH RISE-1 uniquement

```bash
cd ~/Cerato-Network
git pull --ff-only origin feature/secure-accounts
python3 integrations/check_live_auth_cutover.py
python3 integrations/inspect_live_handler_flow.py
```

Le second audit suit maintenant les appels `self.methode()` et les fonctions globales locales qu'un handler HTTP appelle. Il présente :
- `direct_conditional_routes` : routes dans le handler lui-même ;
- `conditional_routes` : routes trouvées dans les fonctions potentiellement atteignables ;
- `reachable_delegate_counts` : nombre de méthodes/fonctions locales suivies ;
- `reachable_call_counts` : nombre d'appels identifiés sur le graphe d'appels.

**Attention :** des appels `check_session` visibles ne prouvent pas qu'ils précèdent toutes les opérations sensibles ; l'analyse est syntaxique uniquement. Les routes non connues ne sont pas affichées dans le rapport.

## Étape suivante avant déploiement

La branche contient les adaptateurs `security/legacy_auth_api.py` et `security/live_session_guard.py`, mais ils **ne sont pas raccordés au backend actif**. Une revue locale de l'ordre d'exécution des méthodes et de la politique CSRF, un test E2E de l'ancien/nouveau login et des opérations IPv4/NAT sont obligatoires. Ne pas activer la migration du compte owner, ni déployer les nouveaux écrans ou remplacer les fichiers Web de production à cette étape.

RISE-1 continue d'utiliser son panneau sur `8787`. Dell `10.77.0.2`, l'Additional IP OVH, WireGuard, nftables et NAT ne sont pas modifiés par ces scripts.
