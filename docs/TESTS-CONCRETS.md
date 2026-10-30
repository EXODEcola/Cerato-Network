# Tests concrets de préproduction — Cerato Network

## Où en est-on ?

- **64 tests unitaires et simulés réussis** sur CERATO-BUILD-01 le 30 octobre 2026 (rapport transmis par le testeur).
- Nouvelle suite **de tests d'intégration live**, avec **vraies sockets TLS et HTTP sur localhost**, publiée ensuite sur la branche de développement. Elle reste **à exécuter et valider** sur CERATO-BUILD-01.
- RISE-1 : service de production non modifié. Dell R530 : WireGuard toujours à vérifier en situation réelle. Ne pas confondre connexion à la VM et tunnel opérationnel.

## Niveau A : préproduction live sur CERATO-BUILD-01

Cette phase ne nécessite ni root, ni adresse publique, ni manipulation du système :

1. Génère une paire Ed25519 de test et deux clés TLS temporaires.
2. Construit de **vraies archives ZIP signées** pour trois versions de démonstration.
3. Lance un vrai serveur HTTPS sur un port éphémère de l'interface 127.0.0.1.
4. Fait une connexion HTTPS réelle avec vérification d'un certificat auto-signé temporaire approuvé uniquement par le test ; l'absence de confiance TLS est rejetée.
5. Récupère l'index stable signé, le manifeste signé, l'archive ZIP réelle, puis vérifie la signature et SHA-256.
6. Extrait les fichiers dans une arborescence privée, bascule le lien de version et interroge un vrai endpoint HTTP /health local.
7. Met une version volontairement défectueuse en place et vérifie que le retour arrière restaure la version fonctionnelle.
8. Enregistre deux machines **logiques** dans la file d'updates ; l'une récupère une release et rapporte sa réussite, l'autre reste hors ligne/en attente.
9. Corrompt volontairement une archive sur le serveur HTTPS de test : le client doit la refuser sans l'installer.

Toutes les opérations utilisent un TemporaryDirectory et des serveurs sur 127.0.0.1 seulement. **Aucun accès SSH distant, modification d'IP, firewall, tunnel WireGuard ou redémarrage du système**. Le service HTTP /health est un **serveur de démonstration** qui lit la version active ; ce n'est pas encore la véritable API Cerato Network en production.

La politique de l'URL HTTPS en production exige le port 443 ; le test utilise un patch **local au processus de test** pour autoriser un port éphémère sur localhost. Les restrictions du code de production restent inchangées.

### Une seule commande sur la VM de build

Si le dépôt est déjà cloné :

~~~bash
cd ~/Cerato-Network
bash scripts/update-dev.sh
bash scripts/test-preprod-live.sh
~~~

Le premier script récupère les sources et repasse les tests de base. Le second relance ces tests puis effectue la **nouvelle phase de préproduction HTTP/TLS réellement connectée**.

L'exécution doit se faire sous le compte **cerato**, pas root, sur **CERATO-BUILD-01**. Le script refuse les machines où cerato-network-web.service est actif.

### Critères de validation

- Tous les tests unitaires existants passent.
- Tous les tests dans integration/ passent, sans FAIL ni ERROR.
- Le test de téléchargement récupère réellement le ZIP via TLS puis réussit l'installation **dans un sandbox**, avec /health égal à la bonne version.
- Le test d'archive altérée et celui du mauvais certificat TLS échouent proprement (tests de refus verts).
- Une version défectueuse déclenche un rollback, sans modifier le système hôte.
- L'agent logique hors ligne reste marqué queued, pas updated.

Ne pas activer la production simplement parce que ces tests passent.

## Niveau B : diagnostic UDP réel entre deux machines

Lorsqu'on est prêt à tester le trajet IP réel, il faut **deux terminaux distincts** et une capture de paquets sur le RISE-1. Le diagnostic reste non destructif.

### Sur le RISE-1 (destination), en SSH

Installer tcpdump si nécessaire via maintenance autorisée, puis écouter :

~~~bash
sudo timeout 30 tcpdump -nni any 'udp and (port 51820 or port 51821)' -c 20
~~~

**Ne pas modifier nftables ou la configuration WireGuard pendant ce test.** Vérifier d'abord que les IPs et ports sont bien ceux du serveur cible.

### Sur CERATO-BUILD-01 (machine émettrice), pendant la capture

~~~bash
cd ~/Cerato-Network
python3 scripts/udp-probe.py --target IP_PUBLIQUE_DE_LA_PASSERELLE --port 51820 --count 5
~~~

Remplacer IP_PUBLIQUE_DE_LA_PASSERELLE par l'IP connue et autorisée du serveur. L'outil envoie seulement cinq datagrammes marqués et affiche le résultat de l'envoi. Il ne lance aucune connexion WireGuard et n'ouvre pas de port permanent.

- Paquets visibles dans tcpdump : le trafic UDP arrive sur le serveur. Vérifier ensuite les règles hôtes/OVH, WireGuard, clés et endpoints.
- Paquets non visibles : inspecter le chemin réseau, les pare-feu OVH, la bonne IP de destination, les interfaces et les éventuels filtres amont.
- La réussite de sendto sur la VM ne prouve jamais la réception ; seule la capture destination la confirme.

Le PowerShell de l'ancien journal, exécuté sous Bash, est la cause de ses erreurs. Utiliser ce script **Python Linux** évite de reproduire cette confusion.

## Niveau C : vraie préproduction sur deux serveurs distincts

Encore à réaliser : déployer une seconde instance **Cerato Network en environnement de préproduction**, sur une VM non productive, avec agent réel, WireGuard propre au test, Nginx HTTPS, certificats, sous-réseau dédié et règles nftables isolées. Test de l'enrôlement, de la connexion, de la télémétrie et d'une release avec vrai redémarrage de service + watchdog.

**Il ne faut pas utiliser la passerelle RISE-1 en production comme cible du premier test de redémarrage ou d'auto-update.** Attendre la fin du développement de l'agent et la validation du rollback indépendant.

## Condition de publication stable

Une mise à jour ne sera déclarée prête pour la production qu'après tests des composants réellement déployés, backups, migrations de base, TLS, authentification MFA, fonctionnement des opérations réseau autorisées et restauration en cas de coupure. Le travail sur la VM de build ne remplace pas cet audit.
