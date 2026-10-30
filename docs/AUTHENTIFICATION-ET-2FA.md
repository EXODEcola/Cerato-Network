# Connexion sécurisée et double authentification

Statut : **branche de développement**, non déployée sur la passerelle existante.

## Première utilisation

1. Un administrateur SSH lance `python security/cli.py bootstrap-token` sur le système d'installation pour obtenir un jeton de configuration temporaire.
2. Dans l'interface HTTPS, l'utilisateur définit librement son **e-mail principal** et son **mot de passe** (14 caractères minimum) et fournit ce jeton.
3. Le compte `owner` est créé une seule fois. Aucune session privilégiée n'est encore ouverte.
4. Lors du premier login, l'interface fournit une clé TOTP et une URI `otpauth://` à enregistrer dans une application d'authentification.
5. Le propriétaire saisit son code TOTP : **seulement à cette étape** le backend émet un cookie de session `HttpOnly`, `Secure` et `SameSite=Strict`.
6. Les huit codes de secours sont affichés **une seule fois**. Il faut les stocker hors du serveur dans un gestionnaire sécurisé.

Les administrateurs supplémentaires doivent suivre le même processus TOTP à leur première connexion. Les utilisateurs en lecture seule n'ont jamais accès à une route administrative, même en forgeant leurs requêtes API.

## Protections en place dans le noyau de développement

- Argon2id et base SQLite privée chmod 0600.
- Aucun mot de passe ni compte administrateur par défaut.
- Un propriétaire unique verrouillé par contrainte en base et contrôle API.
- Défis MFA valables 5 minutes, au plus cinq tentatives par défi.
- Limitation de la création de défis à six par compte sur 15 minutes.
- Rejet des codes TOTP déjà utilisés par ce compte.
- Codes de récupération à usage unique.
- Révocation de sessions après changement de mot de passe, changement de rôle ou réinitialisation 2FA.
- Validation de l'origine HTTP et du jeton CSRF pour les modifications.
- Serveur de test strictement sur `127.0.0.1` ; mode HTTP local opt-in seulement.
- Aucune mutation du réseau ni des mises à jour par l'API de développement.

## Récupération SSH du propriétaire

```bash
python security/cli.py owner-status
python security/cli.py owner-reset
python security/cli.py owner-reset-mfa
```

Ces commandes nécessitent une session terminal autorisée sur la passerelle (ou l'instance de test) et un accès en lecture/écriture à la base de comptes. `owner-reset-mfa` révoque toutes les sessions du propriétaire, supprime l'ancien facteur TOTP et ses codes de secours ; le prochain login exige l'enrôlement d'un nouveau facteur.

Les co-administrateurs peuvent réinitialiser le MFA **d'autres administrateurs**, mais ni celui du propriétaire ni celui de leur propre compte depuis la gestion des comptes. Tout changement est audité.

## Vérifier les développements sur un VPS de build

```bash
git clone https://github.com/EXODEcola/Cerato-Network.git
cd Cerato-Network
git switch feature/secure-accounts
bash scripts/bootstrap-dev.sh
```

Le bootstrap installe venv, Node.js et dépendances manquantes et lance les tests unitaires et HTTP. Il refuse une machine dont le service `cerato-network-web.service` est actif. Ne pas le lancer sur un serveur de production.

### Mises à jour Web (consultation)

L'endpoint `GET /api/updates` permet à un administrateur de connaître l'état d'une release déposée localement. Pour les tests isolés, fournir :

- `CERATO_RELEASE_DIR` : dossier contenant `manifest.json`, `manifest.sig` et `cerato-network-release.zip`.
- `CERATO_RELEASE_PUBKEY` : clé publique Ed25519 correspondant au build autorisé.
- `CERATO_INSTALLED_VERSION` : version locale (ex. `v0.1.0-beta.1`).
- `CERATO_RELEASE_CHANNEL` : `stable` ou `beta`.

La vérification de signature et du contenu se fait côté serveur. **Aucune installation n'est déclenchée** par cette API de développement. Le bouton Installer reste désactivé en attendant les tests E2E de rollback, de distribution HTTPS et de déploiement des agents.

## Points à auditer avant une version publique stable

- Chiffrement des secrets TOTP au repos et rotation des clés.
- Tests d'intégration proxy Nginx et HTTPS, politique stricte de cookies.
- Attaques de charge, récupération de session, horloge TOTP, verrouillage et CSRF.
- Configuration initiale en cas de coupure ou migration d'une installation déjà existante.
- Authentification de la machine de build et signature des paquets isolée des tests non fiables.
- Autorisation réelle des actions de routage/WireGuard/nftables et correctif de sécurité lors du rollback.
- Validation des agents distants et de leurs permissions après expiration/révocation.
