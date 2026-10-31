# Comptes, première connexion et permissions — Cerato Network

## Principe validé

Aucun compte administrateur ou mot de passe par défaut livré avec le logiciel.

### Première connexion

1. Le serveur démarre en mode **non initialisé** : toutes les API réseau sont fermées.
2. L'administrateur ayant un accès SSH au RISE-1 lance `sudo cerato-network setup-token`, qui génère un **code aléatoire valable 15 minutes, utilisable une fois**. Il ne s'affiche jamais dans les journaux ni dans le dépôt.
3. Sur l'interface HTTPS, l'assistant initial demande le code, **l'adresse e-mail souhaitée**, le **mot de passe souhaité** et sa confirmation.
4. Création atomique du seul compte `owner`. Le code est invalidé, l'assistant disparaît et le panneau passe en mode connexion.
5. Si le compte owner existe déjà, il est **impossible** de réactiver ce parcours, même depuis l'API publique. Les procédures de récupération sont limitées à une commande SSH privilégiée et journalisée.

Éviter qu'un tiers prenne possession du serveur pendant son initialisation est une exigence de sécurité obligatoire.

### Rôles

| Action | Propriétaire principal | Administrateur | Utilisateur |
| --- | :---: | :---: | :---: |
| Voir le tableau de bord (données non secrètes) | ✅ | ✅ | ✅ |
| Voir les IP / routes détaillées, clés publiques et logs sensibles | ✅ | ✅ | ❌ |
| Modifier tunnels, IP, NAT, pare-feu | ✅ | ✅ | ❌ |
| Créer des utilisateurs | ✅ | ✅ | ❌ |
| Créer des administrateurs | ✅ | ✅ | ❌ |
| Modifier les autres administrateurs (hors owner) | ✅ | ✅ | ❌ |
| Modifier / désactiver / supprimer un compte utilisateur | ✅ | ✅ | ❌ |
| Modifier **le compte principal** | **son propriétaire uniquement** | ❌ | ❌ |
| Changer ses propres identifiants (mot de passe actuel requis) | ✅ | ✅ | ✅ |
| Régler mises à jour et restaurations réseau | ✅ | ✅ | ❌ |
| Définir un nouveau propriétaire principal depuis le Web | ❌ | ❌ | ❌ |

- **Un seul `owner`**, immuable par les API de gestion. Ni un administrateur ni un utilisateur ne peut le renommer, modifier, rétrograder ou désactiver.
- Les administrateurs peuvent gérer **tous les autres comptes**, y compris d'autres administrateurs. Ils ne peuvent pas s'attribuer le rôle owner.
- Un administrateur ne peut pas supprimer son propre compte par l'API de gestion (utiliser la modification personnelle dédiée).
- Les comptes `user` consultent un **modèle de données expurgé par le backend**. Le frontend ne décide jamais de cacher un secret à lui seul.
- Aucune création anonyme de compte après l'initialisation : seul owner/admin peut créer des membres.

### Sécurité

- Argon2id et mot de passe d'au moins 14 caractères ; aucune persistance du mot de passe en clair.
- Sessions aléatoires, jeton **haché** en base, cookie `Secure; HttpOnly; SameSite=Strict`, expiration et invalidation côté serveur ; antiforgery CSRF.
- Déconnexion, invalidation de sessions lors d'un changement de mot de passe ou de désactivation.
- Limitation des essais de connexion sur IP et compte ; messages d'erreur neutres, journaux d'audit sans secrets.
- Vérification d'autorisation **sur chaque endpoint API**, y compris mises à jour, diagnostics, NAT et export.
- 2FA TOTP : intégrer avant mise en production (obligatoire pour owner et admin).
- Accès HTTPS obligatoire et possibilité de verrouillage/reprise depuis la console OVH.

### Compatibilité / migration

Le panneau actuel a une authentification à mot de passe unique. **Ne jamais la remplacer ni ouvrir l'assistant d'initialisation sans sauvegarde et migration testée.** La future migration devra demander une confirmation locale par SSH, supprimer l'ancien secret d'authentification après validation, et invalider toutes les anciennes sessions.

### Réseau et confidentialité

Le compte utilisateur peut lire : statut de passerelle, santé des machines, noms autorisés, version de l'agent, dernier contact et trafic agrégé. Il ne peut pas lire : clés WireGuard, IP privées ou publiques détaillées, adresses d'endpoint, contenu des règles de filtrage, jetons d'enrôlement, logs d'authentification, secrets de déploiement.

## Contrat API prévu

| Méthode | Route | Permission |
| --- | --- | --- |
| `GET` | `/api/auth/setup-status` | Publique, réponse booléenne uniquement |
| `POST` | `/api/auth/setup` | Code d'initialisation SSH, une seule fois |
| `POST` | `/api/auth/login` | Publique (anti-bruteforce) |
| `POST` | `/api/auth/logout` | Authentifié + CSRF |
| `GET` | `/api/auth/me` | Authentifié |
| `PATCH` | `/api/auth/me` | Authentifié + ancien mot de passe |
| `GET` | `/api/accounts` | owner/admin |
| `POST` | `/api/accounts` | owner/admin |
| `PATCH` | `/api/accounts/{id}` | owner/admin, cible différente du owner et de soi |
| `DELETE` | `/api/accounts/{id}` | owner/admin, cible différente du owner et de soi |
| `GET` | `/api/status` | Authentifié (projection selon le rôle) |
| `POST` | `/api/network/*` | owner/admin + CSRF |
| `POST` | `/api/updates/*` | owner/admin + CSRF, validation en deux temps |

## Déploiement

Cette spécification ne modifie rien sur le RISE-1. Le code d'authentification et son intégration devront être testés contre le backend existant et la politique Nginx HTTPS avant publication stable.
