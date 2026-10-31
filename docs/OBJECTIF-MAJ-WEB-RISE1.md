# Cerato Network — clarification du circuit de mise à jour

**Règle du projet : ne jamais demander une intervention sur CERATO-BUILD-01.**
Le service de build de Cerato existant reste hors périmètre. Les nouveaux
workflows de ce dépôt ne sont pas la preuve qu'une VM Build est connectée ;
aucun SSH, service ou runner de la VM n'est modifié.

**Serveur autorisé pour l'initialisation unique : RISE-1, OVH 51.210.223.57.**
Le panneau Graphite et le moteur de mises à jour sont déjà installés.
Nginx expose le chemin public `/cerato-releases/` avec certificat valide.
Le script `integrations/activate_live_updates.py` vérifie et raccorde
uniquement la source signée au moteur existant.

## Avant tout lancement

Le script **ne génère aucune clé privée**. Une clé publique Ed25519
préalablement approuvée et son empreinte vérifiée indépendamment sont
indispensables. La source officielle et une release signée ne sont **pas**
créées par le script.

Quand la clé publique est déjà présente sur OVH, l'initialisation peut
être faite en une seule ligne dans le SSH de RISE-1 :

```bash
cd ~/Cerato-Network && git pull --ff-only origin feature/secure-accounts && sudo python3 integrations/activate_live_updates.py --install --public-key /CHEMIN/PUBLIC-APPROUVEE.pub --fingerprint EMPREINTE-SHA256-DER-APPROUVEE --channel beta
```

Les valeurs ci-dessus sont volontairement des **placeholders** : ne pas
exécuter la commande sans les vraies valeurs. Si
`/etc/cerato-network/release-source.json` est déjà configuré et valide,
la commande simplifiée suffit :

```bash
cd ~/Cerato-Network && git pull --ff-only origin feature/secure-accounts && sudo python3 integrations/activate_live_updates.py --install
```

Si aucune identité de signature approuvée n'existe encore, il n'est pas
possible de rendre installable une release en une commande sur OVH sans
affaiblir la politique de confiance. Le script refuse ce cas sans effet.

La vérification du canal peut renvoyer
`waiting_for_signed_release` : le moteur accepte la source et permet
de rechercher des mises à jour, mais aucune release compatible n'existe
encore. Cela **n'est pas** une activation bout en bout.

## Fonctionnement courant après l'initialisation

Développement et tests GitHub ; build hors du périmètre de maintenance ;
publication de releases **signées et compatibles** sur l'URL HTTPS OVH ;
puis les mises à jour sont recherchées et installées depuis le Web.
Aucune connexion SSH récurrente sur la VM Build n'est requise.
Pour les futurs correctifs de développement, un SSH ponctuel sur RISE-1
reste autorisé si nécessaire.

La migration Owner/Admin/User + 2FA reste un changement distinct nécessitant
des tests de bout en bout avant de retirer les protections historiques.
