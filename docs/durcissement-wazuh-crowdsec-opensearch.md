# EYE — durcissement Wazuh + CrowdSec + OpenSearch

> « The Lidless Eye — nothing escapes my gaze. » Rien ne doit échapper au regard, et chaque affirmation de ce guide se vérifie par une commande.
> Version du 9 octobre 2026. Wazuh 4.14.4. Dépôt public : aucune adresse, aucun nom d'hôte interne, aucun secret.

## 1. Pourquoi ce guide va plus loin que les références

| | yeager/wazuh-hardening-guide | The Hacker News, « Wazuh for Zero Trust » (2024) | Documentation Wazuh, intégrations | **Ce guide** |
|---|---|---|---|---|
| Vérification automatique | Non : des chapitres à lire | Non : principes | Non | **Oui** : `audit/wazuh-durcissement-audit.sh`, 26 contrôles en lecture seule, verdict OK, KO ou À VOIR, avec preuve chiffrée |
| Enrôlement par mot de passe et certificat d'agent | Absent | Absent | — | M01, M02, M03 |
| Exposition des ports Docker, clé de cluster par défaut | Absent | Absent | — | M05, M08 |
| Qualité de détection (part des alertes génériques) | Absent | Absent | — | M14 |
| Santé réelle des intégrations (mail, GLPI) | Absent | Absent | Export seulement | M15, M16 |
| Doublons d'agents, agent conteneurisé privilégié, socket Docker | Absent | Absent | — | M18, A02, A03, A04 |
| Posture Zero Trust (SCA, inventaire, renseignement sur les menaces) | Principes listés | Oui, sans contrôle | — | M19 à M22 |
| CrowdSec relié à Wazuh dans les deux sens | Déploiement séparé | Absent | Absent | §4 |
| OpenSearch comme lac de données de sécurité (rétention, archives froides) | Sauvegarde ponctuelle | Absent | Export vers OpenSearch | §5 |

## 2. Contrôle : comment l'exécuter

```bash
# Sur l'hôte du manager (conteneurs wam_master et wai_indexer)
ssh <hôte-manager> 'bash -s manager wam_master wai_indexer' < audit/wazuh-durcissement-audit.sh
# Sur chaque hôte surveillé
ssh <hôte> 'bash -s agent' < audit/wazuh-durcissement-audit.sh
```

Lecture seule : aucune écriture, aucun redémarrage. Les secrets ne sont jamais affichés ; la clé de cluster, par exemple, est comparée par empreinte. Les adresses IP sont masquées dans la sortie.

## 3. État mesuré le 9 octobre 2026 (20:20 UTC)

Manager : **13 OK, 7 KO, 6 à voir**. Agents : 3 hôtes contrôlés, **11 KO**.

| Id | Constat | Gravité | Correction (ordre conseillé) |
|---|---|---|---|
| M01 | Enrôlement **ouvert sans mot de passe** : tout hôte qui joint le port 1515 peut devenir un agent et injecter des événements | **P0** | `openssl rand -hex 24` dans `/var/ossec/etc/authd.pass` (root:wazuh, 640), `<use_password>yes</use_password>` dans `<auth>`, redémarrage du manager. Les agents déjà enrôlés ne sont pas touchés ; un nouvel agent reçoit le mot de passe dans son propre `authd.pass` |
| M15 | Notification par mail : **19 825 échecs, 0 succès** (rejet anti-spam 554) | **P0** | Côté messagerie : déclarer le manager comme hôte de relais, filtre anti-spam désactivé. Côté script : file d'attente locale et décompte de l'anti-inondation **après** un envoi réussi seulement |
| M14 | **48 %** des alertes du jour (105 592 sur 217 011) tombent dans la règle générique 1002 « Unknown problem » | **P0** | Une règle dédiée par flux JSON (`schema`). Premier lot : `wazuh/rules/eye-fail2ban.xml` (101200 à 101204). Ensuite, recenser les sources de 1002 par `agent.name` et `location` |
| M18, A02 | Deux agents sur le même hôte (service système **et** conteneur) sur 2 serveurs : chaque événement compte double | P1 | Garder l'agent système. Reporter dans sa configuration les `<localfile>` du conteneur, puis retirer le conteneur |
| A03, A04 | Agent conteneurisé `privileged=true` avec le **socket Docker** monté : c'est un root complet de l'hôte, piloté par un conteneur | P1 | Réglé par la correction précédente (retrait du conteneur). À défaut : `privileged: false`, `cap_add` minimal, retrait de `docker.sock` (l'écoute Docker passe par le module `docker-listener` de l'agent système) |
| M16 | Le manager ne reconnaît pas l'autorité de certification interne : toute intégration HTTPS interne échoue (GLPI) | P1 | Copier le paquet d'autorités de l'hôte dans le conteneur (`/var/ossec/etc/yuz-ca.pem`) et le désigner dans l'intégration (`ca_bundle`) |
| M19 | SCA désactivé : aucune mesure de posture | P1 | `<sca><enabled>yes</enabled>` dans le groupe d'agents, politique CIS de l'OS |
| M17 | 1 agent déconnecté, 2 jamais connectés | P1 | `agent_control -l` : reconnecter ou supprimer (`manage_agents -r`) |
| A05 | Un serveur sans auditd ; son agent Wazuh existe mais tourne en conteneur, invisible depuis un compte hors du groupe `docker` (A00) | P1 | `auditd` + règles, puis agent depuis le dépôt officiel Wazuh, avec le mot de passe d'enrôlement (M01 d'abord) |
| A07, A08 | Compte d'exploitation avec `sudo` sans mot de passe et membre de `docker` | P1 | Compte réservé aux agents, sans `sudo` ni `docker`, limité à une liste de commandes. C'est une décision de gouvernance des accès |
| M13 | Seules les alertes sont archivées : impossible de reconstituer après coup | P2 | `<logall_json>yes</logall_json>` + rétention ISM (§5) |
| M20–M22 | Pas de liste de menaces propre ni de renseignement externe branché | P2 | CrowdSec (§4), puis MISP |
| M07, M02 | API avec la limite de tentatives par défaut ; aucun certificat d'agent exigé | P2 | `max_login_attempts` dans `api.yaml` ; `ssl_agent_ca` quand la PKI des agents existera |

### 3 bis. Les 48 % d'alertes « problème inconnu » : origine mesurée et correction

Sur 105 770 alertes de la règle 1002 du 09/10, deux sources font 90 % du volume :

| Part | Source | Nature réelle | Règle de classement (`wazuh/rules/eye-classement.xml`) |
|---|---|---|---|
| 61,8 % | Journal PostgreSQL du manager | **Incident d'exploitation** : une application interroge en boucle une table Odoo absente (`ir_module_module`), donc elle est branchée sur la mauvaise base | 101210 (niveau 5) ; 101211 (plus de 100 erreurs en 10 min) ; 101212 (autres erreurs SQL) |
| 28,3 % | Zeek DNS (capteur réseau) | Télémétrie | 101213, niveau 0 : conservée en archive, pas d'alerte |
| 2,2 % chacun | dbus, Gatus, journald | Télémétrie, disponibilité | 101216, 101217 |
| 1,4 % | Keycloak en DEBUG | Télémétrie (et niveau de journalisation à baisser en production) | 101215 |
| 2 × 1,0 % | Instantanés Fail2ban EYE (deux agents) | Télémétrie de couverture, en double | 101214 ; doublon traité par M18 |

**Résultat (installation le 09/10 à 20:26 UTC, lancée par Guillaume)** : la part de 1002 passe de **55 %** (19:50–20:25Z, 2 202 sur 3 996) à **4 %** (après 20:27Z, 181 sur 4 473). wazuh-logtest : un bannissement donne la règle 101201 (niveau 8, T1110), un instantané réel la règle 101214 (niveau 0). Le worker du cluster a reçu les fichiers. La règle 101211 (plus de 100 erreurs PostgreSQL en 10 minutes) s'est déclenchée 13 fois : l'incident d'exploitation continue. Objectif M14 (sous 10 %) atteint. L'incident PostgreSQL relève de l'exploitation : il faut corriger l'application fautive, pas masquer sa trace.

## 4. Architecture cible : Wazuh + CrowdSec + OpenSearch

```
            HÔTES SURVEILLÉS                                    CENTRALE
 ┌───────────────────────────────────┐            ┌──────────────────────────────────────────┐
 │ agent Wazuh (un seul, système)    │──1514 TLS─►│ manager Wazuh (règles, SCA, vulnérab.)   │
 │ agent CrowdSec (journaux ssh,     │            │   │ alertes            ▲ décisions       │
 │   nginx, mail)                    │──LAPI────► │ CrowdSec LAPI ◄──────────┘ (réponse      │
 │ bouncer pare-feu (nftables)  ◄────│─décisions──│   active Wazuh → cscli decisions add)    │
 │ Fail2ban (transition)             │            │   ▼                                      │
 └───────────────────────────────────┘            │ indexeur Wazuh = OpenSearch (chaud, 90 j)│
                                                  │   ▼ snapshots                            │
                                                  │ MinIO verrouillé, WORM (froid, 1 an)     │
                                                  │ restitution : mail [TALOS], GLPI, Grafana│
                                                  └──────────────────────────────────────────┘
```

**Dans les deux sens :**
1. **CrowdSec → Wazuh** : chaque décision CrowdSec est écrite en JSON (journal de `crowdsec` ou `cscli decisions list -o json` en tâche périodique) et lue par l'agent Wazuh. Une règle dédiée lui donne le groupe `crowdsec`, déjà classé « réseau » par `custom-supervision`. Les adresses bannies alimentent une **liste CDB** Wazuh, ce qui règle M21.
2. **Wazuh → CrowdSec** : une réponse active Wazuh (`<active-response>`) appelle `cscli decisions add --ip … --duration 4h --reason wazuh-<règle>` sur la LAPI. Un bannissement décidé par Wazuh est ainsi appliqué par tous les bouncers, sur tous les hôtes : c'est la micro-segmentation dynamique.
3. **Fail2ban** reste en place pendant la transition. CrowdSec le remplace prison par prison, une fois la détection équivalente prouvée sur des événements réels.

**Données vers l'extérieur : à décider.** Par défaut, CrowdSec partage ses signaux avec son API centrale (CAPI) et reçoit la liste communautaire. C'est un envoi vers un tiers : il faut un accord explicite. Sans cet accord, on retire `online_client` de la configuration (mode local seul).

## 5. OpenSearch comme lac de données de sécurité, sans nouveau composant

L'indexeur Wazuh **est** un OpenSearch. Pas besoin de second lac : il suffit de régler celui-ci.

1. **Chaud** : politique ISM sur `wazuh-alerts-*` et `wazuh-archives-*`, avec bascule quotidienne et suppression au bout de 90 jours.
2. **Froid** : dépôt de snapshots S3 vers MinIO avec verrouillage (`mc mb --with-lock`, `mc retention set --default COMPLIANCE 365d`), snapshot quotidien, restauration témoin mensuelle.
3. **Séparé** : l'OpenSearch d'Arkime (réseau) reste distinct. On les rapproche au tableau de bord, pas dans l'index.
4. **Exploitation** : les journaux applicatifs vont dans Loki/Grafana, pas dans l'indexeur de sécurité. La clé commune est `hostname` + `asset.glpi_id` + horodatage UTC.
5. **Export** (Splunk, Elastic, Security Lake) : seulement si un besoin apparaît, par la méthode « serveur » de la documentation Wazuh (`alerts.json`).

## 6. Restitution et preuve de bout en bout

Une détection ne compte que si elle arrive jusqu'à quelqu'un, et si cette arrivée se prouve.

- **Mail** : `[TALOS][P1…P4][catégorie]` (`wazuh/integrations/custom-supervision.py`).
- **Incident GLPI** : `wazuh/integrations/custom-glpi.py`.
  - Une alerte de niveau 8 ou plus crée un incident, avec les sept questions QQOQCCP remplies.
  - Dédoublonnage par `correlation_id`.
  - Plafond de 30 fiches par heure.
  - Test à blanc : `TALOS_DRYRUN=1`.
- **Preuve attendue** : pour un événement réel, la même identité de corrélation dans la source, l'alerte, le mail ou l'incident et l'observateur indépendant, puis le retour arrière (levée du bannissement).

## 7. Cadence
- Contrôle de durcissement : chaque semaine et après chaque changement. Un nouveau KO ouvre un incident GLPI.
- Restauration témoin des snapshots : chaque mois.
- Revue des règles génériques (M14) : chaque semaine, tant que leur part dépasse 10 %.
