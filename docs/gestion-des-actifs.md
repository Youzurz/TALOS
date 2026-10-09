# TALOS — gestion des actifs, conservation des preuves, notification

> Dépôt **public** : ne jamais y pousser de résultat d'audit, d'IP, de nom d'hôte
> interne, d'identifiant ou d'ETAT.json. Seuls des scripts et gabarits génériques vont ici.

## 1. Rôle de chaque outil

| Couche | Outil | Rôle pour les actifs |
|---|---|---|
| Référentiel (ce qui **doit** exister) | **GLPI** | CMDB : matériel, logiciels, licences, équipements réseau (SNMP), certificats, domaines, bases de données, Appliances (services métier), contrats |
| | **Terraform** | Ressources cloud déclarées ; l'état (`tfstate`), versionné dans MinIO, garde l'historique |
| Observé (ce qui existe **réellement**) | **Wazuh syscollector** | Hardware, OS, Packages, Networks, Ports, Processes, Users, Groups, Services, Browser extensions, Windows updates — **état courant uniquement** |
| | **Velociraptor** | Photo forensique à un instant T (processus, connexions, persistance, fichiers) |
| | **Arkime** | Réseau observé (qui parle à qui, sur quels ports) ; PCAP écrasés quand le disque est plein |
| Détection / blocage | **Wazuh** (FIM, SCA, vulnérabilités, règles), **CrowdSec**, **fail2ban** | Atteintes à la configuration, aux comptes, aux fichiers, au réseau |
| Réponse | **TheHive** ← **Cortex** ← **MISP** | Dossiers, observables, enrichissement, IOC |
| Conservation | **OpenSearch**, **Cassandra**, **MinIO** | Alertes et états (OpenSearch), dossiers (Cassandra), preuves et snapshots (MinIO, verrouillage WORM) |

La gestion des actifs revient à comparer en continu **GLPI/Terraform (déclaré)** à
**Wazuh/Velociraptor/Arkime (observé)**. Chaque écart est soit un oubli dans l'inventaire,
soit une atteinte.

| Actif | Déclaré | Observé | Détection | Historique |
|---|---|---|---|---|
| Hardware | GLPI | Wazuh Hardware | — | onglet *Historique* de GLPI |
| Software / Packages | GLPI | Wazuh Packages | Wazuh vulnérabilités, SCA | GLPI, dpkg.log |
| Processes / Services | GLPI Appliances | Wazuh, Velociraptor | règles Wazuh | collecte Velociraptor |
| Identity (users/groups) | GLPI / annuaire | Wazuh Users, Groups | Wazuh (auth, sudo) | alertes Wazuh |
| Network / Open ports | GLPI, pare-feu Terraform | Wazuh Ports, Arkime | CrowdSec, fail2ban | Arkime (limite disque) |
| Cloud | Terraform | `terraform plan -refresh-only` | — | versions du tfstate |
| Équipements | GLPI (SNMP) | syslog → Wazuh | Wazuh | GLPI |
| Container | GLPI agent | Wazuh docker-listener | Wazuh | alertes Wazuh |
| Mobile | GLPI agent Android | — (hors Wazuh) | — | GLPI |
| Data | GLPI Bases de données + classification | FIM | FIM, MinIO WORM | diffs FIM, versions MinIO |
| Secure (clés, certificats) | GLPI Certificats | FIM `~/.ssh`, `/etc/ssl` | FIM, SCA | diffs FIM (`nodiff` sur les secrets) |
| Immatériel (domaines, licences, réputation) | GLPI | MISP, CrowdSec | Cortex | TheHive |

## 2. Ce que montrent les captures du tableau de bord Wazuh

| Écran | Constat | Cause probable | Correction |
|---|---|---|---|
| SCA → Inventory « No agent selected » | Normal | Cet écran demande de choisir un agent | Choisir un agent. S'il n'y a aucun agent, voir l'audit |
| Maps « Create your first map » | Aucune carte | Module de carte jamais configuré | Facultatif : carte des `srcip` de `wazuh-alerts-*` |
| Docker, filtre `cluster.name`, « No results » (24 h) | Aucun événement Docker | `docker-listener` non activé sur les agents | `wazuh/shared/serveurs/agent.conf` |
| Filtre `cluster.name` par serveur | Peut-être **un manager Wazuh par serveur** | Le sélecteur d'API bascule d'un manager à l'autre | À confirmer par l'audit ; cible : un seul manager, ou un seul indexeur partagé |

## 3. Les atteintes sont-elles conservées, avec l'état d'avant ?

Pas par défaut :

- syscollector ne garde **que l'état courant** (remplacé à chaque inventaire, toutes les heures) ;
- FIM garde le contenu d'avant uniquement avec `report_changes="yes"` ;
- CrowdSec purge au bout de 7 jours, fail2ban au bout de 1 jour ;
- Arkime écrase les PCAP les plus anciens ;
- sans `logall_json`, seuls les événements qui déclenchent une alerte sont conservés ;
- **GLPI** (onglet Historique) et un **tfstate versionné** sont les seules sources
  fiables de l'état d'avant, s'ils étaient en place avant l'atteinte.

## 4. Classification, tags, notification vers supervision@youzurz.com

```
agent Wazuh ──labels asset.* (agent.conf du groupe)──► alerte (agent.labels)
     │
manager ─► integratord ─► custom-supervision (niveau Wazuh ≥ 7)
                               ├─ catégorie : compromission | comptes | authentification |
                               │              integrite | vulnerabilite | conformite |
                               │              messagerie | conteneur | reseau | disponibilite | autre
                               ├─ gravité   : 1 à 5 (voir le tableau ci-dessous)
                               ├─ tags      : N<gravité>, gravite:<nom>, catégorie,
                               │              asset.*, mitre:Txxxx, group:*
                               ├─ filtre    : gravité < niveau_min → aucun message
                               ├─ anti-inondation : 3/h par (règle, agent), 60/h au total
                               └─ SMTP ─► boîte de supervision
                                          Objet : [TALOS][N5 critique][compromission][messagerie] …
                                          En-têtes : X-TALOS-Level / -Severity / -Category /
                                                     -Asset / -Tags / -Rule
```

### Échelle de gravité : 1 à 5

**1 est le moins grave, 5 le plus grave** — c'est l'inverse de l'échelle `level` de Wazuh,
qui va de 0 à 15, et de l'ancienne notation P1-P4.

| Gravité | Nom | Niveau Wazuh | Notifié par défaut |
|---:|---|---|---|
| **5** | critique | ≥ 14 | **oui** |
| **4** | majeur | 12-13 | **oui** |
| 3 | moyen | 9-11 | non |
| 2 | faible | 6-8 | non |
| 1 | information | ≤ 5 | non |

Un actif portant `asset.criticality=haute` monte d'un cran : sur un serveur sensible, un fait
ordinaire ailleurs mérite d'être vu. Une tentative de force brute (niveau Wazuh 10) passe ainsi
de 3 à 4 sur le serveur de messagerie, et devient notifiable.

Le seuil se règle avec `niveau_min` (4 par défaut). **En dessous du seuil, l'alerte n'est pas
perdue** : elle reste classée, taguée et consultable dans Wazuh ; seul l'envoi du message est
supprimé. Mettre `3` pour élargir, `5` pour ne recevoir que le critique.

Les tags `N4`, `N5` et `gravite:majeur` permettent de trier directement dans la boîte aux
lettres, sans ouvrir le message.

**Attention** : si le relais SMTP est le serveur de messagerie lui-même et qu'il est
compromis, les notifications passent par une machine non fiable.

### Toujours passer par la soumission authentifiée, jamais par le port 25

Envoyer sur le port 25 revient à se présenter comme un serveur de messagerie **extérieur et
anonyme**. Un antispam correctement réglé rejette alors le message, et il a raison : l'IP émettrice
est privée, sans DNS inverse, absente du SPF, et le message n'est pas signé.

Configuration correcte, avec une boîte dédiée :

- `hook_url` : `smtp+starttls://<hôte-mail>:587`
- `api_key` : `<boîte-dédiée>:<mot-de-passe>`

La soumission authentifiée écarte les contrôles destinés aux serveurs extérieurs et fait signer le
message en DKIM par le serveur de messagerie.

> **Ne jamais désactiver ni abaisser l'antispam pour faire passer les alertes.** Le corps d'une
> alerte contient du texte issu des journaux, donc potentiellement écrit par un attaquant : c'est
> exactement ce qu'il faut continuer d'analyser. Un chemin de réexpédition non analysé depuis une
> machine compromise est une voie d'envoi de spam, qui dégrade la réputation de l'IP et du domaine.

### Disjoncteur : ne pas marteler un relais qui refuse

`custom-supervision` suspend les tentatives après `max_consecutive_failures` échecs d'affilée, puis
ne tente plus qu'une sonde par `mute_seconds_after_failures`. La reprise est automatique dès que le
relais refonctionne. Un envoi qui échoue **ne consomme pas** le quota horaire et reste compté comme
retenu, de sorte qu'aucune alerte ne disparaît en silence.

Sans ce garde-fou, chaque alerte retente indéfiniment : le relais accumule les rejets et son
antispam finit par **apprendre que les alertes sont du spam**, ce qui bloque la notification même
une fois l'expéditeur corrigé.

## 5. Déploiement, par étapes

1. **Audit en lecture seule** sur chaque serveur : `sudo bash audit/talos-audit.sh`
   (options `OS_URL`/`OS_USER`, `WAZUH_API_URL`/`WAZUH_API_USER`, mot de passe demandé sans écho).
   Lire `00-SUMMARY.txt`. Résultat à garder hors de ce dépôt.
2. **Conserver les preuves** avant toute correction : collecte Velociraptor ; export CrowdSec
   (`cscli alerts list -o json --limit 0`) ; copie de `/var/lib/fail2ban/fail2ban.sqlite3` et de
   `/var/ossec/logs/alerts/` ; snapshot OpenSearch vers un bucket MinIO verrouillé
   (`mc mb --with-lock`, `mc retention set --default COMPLIANCE 180d`) ; empreintes `sha256sum`
   consignées dans TheHive ; copie **hors** de l'hôte TALOS si c'est lui qui est touché.
3. **Groupes et labels Wazuh** (manager) : copier `wazuh/shared/<groupe>/agent.conf` dans
   `/var/ossec/etc/shared/<groupe>/`, `agent_groups -a -i <ID> -g <groupe> -q`, puis
   `verify-agent-conf`.
4. **Notification** (manager) : installer `wazuh/integrations/custom-supervision*` dans
   `/var/ossec/integrations/` (root:wazuh, 750), `talos-supervision.json` dans `/var/ossec/etc/`,
   fusionner `wazuh/etc/ossec-manager-snippet.xml`, redémarrer le manager. Test à blanc :
   `TALOS_DRYRUN=1 TALOS_STATE=/tmp/t.state /var/ossec/integrations/custom-supervision alerte.json`.
5. **Rétention** : CrowdSec `db_config.flush.max_age: 90d`, fail2ban `dbpurgeage = 90d`,
   politique ISM et dépôt de snapshots sur l'indexeur, Terraform avec backend `s3` (MinIO, versioning).
6. **CMDB** : agent GLPI sur chaque hôte, puis rapprochement GLPI ↔ agents Wazuh
   (n° de série ou UUID), en renseignant `asset.glpi_id`.
