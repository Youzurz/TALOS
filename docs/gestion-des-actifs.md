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
| Maps « Create your first map » | Aucune carte | Module de carte OpenSearch Dashboards jamais configuré | Facultatif : carte de `GeoLocation` des `srcip` de `wazuh-alerts-*` |
| Docker, filtre `cluster.name: wazuh-ns…`, « No results » (24 h) | Aucun événement Docker | `docker-listener` non activé sur les agents (ou pas de Docker) | `wazuh/shared/serveurs/agent.conf` |
| Filtre `cluster.name` par serveur | Il y a peut-être **un manager Wazuh par serveur** | Le sélecteur d'API bascule d'un manager à l'autre, sans vue consolidée | À confirmer par l'audit ; cible : un seul manager, ou un seul indexeur partagé |

## 3. Les atteintes sont-elles conservées, avec l'état d'avant ?

Pas par défaut :

- syscollector ne garde **que l'état courant** (il est remplacé à chaque inventaire, toutes les heures) ;
- FIM garde le contenu d'avant uniquement avec `report_changes="yes"` ;
- CrowdSec purge au bout de 7 jours, fail2ban au bout de 1 jour ;
- Arkime écrase les PCAP les plus anciens ;
- sans `logall_json`, seuls les événements qui déclenchent une alerte sont conservés ;
- **GLPI** (onglet Historique) et un **tfstate versionné** sont les seules sources
  fiables de l'état d'avant, à condition qu'ils aient été en place avant l'atteinte.

Conservation immédiate, sans traiter les incidents : voir la section 5, étape 2.

## 4. Classification, tags, notification vers supervision@youzurz.com

```
agent Wazuh ──labels asset.* (agent.conf du groupe)──► alerte (agent.labels)
     │
manager ─► integratord ─► custom-supervision (niveau ≥ 7)
                               ├─ catégorie : compromission | comptes | authentification |
                               │              integrite | vulnerabilite | conformite |
                               │              messagerie | conteneur | reseau | disponibilite | autre
                               ├─ priorité  : P1 (niv ≥13) P2 (≥10) P3 (≥7) P4,
                               │              relevée d'un cran si asset.criticality=haute
                               ├─ tags      : catégorie, priorité, asset.*, mitre:Txxxx, group:*
                               ├─ anti-inondation : 3/h par (règle, agent), 60/h au total
                               └─ SMTP ─► supervision@youzurz.com
                                          Objet : [TALOS][P1][authentification][messagerie] …
                                          En-têtes : X-TALOS-Priority / -Category / -Asset / -Tags
```

Les en-têtes `X-TALOS-*` permettent de trier les mails côté messagerie (règles Sieve, etc.).

**Attention** : si le relais SMTP est le serveur de messagerie lui-même et qu'il est
compromis, les notifications passent par une machine qui n'est pas fiable. Prévoir un
relais externe (`smtp+starttls://…:587` avec `api_key` au format `utilisateur:motdepasse`).

## 5. Déploiement, par étapes

1. **Audit en lecture seule** sur chaque serveur :
   ```bash
   sudo bash audit/talos-audit.sh
   # facultatif, pour interroger l'indexeur et l'API Wazuh (mot de passe demandé sans écho) :
   sudo OS_URL=https://127.0.0.1:9200 OS_USER=admin \
        WAZUH_API_URL=https://127.0.0.1:55000 WAZUH_API_USER=wazuh-wui \
        bash audit/talos-audit.sh
   ```
   Lire `00-SUMMARY.txt`. Transmettre l'archive par un **canal privé**, jamais dans ce dépôt.
2. **Conserver les preuves** avant toute correction :
   - collecte Velociraptor sur chaque hôte ;
   - `cscli alerts list -o json --limit 0`, copie de `/var/lib/fail2ban/fail2ban.sqlite3` ;
   - copie de `/var/ossec/logs/alerts/` ;
   - snapshot OpenSearch vers un bucket MinIO verrouillé en écriture (WORM) :
     `mc mb --with-lock` puis `mc retention set --default COMPLIANCE 180d` ;
   - empreintes `sha256sum` de chaque fichier, consignées dans un dossier TheHive par serveur ;
   - copie **hors** de l'hôte TALOS si c'est lui qui est touché.
3. **Groupes et labels Wazuh** (manager) :
   ```bash
   for g in serveurs messagerie soc; do
     mkdir -p /var/ossec/etc/shared/$g && cp wazuh/shared/$g/agent.conf /var/ossec/etc/shared/$g/
   done
   /var/ossec/bin/agent_groups -a -i <ID> -g serveurs -q       # tous les serveurs
   /var/ossec/bin/agent_groups -a -i <ID> -g messagerie -q     # le serveur de messagerie
   /var/ossec/bin/verify-agent-conf
   ```
   Labels propres à un hôte, dans le `ossec.conf` local de l'agent :
   `<labels><label key="asset.glpi_id">NN</label><label key="asset.owner">…</label></labels>`
4. **Pipeline de notification** (manager) :
   ```bash
   install -o root -g wazuh -m 750 wazuh/integrations/custom-supervision    /var/ossec/integrations/
   install -o root -g wazuh -m 750 wazuh/integrations/custom-supervision.py /var/ossec/integrations/
   install -o root -g wazuh -m 640 wazuh/etc/talos-supervision.json.example /var/ossec/etc/talos-supervision.json
   # fusionner wazuh/etc/ossec-manager-snippet.xml dans /var/ossec/etc/ossec.conf, puis :
   systemctl restart wazuh-manager
   # test à blanc :
   TALOS_DRYRUN=1 TALOS_STATE=/tmp/t.state /var/ossec/integrations/custom-supervision /chemin/alerte.json
   ```
5. **Rétention** : CrowdSec `db_config.flush.max_age: 90d`, fail2ban `dbpurgeage = 90d`,
   politique ISM et dépôt de snapshots sur l'indexeur, Terraform avec backend `s3` (MinIO, versioning).
6. **CMDB** : agent GLPI sur chaque hôte (`server = https://<glpi>/`), puis rapprocher les
   fiches GLPI des agents Wazuh (n° de série ou UUID de Hardware), en renseignant `asset.glpi_id`.

## 6. Accès pour l'automatisation

La session Claude dans le cloud ne peut joindre ni le tableau de bord interne (DNS interne) ni les serveurs
en SSH. Options :

- **Session sur une machine qui a déjà les accès** (Claude Desktop, ou `claude remote-control`
  lancé depuis un poste ou bastion qui a les clés SSH et l'accès au tableau de bord interne). C'est la voie
  recommandée pour « prendre la main ».
- **Accès API en lecture seule** depuis le cloud : autoriser le domaine public du tableau de bord dans l'accès réseau
  de l'environnement, et fournir des identifiants **lecture seule** comme secrets d'environnement
  (`WAZUH_API_URL`, `WAZUH_API_USER`, `WAZUH_API_PASS`, `OS_URL`, `OS_USER`, `OS_PASS`),
  jamais dans le chat ni dans ce dépôt.
