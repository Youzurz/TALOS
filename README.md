# TALOS

Outillage de la plateforme SOC (Wazuh, Velociraptor, TheHive, Cortex, MISP, Arkime,
OpenSearch, MinIO, CrowdSec, fail2ban, GLPI, Terraform).

| Chemin | Contenu |
|---|---|
| `docs/gestion-des-actifs.md` | Rôle de chaque outil dans la gestion des actifs, conservation des preuves, pipeline de notification, étapes de déploiement |
| `audit/talos-audit.sh` | Audit **lecture seule** d'un serveur : ce qui est configuré ou non (Wazuh, CrowdSec, fail2ban, GLPI, Velociraptor, Terraform…) et photo de l'état de l'hôte |
| `wazuh/shared/*/agent.conf` | Groupes Wazuh : inventaire complet, FIM avec diff, docker-listener, labels `asset.*` |
| `wazuh/integrations/custom-supervision*` | Classification, tags, priorité et envoi par e-mail vers supervision@ |
| `wazuh/etc/` | Extrait de `ossec.conf` du manager et réglages de la notification |

> ⚠️ Dépôt **public** : ne jamais y pousser de résultat d'audit, de configuration réelle,
> d'IP, d'identifiant ou de fichier d'état (tfstate, ETAT.json).
