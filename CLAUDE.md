# TALOS — plateforme SOC / gestion des actifs

Outillage (scripts, gabarits de config, docs) pour Wazuh, OpenSearch, CrowdSec, fail2ban,
GLPI, Terraform, Velociraptor, TheHive/Cortex/MISP, Arkime, MinIO. Vue d'ensemble :
@docs/gestion-des-actifs.md

## Règles impératives
- IMPORTANT : ce dépôt est **public**. Jamais de nom d'hôte réel, IP, identifiant, clé,
  talosconfig, kubeconfig, tfstate, ETAT.json ni résultat d'audit dans un fichier suivi par git.
  Les infos d'accès réelles vont dans `CLAUDE.local.md` (ignoré par git).
- Serveurs en production et possiblement compromis : **lecture seule par défaut**.
  Toute action qui modifie un serveur (restart, apply, install, rm, reboot, config) exige
  l'accord explicite de l'utilisateur, action par action. Ne jamais redémarrer avant
  préservation des preuves.
- Preuves et résultats d'audit : dans `~/talos-evidence/<hôte>/<date>/` (hors dépôt),
  avec `sha256sum`, copie hors de l'hôte audité.
- Langue : français pour la doc, les messages de commit et les échanges.

## Accès
- Serveurs Linux : SSH (alias dans `~/.ssh/config`, voir `CLAUDE.local.md`).
- Nœud TALOS (Talos Linux) : `talosctl` avec un talosconfig `os:reader` ; pas de SSH.

## Vérifier avant de livrer
- `shellcheck -S warning audit/*.sh .claude/hooks/*.sh`
- `python3 -m py_compile wazuh/integrations/custom-supervision.py`
- `TALOS_DRYRUN=1 TALOS_STATE=/tmp/t.state wazuh/integrations/custom-supervision <alerte.json>`
- XML Wazuh : chaque `wazuh/shared/*/agent.conf` doit parser (voir hook de vérification).

## Workflows (skills)
`/audit-serveurs`, `/preserver-preuves`, `/inspecter-talos` (lecture seule),
`/deployer-wazuh` (modifie les serveurs : manuel uniquement).
