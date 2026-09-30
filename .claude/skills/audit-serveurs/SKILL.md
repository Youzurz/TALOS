---
name: audit-serveurs
description: "Audite en LECTURE SEULE un ou plusieurs serveurs Linux de TALOS (Wazuh, CrowdSec, fail2ban, GLPI, Velociraptor, Terraform, état de l'hôte) et rapatrie le résultat hors du dépôt. À utiliser pour « auditer », « vérifier la config », « état des serveurs »."
argument-hint: "[alias-ssh ...]"
allowed-tools: Bash(ssh *) Bash(scp *) Bash(sha256sum *) Bash(mkdir -p ~/talos-evidence*) Bash(tar *)
---
Serveurs visés : $ARGUMENTS (vide = tous les alias Linux de CLAUDE.local.md).

Pour chaque alias, dans l'ordre, sans rien modifier sur le serveur hormis /tmp :
1. `scp audit/talos-audit.sh <alias>:/tmp/talos-audit.sh`
2. `ssh <alias> 'sudo OUT_BASE=/tmp bash /tmp/talos-audit.sh'` (ajouter OS_URL/OS_USER et
   WAZUH_API_URL/WAZUH_API_USER si l'utilisateur les a fournis ; jamais de mot de passe en clair
   dans la commande : le script le demande sans écho).
3. Rapatrier l'archive et son .sha256 vers `~/talos-evidence/<alias>/<AAAAMMJJ>/`, vérifier
   `sha256sum -c`, puis supprimer les copies de /tmp sur le serveur **seulement avec accord**.
4. Lire `00-SUMMARY.txt`.

Livrable : un tableau par serveur (OK / WARN / MISS), les écarts entre ce qui est déclaré
(GLPI, Terraform) et ce qui est observé (Wazuh), et les 5 actions prioritaires.
Ne jamais copier le résultat dans le dépôt (public).
