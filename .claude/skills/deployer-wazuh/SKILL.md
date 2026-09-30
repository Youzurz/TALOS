---
name: deployer-wazuh
description: "Déploie sur le manager Wazuh les groupes d'agents (labels asset.*, inventaire, FIM avec diff, docker-listener) et le pipeline de notification custom-supervision vers supervision@youzurz.com."
argument-hint: "[alias-ssh-du-manager]"
disable-model-invocation: true
---
Manager : $ARGUMENTS. Prérequis : `/preserver-preuves` fait sur les serveurs concernés.
Suivre `docs/gestion-des-actifs.md` §5 étapes 3 et 4. Pour CHAQUE étape qui écrit sur le
serveur, montrer la commande exacte et attendre l'accord de l'utilisateur.

1. Sauvegarder l'existant : `ossec.conf`, `etc/shared/*/agent.conf` → `~/talos-evidence/$ARGUMENTS/config-avant-<date>/`.
2. Copier `wazuh/shared/<groupe>/agent.conf`, puis `verify-agent-conf`.
3. Installer `custom-supervision{,.py}` et `talos-supervision.json` (relais SMTP de CLAUDE.local.md).
4. Test à blanc : `TALOS_DRYRUN=1` sur une alerte réelle tirée de `alerts.json`.
5. Fusionner `wazuh/etc/ossec-manager-snippet.xml`, puis `wazuh-control restart` (accord requis).
6. Vérifier : `integrations.log` sans erreur, un mail reçu sur supervision@, agents toujours actifs.
