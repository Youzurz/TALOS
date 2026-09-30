---
name: preserver-preuves
description: "Fige les preuves d'atteinte d'un serveur (alertes Wazuh, CrowdSec, fail2ban, logs, état) avant toute remédiation, avec empreintes et copie hors de l'hôte."
argument-hint: "[alias-ssh]"
disable-model-invocation: true
---
Serveur : $ARGUMENTS. Objectif : tout copier, ne rien modifier, ne rien redémarrer.

Dans `~/talos-evidence/$ARGUMENTS/<AAAAMMJJ-HHMM>/` (hors dépôt) :
1. Photo de l'état : lancer `/audit-serveurs $ARGUMENTS` si pas fait aujourd'hui.
2. CrowdSec (purge à 7 j) : `cscli alerts list -o json --limit 0`, `cscli decisions list -o json`,
   copie de `/var/lib/crowdsec/data/crowdsec.db` (via `sudo cat` > fichier local).
3. fail2ban (purge à 1 j) : copie de `/var/lib/fail2ban/fail2ban.sqlite3` et `/var/log/fail2ban.log*`.
4. Wazuh manager : archive de `/var/ossec/logs/alerts/` (et `archives/` si présent).
5. Logs système : `/var/log/auth.log*`, `syslog*`, `mail.log*` ; `journalctl -o export` des 30 derniers jours.
6. `sha256sum` de chaque fichier dans `SHA256SUMS`, puis proposer à l'utilisateur la copie vers
   le bucket MinIO verrouillé (WORM) — une commande d'écriture, donc avec son accord.

Rapport : liste des fichiers, tailles, empreintes, et ce qui manquait (source déjà purgée).
