---
name: inspecter-talos
description: "Inspecte en lecture seule le nœud Talos Linux (TALOS) avec talosctl et kubectl : services, santé, journaux, pods, événements. À utiliser pour tout ce qui concerne le serveur TALOS."
allowed-tools: Bash(talosctl * get *) Bash(talosctl * services*) Bash(talosctl * version*) Bash(talosctl * logs *) Bash(talosctl * dmesg*) Bash(talosctl * health*) Bash(kubectl get *) Bash(kubectl describe *) Bash(kubectl logs *) Bash(kubectl top *)
---
Talos n'a ni SSH ni gestionnaire de paquets : `audit/talos-audit.sh` ne s'y applique pas.
Utiliser le contexte talosconfig **os:reader** indiqué dans CLAUDE.local.md.

1. `talosctl version`, `talosctl health`, `talosctl services`, `talosctl get members`.
2. `talosctl get machineconfig -o yaml` est refusé en os:reader (normal) ; utiliser
   `talosctl get machinestatus`, `talosctl get addresses`, `talosctl get routes`.
3. `talosctl dmesg | tail -n 200`, `talosctl logs kubelet --tail 200`.
4. `kubectl get nodes,pods -A -o wide`, `kubectl get events -A --sort-by=.lastTimestamp | tail -n 100`.
5. Chercher la pile SOC (wazuh, opensearch, thehive, cortex, misp, cassandra, arkime, minio,
   velociraptor) : état, redémarrages, volumes persistants, rétention.

Toute commande `apply`, `patch`, `edit`, `reboot`, `upgrade`, `delete` : demander l'accord.
Livrable : état de la pile SOC, anomalies, et ce qu'il faut pour que les preuves soient conservées.
