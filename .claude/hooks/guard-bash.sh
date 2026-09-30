#!/bin/bash
# PreToolUse(Bash) : garde-fous TALOS.
#  - refuse (exit 2) : push forcé ; commit contenant secrets / hôtes réels / résultats d'audit
#  - demande l'accord (ask) : toute commande qui modifie un serveur distant (ssh, talosctl, kubectl)
INPUT=$(cat)
CMD=$(jq -r '.tool_input.command // empty' <<<"$INPUT")
[ -z "$CMD" ] && exit 0

deny() { echo "Bloqué (TALOS) : $1" >&2; exit 2; }
ask() {
  jq -n --arg r "$1" '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"ask",permissionDecisionReason:$r}}'
  exit 0
}

if grep -Eq 'git\s+push\b.*(--force\b|-f\b|--force-with-lease)' <<<"$CMD"; then
  deny "push forcé interdit sur ce dépôt"
fi

if grep -Eq 'git\s+commit\b' <<<"$CMD"; then
  cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0
  FILES=$(git diff --cached --name-only 2>/dev/null)
  BAD=$(grep -Ei '(^|/)(talos-audit-|evidence/|ETAT\.json|CLAUDE\.local\.md$|talosconfig|kubeconfig|id_[a-z0-9]+$)|\.tfstate|\.pem$' <<<"$FILES")
  [ -n "$BAD" ] && deny "fichiers sensibles indexés : $BAD"
  ADDED=$(git diff --cached -U0 2>/dev/null | grep -E '^\+' | grep -vE '^\+\+\+')
  grep -Eq 'BEGIN [A-Z ]*PRIVATE KEY' <<<"$ADDED" && deny "clé privée dans le diff indexé"
  HOSTS=$(grep -Eo '\bns[0-9]{6,}\b|\b3y3\.[a-z.]+\b' <<<"$ADDED" | sort -u | tr '\n' ' ')
  [ -n "$HOSTS" ] && deny "noms d'hôtes réels dans le diff indexé ($HOSTS) : dépôt public"
  IPS=$(grep -Eo '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' <<<"$ADDED" \
        | grep -Ev '^(127\.|0\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|203\.0\.113\.|198\.51\.100\.|192\.0\.2\.)' | sort -u | tr '\n' ' ')
  [ -n "$IPS" ] && deny "adresses IP publiques dans le diff indexé ($IPS) : dépôt public"
fi

REMOTE='(\bssh\b|\btalosctl\b|\bkubectl\b|\bscp\b.*:)'
if grep -Eq "$REMOTE" <<<"$CMD"; then
  MUT='(\breboot\b|\bshutdown\b|\bpoweroff\b|\bhalt\b|systemctl\s+(restart|stop|start|disable|enable|reload|mask|kill)|\bservice\s+\S+\s+(restart|stop|start)|\b(apt|apt-get|dnf|yum|pip3?|snap)\s+(install|remove|purge|upgrade|dist-upgrade|autoremove)|\brm\s|\bmv\s|\bdd\s|\bmkfs|\bchmod\s|\bchown\s|\bsed\s+-i|\btee\b|>\s*[/~]|\bdocker\s+(rm|rmi|stop|restart|kill|compose\s+(up|down|restart))|\bcscli\s+(decisions\s+(add|delete)|bouncers\s+(add|delete))|fail2ban-client\s+(set|unban|reload|stop)|agent_groups\s+-a|wazuh-control\s+(restart|stop|start)|\btalosctl\s+(reboot|reset|upgrade|apply-config|patch|edit|shutdown|rollback|bootstrap)|\bkubectl\s+(delete|apply|edit|patch|scale|rollout|drain|cordon|create|replace|set|label|annotate|exec)|\bscp\s+[^:]+\s+\S+:)'
  if grep -Eq "$MUT" <<<"$CMD"; then
    ask "Commande qui MODIFIE un serveur distant (production, possiblement compromis). Accord explicite requis."
  fi
fi
exit 0
