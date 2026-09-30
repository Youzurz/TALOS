#!/bin/bash
# PreToolUse(Edit|Write) : jamais de secret ni de résultat d'audit dans le dépôt public.
INPUT=$(cat)
FP=$(jq -r '.tool_input.file_path // empty' <<<"$INPUT")
CONTENT=$(jq -r '.tool_input.content // .tool_input.new_string // empty' <<<"$INPUT")
PROJ="${CLAUDE_PROJECT_DIR:-$PWD}"
case "$FP" in "$PROJ"/*|[!/]*) ;; *) exit 0;; esac   # hors dépôt : pas de contrôle
case "$FP" in
  */CLAUDE.local.md) exit 0;;                          # ignoré par git, prévu pour ça
  *talos-audit-*|*/evidence/*|*ETAT.json|*talosconfig*|*kubeconfig*|*.tfstate*|*.pem|*/id_*)
    echo "Bloqué (TALOS) : $FP ne doit pas être dans le dépôt public (hors dépôt : ~/talos-evidence)." >&2; exit 2;;
esac
if grep -Eq 'BEGIN [A-Z ]*PRIVATE KEY' <<<"$CONTENT"; then
  echo "Bloqué (TALOS) : clé privée dans le contenu écrit." >&2; exit 2
fi
if grep -Eq '\bns[0-9]{6,}\b|\b3y3\.[a-z.]+\b' <<<"$CONTENT"; then
  echo "Bloqué (TALOS) : nom d'hôte réel dans un fichier du dépôt public ; utiliser un alias (voir CLAUDE.local.md)." >&2; exit 2
fi
exit 0
