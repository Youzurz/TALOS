#!/bin/bash
# PostToolUse(Edit|Write) : vérifie automatiquement le fichier modifié.
FP=$(jq -r '.tool_input.file_path // empty')
[ -f "$FP" ] || exit 0
fail() { echo "Vérification échouée pour $FP :" >&2; echo "$1" >&2; exit 2; }
case "$FP" in
  *.sh|*/integrations/custom-supervision)
    head -n1 "$FP" | grep -q 'sh' || exit 0
    OUT=$(bash -n "$FP" 2>&1) || fail "$OUT"
    command -v shellcheck >/dev/null && { OUT=$(shellcheck -S warning "$FP" 2>&1) || fail "$OUT"; } ;;
  *.py) OUT=$(python3 -m py_compile "$FP" 2>&1) || fail "$OUT" ;;
  *.json) OUT=$(jq empty "$FP" 2>&1) || fail "$OUT" ;;
  *agent.conf|*.xml)
    OUT=$(python3 - "$FP" 2>&1 <<'PY'
import sys, xml.dom.minidom as m
m.parseString("<root>" + open(sys.argv[1]).read() + "</root>")
PY
) || fail "$OUT" ;;
esac
exit 0
