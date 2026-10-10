#!/usr/bin/env bash
#
# codex-resolve.sh — localise un fil Codex à partir d'une URI codex:// ou d'un UUID.
#
# Décode l'horodatage d'un UUIDv7, en déduit le dossier de rollout attendu,
# cherche le fil dans ~/.codex puis dans les transcripts Claude Code importés,
# et conclut sur l'état du fil.
#
# Usage :
#   tools/codex-resolve.sh codex://threads/01a0486a-e232-7bc2-8f38-f447129bb778
#   tools/codex-resolve.sh 01a0486a-e232-7bc2-8f38-f447129bb778 --deep
#
# Options :
#   --deep           étend la recherche par nom de fichier à tout $HOME (lent)
#   --also <dir>     racine supplémentaire à fouiller (répétable)
#   -h, --help       cette aide
#
# Variables d'environnement :
#   CODEX_HOME          défaut : $HOME/.codex
#   CLAUDE_CONFIG_DIR   défaut : $HOME/.claude
#
# Codes de sortie : 0 fil trouvé · 1 introuvable · 2 erreur d'usage.
#
# Compatible bash 3.2 (macOS) : pas de tableaux, pas de mapfile.

set -euo pipefail

CODEX_HOME="${CODEX_HOME:-$HOME/.codex}"
CLAUDE_HOME="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"

DEEP=0
EXTRA_ROOTS=""   # une racine par ligne
RAW=""

die() { printf 'erreur : %s\n' "$*" >&2; exit 2; }
usage() { sed -n '3,24p' "$0" | sed 's/^#\{1,\} \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --deep)    DEEP=1; shift ;;
    --also)    [ $# -ge 2 ] || die "--also attend un dossier"
               EXTRA_ROOTS="$EXTRA_ROOTS$2
"; shift 2 ;;
    -*)        die "option inconnue : $1" ;;
    *)         [ -z "$RAW" ] || die "un seul identifiant à la fois"; RAW="$1"; shift ;;
  esac
done

[ -n "$RAW" ] || { usage; exit 2; }

# codex://threads/<uuid>, codex://thread/<uuid> ou <uuid> nu.
ID=$(printf '%s' "$RAW" | sed -e 's#^codex://##' -e 's#^.*/##' | tr 'A-Z' 'a-z')
printf '%s' "$ID" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' \
  || die "identifiant invalide : $RAW"

# date -d (GNU) ou date -r (BSD/macOS).
fmt_epoch() { # <secondes> <format> [utc|local]
  if [ "${3:-utc}" = utc ]; then
    date -u -d "@$1" +"$2" 2>/dev/null || date -u -r "$1" +"$2"
  else
    date -d "@$1" +"$2" 2>/dev/null || date -r "$1" +"$2"
  fi
}

print_list() { # lit des chemins sur stdin, les imprime indentés (gère les espaces)
  while IFS= read -r line; do
    [ -n "$line" ] && printf '    %s\n' "$line"
  done
}

by_name() { # <racine> — fichiers dont le nom contient l'uuid
  [ -d "$1" ] || return 0
  find "$1" -type f -name "*$ID*" 2>/dev/null || true
}

by_content() { # <racine> — transcripts citant l'uuid
  [ -d "$1" ] || return 0
  find "$1" -type f \( -name '*.jsonl' -o -name '*.json' \) -print0 2>/dev/null \
    | xargs -0 grep -l -- "$ID" 2>/dev/null || true
}

append() { # <accumulateur> <ajout> -> accumulateur sur stdout
  if [ -n "$2" ]; then printf '%s%s\n' "$1" "$2"; else printf '%s' "$1"; fi
}

echo "=== Fil Codex $ID ==="

VERSION=$(printf '%s' "$ID" | cut -c15)
CANDIDATE_DIRS=""
if [ "$VERSION" = "7" ]; then
  MS=$((16#$(printf '%s' "$ID" | tr -d '-' | cut -c1-12)))
  SEC=$((MS / 1000))
  printf 'UUIDv7 — créé le %s / %s (heure locale)\n' \
    "$(fmt_epoch "$SEC" '%Y-%m-%d %H:%M:%S UTC')" \
    "$(fmt_epoch "$SEC" '%Y-%m-%d %H:%M:%S %Z' local)"
  # Les rollouts sont rangés par date : on tente la date locale ET la date UTC.
  D_LOCAL=$(fmt_epoch "$SEC" '%Y/%m/%d' local)
  D_UTC=$(fmt_epoch "$SEC" '%Y/%m/%d')
  CANDIDATE_DIRS="$D_LOCAL"
  [ "$D_UTC" = "$D_LOCAL" ] || CANDIDATE_DIRS="$CANDIDATE_DIRS
$D_UTC"
else
  echo "UUID version $VERSION — pas d'horodatage intégré, recherche à l'aveugle."
fi

HITS_CODEX=""
HITS_CLAUDE=""
HITS_OTHER=""

echo
echo "--- 1. Emplacement attendu (rollouts datés) ---"
if [ -z "$CANDIDATE_DIRS" ]; then
  echo "  (sans date : étape sautée)"
else
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    dir="$CODEX_HOME/sessions/$d"
    if [ -d "$dir" ]; then
      found=$(by_name "$dir")
      if [ -n "$found" ]; then
        printf '  TROUVÉ dans %s :\n' "$dir"
        printf '%s\n' "$found" | print_list
        HITS_CODEX=$(append "$HITS_CODEX" "$found")
      else
        printf '  %s existe (%s fichiers) mais ne contient pas ce fil\n' \
          "$dir" "$(find "$dir" -type f 2>/dev/null | wc -l | tr -d ' ')"
      fi
    else
      printf '  %s : dossier absent\n' "$dir"
    fi
  done <<EOF
$CANDIDATE_DIRS
EOF
fi

echo
echo "--- 2. Tout $CODEX_HOME ---"
if [ -d "$CODEX_HOME" ]; then
  found=$(by_name "$CODEX_HOME")
  [ -n "$found" ] && { echo "  par nom :"; printf '%s\n' "$found" | print_list; HITS_CODEX=$(append "$HITS_CODEX" "$found"); }
  found=$(by_content "$CODEX_HOME")
  [ -n "$found" ] && { echo "  par contenu :"; printf '%s\n' "$found" | print_list; HITS_CODEX=$(append "$HITS_CODEX" "$found"); }
  [ -n "$HITS_CODEX" ] || echo "  aucune occurrence"
else
  printf '  %s : dossier absent (Codex CLI jamais installé ici ?)\n' "$CODEX_HOME"
fi

echo
echo "--- 3. Transcripts Claude Code ($CLAUDE_HOME/projects) ---"
found=$(by_name "$CLAUDE_HOME/projects")
[ -n "$found" ] && { echo "  par nom :"; printf '%s\n' "$found" | print_list; HITS_CLAUDE=$(append "$HITS_CLAUDE" "$found"); }
found=$(by_content "$CLAUDE_HOME/projects")
[ -n "$found" ] && { echo "  par contenu :"; printf '%s\n' "$found" | print_list; HITS_CLAUDE=$(append "$HITS_CLAUDE" "$found"); }
[ -n "$HITS_CLAUDE" ] || echo "  aucune occurrence"

if [ -n "$EXTRA_ROOTS" ]; then
  echo
  echo "--- 4. Racines supplémentaires ---"
  while IFS= read -r r; do
    [ -n "$r" ] || continue
    found=$(by_name "$r")
    [ -n "$found" ] && { printf '%s\n' "$found" | print_list; HITS_OTHER=$(append "$HITS_OTHER" "$found"); }
    found=$(by_content "$r")
    [ -n "$found" ] && { printf '%s\n' "$found" | print_list; HITS_OTHER=$(append "$HITS_OTHER" "$found"); }
  done <<EOF
$EXTRA_ROOTS
EOF
  [ -n "$HITS_OTHER" ] || echo "  aucune occurrence"
fi

if [ "$DEEP" -eq 1 ]; then
  echo
  echo "--- 5. Balayage de \$HOME par nom de fichier (lent) ---"
  found=$(find "$HOME" -type f -name "*$ID*" -not -path '*/Library/Caches/*' 2>/dev/null || true)
  if [ -n "$found" ]; then
    printf '%s\n' "$found" | print_list
    HITS_OTHER=$(append "$HITS_OTHER" "$found")
  else
    echo "  aucune occurrence"
  fi
fi

echo
echo "=== Verdict ==="
if [ -n "$HITS_CODEX" ]; then
  echo "INTACT — le fil est toujours dans Codex."
  echo "  → s'il manque dans ton groupe « fils importés », c'est l'import qui l'a laissé de côté"
  echo "    (fenêtre de dates trop récente, ou dossier source différent) : ré-importe ce fichier."
  exit 0
elif [ -n "$HITS_CLAUDE" ]; then
  echo "IMPORT SEUL — absent de Codex, mais la copie importée dans Claude Code existe."
  echo "  → l'URI codex:// est morte (source purgée) ; le contenu, lui, est sauvé."
  echo "  → sauvegarde-la : la purge de rétention Claude Code finira par l'emporter aussi"
  echo "    (tools/codex-backup.sh)."
  exit 0
elif [ -n "$HITS_OTHER" ]; then
  echo "AILLEURS — trouvé hors des emplacements standard (voir ci-dessus)."
  exit 0
else
  echo "INTROUVABLE sur cette machine. Trois causes possibles :"
  echo "  1. purge de l'historique Codex (le rollout a été supprimé) ;"
  echo "  2. fil vécu côté Codex cloud — aucun fichier local n'a jamais existé ;"
  echo "  3. fil créé sur une autre machine."
  echo
  echo "Pistes restantes : Time Machine / sauvegardes, relance avec --deep,"
  echo "et --also <dossier> pour une archive ou un export hors \$HOME."
  exit 1
fi
