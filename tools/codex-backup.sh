#!/usr/bin/env bash
#
# codex-backup.sh — archive les transcripts Codex et Claude Code avant purge.
#
# Claude Code balaie ~/.claude/projects/*.jsonl au-delà de `cleanupPeriodDays`
# (30 jours par défaut) et Codex fait tourner son propre historique : une fois
# le fichier parti, le fil est perdu. Ce script en fait une archive datée,
# vérifiée, avec un index des fils (uuid, date, taille).
#
# Usage :
#   tools/codex-backup.sh                  # archive dans ~/codex-claude-backups
#   tools/codex-backup.sh /Volumes/SSD/bk  # ailleurs
#   tools/codex-backup.sh --dry-run        # montre ce qui serait archivé
#   tools/codex-backup.sh --keep 10        # ne garde que les 10 archives récentes
#
# Options :
#   --keep <n>     après l'archivage, supprime les archives au-delà des n plus
#                  récentes (aucune suppression si l'option est absente)
#   --dry-run      n'écrit rien
#   -h, --help     cette aide
#
# Variables d'environnement :
#   CODEX_HOME          défaut : $HOME/.codex
#   CLAUDE_CONFIG_DIR   défaut : $HOME/.claude
#   BACKUP_DIR          défaut : $HOME/codex-claude-backups
#
# Les archives contiennent des transcripts bruts : clés d'API, jetons et code
# privé peuvent s'y trouver. Les garder hors d'un dépôt Git.
#
# Compatible bash 3.2 (macOS).

set -euo pipefail

CODEX_HOME="${CODEX_HOME:-$HOME/.codex}"
CLAUDE_HOME="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
DEST="${BACKUP_DIR:-$HOME/codex-claude-backups}"

KEEP=""
DRY_RUN=0

die() { printf 'erreur : %s\n' "$*" >&2; exit 2; }
usage() { sed -n '3,30p' "$0" | sed 's/^#\{1,\} \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --keep)    [ $# -ge 2 ] || die "--keep attend un nombre"
               printf '%s' "$2" | grep -Eq '^[0-9]+$' || die "--keep attend un entier, reçu : $2"
               KEEP="$2"; shift 2 ;;
    -*)        die "option inconnue : $1" ;;
    *)         DEST="$1"; shift ;;
  esac
done

# stat -c (GNU) ou stat -f (BSD/macOS).
file_mtime() { stat -c '%Y' "$1" 2>/dev/null || stat -f '%m' "$1"; }
file_size()  { stat -c '%s' "$1" 2>/dev/null || stat -f '%z' "$1"; }
fmt_epoch()  { date -d "@$1" +'%Y-%m-%d %H:%M' 2>/dev/null || date -r "$1" +'%Y-%m-%d %H:%M'; }

SOURCES=""
for src in "$CODEX_HOME/sessions" "$CLAUDE_HOME/projects"; do
  if [ -d "$src" ]; then
    SOURCES="$SOURCES$src
"
  else
    printf 'note : %s absent, ignoré\n' "$src" >&2
  fi
done
[ -n "$SOURCES" ] || die "rien à sauvegarder (ni $CODEX_HOME/sessions ni $CLAUDE_HOME/projects)"

STAMP=$(date +'%Y%m%d-%H%M%S')
ARCHIVE="$DEST/codex-claude-$STAMP.tar.gz"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/codex-backup.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
INDEX="$WORK/index.tsv"

NOW=$(date +%s)
printf 'source\tuuid\tmtime\tage_jours\ttaille\tchemin\n' > "$INDEX"

count=0
old=0
while IFS= read -r src; do
  [ -n "$src" ] || continue
  case "$src" in
    "$CODEX_HOME"/*)  label=codex ;;
    *)                label=claude ;;
  esac
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    mtime=$(file_mtime "$f")
    age=$(( (NOW - mtime) / 86400 ))
    uuid=$(printf '%s' "${f##*/}" \
      | grep -Eo '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' \
      | head -1 || true)
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$label" "${uuid:--}" "$(fmt_epoch "$mtime")" "$age" "$(file_size "$f")" "$f" >> "$INDEX"
    count=$((count + 1))
    [ "$age" -ge 30 ] && old=$((old + 1))
  done <<EOF
$(find "$src" -type f -name '*.jsonl' 2>/dev/null || true)
EOF
done <<EOF
$SOURCES
EOF

printf '%s transcripts repérés (%s dépassent 30 jours, seuil de purge par défaut)\n' "$count" "$old"
[ "$count" -gt 0 ] || die "aucun fichier .jsonl sous les sources — rien à archiver"

if [ "$DRY_RUN" -eq 1 ]; then
  echo
  echo "--dry-run : aucune écriture. Archive qui serait créée :"
  printf '  %s\n' "$ARCHIVE"
  echo "Sources :"
  printf '%s' "$SOURCES" | sed 's/^/  /'
  echo "Extrait de l'index :"
  head -6 "$INDEX" | sed 's/^/  /'
  exit 0
fi

mkdir -p "$DEST"

# -C répété : chaque source est archivée sous son propre nom de dossier.
set -- -czf "$ARCHIVE" -C "$WORK" index.tsv
while IFS= read -r src; do
  [ -n "$src" ] || continue
  set -- "$@" -C "$(dirname "$src")" "$(basename "$src")"
done <<EOF
$SOURCES
EOF
tar "$@"

tar -tzf "$ARCHIVE" > /dev/null || die "archive illisible après écriture : $ARCHIVE"

printf '\nArchive : %s (%s octets, %s entrées)\n' \
  "$ARCHIVE" "$(file_size "$ARCHIVE")" "$(tar -tzf "$ARCHIVE" | wc -l | tr -d ' ')"
echo "Index des fils : index.tsv à la racine de l'archive"

if [ -n "$KEEP" ]; then
  echo
  echo "--- Rotation (on garde les $KEEP plus récentes) ---"
  n=0
  while IFS= read -r a; do
    [ -n "$a" ] || continue
    n=$((n + 1))
    if [ "$n" -gt "$KEEP" ]; then
      printf '  suppression : %s\n' "$a"
      rm -f "$a"
    fi
  done <<EOF
$(ls -1t "$DEST"/codex-claude-*.tar.gz 2>/dev/null || true)
EOF
  [ "$n" -gt "$KEEP" ] || echo "  rien à supprimer ($n archive(s))"
fi

if [ "$old" -gt 0 ]; then
  echo
  printf 'Rappel : %s transcripts ont plus de 30 jours et sont candidats au prochain balayage.\n' "$old"
  echo "Pour allonger la rétention : cleanupPeriodDays dans ~/.claude/settings.json."
fi
