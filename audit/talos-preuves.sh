#!/usr/bin/env bash
# talos-preuves.sh — rapatrie les preuves depuis les serveurs vers ce Mac.
#
# Corrige l'échec silencieux du 30/09 : les archives produites étaient VIDES (0 entrée,
# même empreinte pour toutes), et le contrôle SHA256SUMS passait quand même — il ne
# vérifie que l'intégrité du fichier, jamais son contenu.
# Ici, toute archive vide ou dérisoire fait ÉCHOUER le script, bruyamment.
#
# N'écrit RIEN sur les serveurs : l'archive est produite sur la sortie standard distante
# et reçue directement ici. Lecture seule côté serveur.
#
# Les hôtes sont passés en argument ou via TALOS_HOSTS (alias ~/.ssh/config).
# Aucun nom d'hôte réel n'est écrit dans ce dépôt : voir CLAUDE.local.md.
#
#   bash local/talos-preuves.sh <alias> [<alias>...]
#   TALOS_HOSTS="<alias1> <alias2>" bash local/talos-preuves.sh
#
# Le volume Docker des alertes Wazuh est donné par WAZUH_LOGS_VOLUME (facultatif).
set -uo pipefail

read -r -a HOSTS <<<"${*:-${TALOS_HOSTS:-}}"
if [ "${#HOSTS[@]}" -eq 0 ] || [ -z "${HOSTS[0]}" ]; then
  sed -n '2,18p' "$0"; exit 2
fi
DEST_BASE="${DEST_BASE:-$HOME/talos-evidence}"
STAMP="$(date -u +%Y%m%d-%H%M)"
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=10)
MIN_ENTRIES=1          # une archive de preuves à 0 entrée n'est pas une preuve
MIN_BYTES=1024
rc_global=0

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '  \033[31mÉCHEC\033[0m : %s\n' "$*"; rc_global=1; }
ok()   { printf '  \033[32mOK\033[0m    : %s\n' "$*"; }

# pull <hôte> <dossier_dest> <nom> <chemins_distants>
# Produit <nom>.tgz, puis REFUSE de le valider s'il est vide.
pull() {
  local h="$1" dest="$2" name="$3" paths="$4"
  local out="$dest/$name.tgz" err="$dest/$name.stderr"

  # tar sur la sortie standard distante ; --ignore-failed-read pour ne pas tout perdre
  # à cause d'un seul fichier illisible.
  "${SSH[@]}" "$h" "sudo tar czf - --ignore-failed-read -- $paths 2>/dev/null" >"$out" 2>"$err"
  local pipe=$?

  local entries bytes
  entries=$(tar tzf "$out" 2>/dev/null | wc -l | tr -d ' ')
  bytes=$(wc -c <"$out" 2>/dev/null | tr -d ' ')
  # un journal d'erreurs vide n'est pas une preuve : il ne doit pas polluer le manifeste
  [ -s "$err" ] || rm -f "$err"

  if [ "$pipe" -ne 0 ] && [ "${entries:-0}" -eq 0 ]; then
    fail "$name : ssh/tar a échoué (code $pipe) — $(head -c 200 "$err" 2>/dev/null)"
    rm -f "$out"; return 1
  fi
  if [ "${entries:-0}" -lt "$MIN_ENTRIES" ] || [ "${bytes:-0}" -lt "$MIN_BYTES" ]; then
    fail "$name : archive VIDE ou dérisoire ($entries entrée(s), $bytes octets) — supprimée"
    rm -f "$out"; return 1
  fi
  ok "$name : $entries entrée(s), $(du -h "$out" | cut -f1)"
  return 0
}

for h in "${HOSTS[@]}"; do
  say "preuves $h"
  if ! "${SSH[@]}" "$h" true </dev/null 2>/dev/null; then
    fail "$h injoignable en SSH — ignoré"; continue
  fi
  dest="$DEST_BASE/$h/$STAMP"; mkdir -p "$dest"

  pull "$h" "$dest" logs-systeme \
      '/var/log/auth.log* /var/log/secure* /var/log/syslog* /var/log/messages* /var/log/dpkg.log*'
  pull "$h" "$dest" logs-messagerie '/var/log/mail.log* /var/log/maillog*' || true
  pull "$h" "$dest" conf-sensible \
      '/etc/passwd /etc/group /etc/sudoers /etc/sudoers.d /etc/crontab /etc/cron.d /etc/ssh/sshd_config'

  # État vivant : ports, processus, comptes, empreintes des clés SSH autorisées.
  # Jamais le contenu d'une clé privée ni d'un mot de passe.
  "${SSH[@]}" "$h" 'sudo sh -c "
      echo ===PORTS===;      ss -tulpnH 2>/dev/null
      echo ===PROCESSUS===;  ps -eo pid,ppid,user,lstart,cmd --sort=start_time 2>/dev/null
      echo ===UID0===;       awk -F: \"\\\$3==0\" /etc/passwd
      echo ===CONNEXIONS===; last -F -n 200 2>/dev/null
      echo ===CLES_SSH===;   for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
                               [ -f \"\$f\" ] && { echo \"--- \$f\"; ssh-keygen -lf \"\$f\" 2>&1; }
                             done
    "' </dev/null >"$dest/etat-vivant.txt" 2>/dev/null
  if [ -s "$dest/etat-vivant.txt" ] && grep -q '===PORTS===' "$dest/etat-vivant.txt"; then
    ok "etat-vivant.txt : $(wc -l <"$dest/etat-vivant.txt" | tr -d ' ') lignes"
  else
    fail "etat-vivant.txt vide ou tronqué"; rm -f "$dest/etat-vivant.txt"
  fi

  # Alertes Wazuh : on ne rapatrie pas des dizaines de Go, on prouve ce qui existe.
  if [ -n "${WAZUH_LOGS_VOLUME:-}" ]; then
    "${SSH[@]}" "$h" "V='$WAZUH_LOGS_VOLUME'
       [ -d \"\$V\" ] || exit 9
       sudo find \"\$V\" -type f -printf '%TY-%Tm-%Td %s %p\n' | sort" </dev/null \
       >"$dest/wazuh-alertes-index.txt" 2>/dev/null
    if [ -s "$dest/wazuh-alertes-index.txt" ]; then
      ok "wazuh-alertes-index.txt : $(wc -l <"$dest/wazuh-alertes-index.txt" | tr -d ' ') fichiers recensés"
    else
      rm -f "$dest/wazuh-alertes-index.txt"
    fi
  fi

  # Manifeste : empreinte ET nombre d'entrées, pour qu'une archive vide se voie.
  ( cd "$dest" || exit
    {
      echo "# Preuves $h — $(date -u +%FT%TZ) — rapatriées en lecture seule"
      echo "# colonnes : sha256  entrées  octets  fichier"
      for f in *; do
        [ -f "$f" ] && [ "$f" != MANIFESTE.txt ] || continue
        n="-"; case "$f" in *.tgz) n=$(tar tzf "$f" 2>/dev/null | wc -l | tr -d ' ');; esac
        printf '%s  %s  %s  %s\n' "$(shasum -a 256 "$f" | cut -d' ' -f1)" "$n" "$(wc -c <"$f" | tr -d ' ')" "$f"
      done
    } >MANIFESTE.txt )

  n_fichiers=$(find "$dest" -type f ! -name MANIFESTE.txt | wc -l | tr -d ' ')
  if [ "$n_fichiers" -eq 0 ]; then
    fail "$h : AUCUNE preuve rapatriée"; rm -f "$dest/MANIFESTE.txt"; rmdir "$dest" 2>/dev/null
  else
    printf '  → %s (%s fichier(s))\n' "$dest" "$n_fichiers"
  fi
done

say "Bilan"
if [ "$rc_global" -eq 0 ]; then
  echo "Toutes les preuves demandées ont été rapatriées et sont non vides."
else
  echo "Des preuves manquent ou sont vides : voir les lignes ÉCHEC ci-dessus."
fi
echo "Destination : $DEST_BASE/<hôte>/$STAMP — vérifier MANIFESTE.txt, colonne « entrées »."
exit "$rc_global"
