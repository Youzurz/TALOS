#!/usr/bin/env bash
# talos-audit.sh — audit LECTURE SEULE de la chaîne de gestion des actifs / SOC
# (Wazuh, OpenSearch, CrowdSec, fail2ban, Velociraptor, GLPI agent, TheHive, Cortex,
#  MISP, Cassandra, Arkime, MinIO, Terraform) + photo de l'état de l'hôte.
#
# Ne modifie RIEN : aucun redémarrage, aucune écriture hors du dossier de sortie.
# Les secrets (mots de passe, clés, tokens) sont masqués dans les fichiers produits,
# mais le résultat contient des noms d'hôtes, IP et configurations :
#   NE JAMAIS le pousser dans le dépôt Git (public). Le transmettre par un canal privé.
#
# Usage (root) :
#   sudo bash talos-audit.sh
# Options par variables d'environnement (facultatives) :
#   OUT_BASE=/root                       dossier où créer le résultat
#   OS_URL=https://127.0.0.1:9200        Wazuh indexer / OpenSearch   (OS_USER, OS_PASS)
#   WAZUH_API_URL=https://127.0.0.1:55000  API Wazuh manager          (WAZUH_API_USER, WAZUH_API_PASS)
# Si *_URL et *_USER sont définis sans mot de passe, il est demandé sans écho.

set -u
umask 077
export LC_ALL=C

HOST="$(hostname -s 2>/dev/null || hostname)"
STAMP="$(date +%Y%m%dT%H%M%S)"
OUT="${OUT_BASE:-/root}/talos-audit-${HOST}-${STAMP}"
mkdir -p "$OUT" || { echo "Impossible de créer $OUT" >&2; exit 1; }
SUMMARY="$OUT/00-SUMMARY.txt"
T=60   # timeout par commande (s)

have() { command -v "$1" >/dev/null 2>&1; }

redact() {
  sed -E \
    -e 's#(<(api_key|password|key|secret|token|auth_key|client_secret|hook_url)>)[^<]*#\1***#Ig' \
    -e 's#((password|passwd|secret|token|api_?key|access_?key|secret_?key|credentials?|pass)[[:space:]]*[=:][[:space:]]*).+#\1***#Ig' \
    -e 's#(https?://[^:/@[:space:]]+:)[^@[:space:]]+@#\1***@#g' \
    -e 's#(Authorization: )[^[:space:]]+( [^[:space:]]+)?#\1***#Ig'
}

# run <fichier> <commande...> : exécute, masque les secrets, ajoute au fichier
# (« run f xin <conteneur> cmd… » exécute cmd dans le conteneur s'il est non vide)
run() {
  local f="$OUT/$1"; shift
  if [ "$1" = xin ]; then
    local c="$2"; shift 2
    [ -n "$c" ] && set -- $DOCKER exec "$c" "$@"
  fi
  { echo "### \$ $*"; timeout "$T" "$@" 2>&1 | redact; echo; } >>"$f"
}
# runsh <fichier> "<pipeline shell>"
runsh() {
  local f="$OUT/$1"; shift
  { echo "### \$ $1"; timeout "$T" bash -c "$1" 2>&1 | redact; echo; } >>"$f"
}

check() {  # check OK|WARN|MISS|INFO "message"
  printf '[%-4s] %s\n' "$1" "$2" >>"$SUMMARY"
}
section() { printf '\n== %s ==\n' "$1" >>"$SUMMARY"; }

{
  echo "TALOS audit — hôte: $HOST — $(date -Is)"
  echo "Légende: OK = en place | WARN = à corriger | MISS = absent | INFO = à savoir"
} >"$SUMMARY"

echo "[*] Sortie : $OUT"

# ---------------------------------------------------------------- conteneurs
DOCKER=""
if have docker && timeout 10 docker info >/dev/null 2>&1; then DOCKER=docker
elif have podman; then DOCKER=podman; fi

containers() { [ -n "$DOCKER" ] && timeout 20 $DOCKER ps --format '{{.Names}} {{.Image}}' 2>/dev/null; }
# find_ctr <regex sur nom ou image> -> nom du premier conteneur actif correspondant
find_ctr() { containers | grep -Ei "$1" | head -n1 | awk '{print $1}'; }
# xin <conteneur|""> <commande...> : exécute dans le conteneur, ou sur l'hôte si vide
xin() { local c="$1"; shift; if [ -n "$c" ]; then $DOCKER exec "$c" "$@"; else "$@"; fi; }

# ---------------------------------------------------------------- 1. système
echo "[*] Système"
section "Système"
run 01-system.txt uname -a
runsh 01-system.txt 'cat /etc/os-release'
run 01-system.txt uptime
runsh 01-system.txt 'who -b; last -x -n 10 reboot shutdown 2>/dev/null'
run 01-system.txt df -hT -x tmpfs -x devtmpfs
run 01-system.txt free -h
check INFO "OS: $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-?}") — uptime: $(uptime -p 2>/dev/null)"

if [ -n "$DOCKER" ]; then
  run 02-containers.txt $DOCKER ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
  check INFO "$DOCKER présent : $(containers | wc -l) conteneur(s) actif(s)"
else
  check INFO "ni docker ni podman actif"
fi
runsh 02-services.txt "systemctl list-units --type=service --all --no-pager --plain 2>/dev/null | grep -Ei 'wazuh|velociraptor|thehive|cortex|misp|cassandra|arkime|moloch|opensearch|elasticsearch|minio|crowdsec|fail2ban|glpi|fusioninventory|postfix|dovecot|exim|nginx|apache|httpd|traefik|haproxy|docker|containerd|auditd|sshd'"

# ------------------------------------------------- 2. photo de l'état (asset "observé")
echo "[*] État de l'hôte (ports, processus, comptes, clés, cron, fichiers récents)"
section "Photo de l'état de l'hôte (voir fichiers 03-*)"
run 03-ports.txt ss -tulpnH
PUBPORTS="$(ss -tulnH 2>/dev/null | awk '{print $5}' | grep -Ev '^(127\.|\[::1\]|::1)' | sed -E 's/.*[:]//' | sort -un | tr '\n' ' ')"
check INFO "ports en écoute hors loopback : ${PUBPORTS:-aucun}"
run 03-processes.txt ps -eo pid,ppid,user,lstart,etime,cmd --sort=start_time
runsh 03-accounts.txt "awk -F: '\$3==0{print \"UID0: \"\$1}' /etc/passwd"
runsh 03-accounts.txt "awk -F: '\$7!~/(nologin|false|sync|halt|shutdown)\$/{print \$1\":\"\$3\":\"\$6\":\"\$7}' /etc/passwd"
runsh 03-accounts.txt 'getent group sudo wheel adm docker 2>/dev/null'
runsh 03-accounts.txt 'ls -la /etc/sudoers.d/ 2>/dev/null'
runsh 03-accounts.txt 'last -F -n 100 2>/dev/null'
runsh 03-accounts.txt 'lastb -F -n 50 2>/dev/null'
UID0="$(awk -F: '$3==0' /etc/passwd | wc -l)"
[ "$UID0" -gt 1 ] && check WARN "$UID0 comptes avec UID 0 (voir 03-accounts.txt)"
# empreintes des clés SSH autorisées (pas le contenu)
runsh 03-ssh-keys.txt 'for f in /root/.ssh/authorized_keys* /home/*/.ssh/authorized_keys*; do [ -f "$f" ] || continue; echo "--- $f ($(stat -c "%y" "$f"))"; ssh-keygen -lf "$f" 2>&1; done'
runsh 03-cron.txt 'ls -la --time-style=long-iso /etc/crontab /etc/cron.* /var/spool/cron /var/spool/cron/crontabs 2>/dev/null'
runsh 03-cron.txt 'for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/*; do [ -f "$f" ] && { echo "--- $f"; grep -v "^\s*#" "$f" | grep -v "^\s*$"; }; done'
runsh 03-cron.txt 'systemctl list-timers --all --no-pager 2>/dev/null'
runsh 03-recent-files.txt 'find /etc /usr/bin /usr/sbin /usr/local /bin /sbin /root /tmp /var/tmp /dev/shm -xdev -type f -mtime -30 -printf "%TY-%Tm-%Td %TH:%TM %u %m %s %p\n" 2>/dev/null | sort | tail -n 1000'
if have dpkg; then
  runsh 03-packages.txt 'zgrep -h " install \| remove \| upgrade " /var/log/dpkg.log* 2>/dev/null | sort | tail -n 300'
  runsh 03-packages.txt "dpkg-query -W -f='\${Package} \${Version}\n'"
elif have rpm; then
  run 03-packages.txt rpm -qa --last
fi

# ----------------------------------------------------------- 3. rétention des logs
echo "[*] Rétention des logs"
section "Rétention des logs système"
runsh 04-logs.txt 'ls -la --time-style=long-iso /var/log/auth.log* /var/log/secure* /var/log/syslog* /var/log/messages* /var/log/mail.log* /var/log/maillog* 2>/dev/null'
runsh 04-logs.txt 'journalctl --disk-usage 2>/dev/null; grep -Ev "^\s*(#|$)" /etc/systemd/journald.conf 2>/dev/null'
runsh 04-logs.txt 'grep -Ev "^\s*(#|$)" /etc/logrotate.conf 2>/dev/null'
OLDEST_AUTH="$(ls -1tr --time-style=long-iso /var/log/auth.log* /var/log/secure* 2>/dev/null | head -n1)"
if [ -n "$OLDEST_AUTH" ]; then
  AGE=$(( ( $(date +%s) - $(stat -c %Y "$OLDEST_AUTH") ) / 86400 ))
  if [ "$AGE" -lt 30 ]; then check WARN "logs d'authentification locaux : ~${AGE} j d'historique seulement ($OLDEST_AUTH)"
  else check OK "logs d'authentification locaux : ~${AGE} j d'historique"; fi
else
  check INFO "pas de auth.log/secure (journald seul ?) — voir 04-logs.txt"
fi
if have postconf; then
  section "Messagerie (Postfix)"
  run 04-mail.txt postconf -n
  runsh 04-mail.txt 'mailq 2>/dev/null | tail -n 1'
  Q="$(mailq 2>/dev/null | tail -n1)"
  check INFO "file Postfix : ${Q:-?} (une file énorme = possible envoi de spam → réputation IP/domaine)"
fi

# ------------------------------------------------------------------ 4. Wazuh
echo "[*] Wazuh"
section "Wazuh"
WZC="$(find_ctr 'wazuh[-/._]?manager')"
WZ_ROLE=""
if [ -n "$WZC" ]; then WZ_ROLE=manager
elif [ -x /var/ossec/bin/wazuh-control ]; then
  if [ -x /var/ossec/bin/wazuh-analysisd ]; then WZ_ROLE=manager; else WZ_ROLE=agent; fi
fi
if [ -z "$WZ_ROLE" ]; then
  check MISS "Wazuh : ni manager ni agent sur cet hôte → aucun inventaire (syscollector), FIM ni SCA ici"
else
  check INFO "Wazuh $WZ_ROLE ${WZC:+(conteneur $WZC)}"
  run 05-wazuh.txt xin "$WZC" /var/ossec/bin/wazuh-control info
  run 05-wazuh.txt xin "$WZC" /var/ossec/bin/wazuh-control status
  CONF="$(xin "$WZC" cat /var/ossec/etc/ossec.conf 2>/dev/null)"
  printf '%s\n' "$CONF" | redact >"$OUT/05-wazuh-ossec.conf"
  if [ "$WZ_ROLE" = manager ]; then
    run 05-wazuh.txt xin "$WZC" /var/ossec/bin/agent_control -l
    runsh 05-wazuh-shared-agent.conf "$( [ -n "$WZC" ] && echo "$DOCKER exec $WZC " )sh -c 'for f in /var/ossec/etc/shared/*/agent.conf; do echo \"--- \$f\"; cat \"\$f\"; done'"
    CONF="$CONF
$(cat "$OUT/05-wazuh-shared-agent.conf" 2>/dev/null)"
    AL="$(xin "$WZC" /var/ossec/bin/agent_control -l 2>/dev/null)"
    NACT="$(printf '%s\n' "$AL" | grep -c 'Active')"
    NDIS="$(printf '%s\n' "$AL" | grep -Ec 'Disconnected|Never connected|Pending')"
    check INFO "agents : $NACT actif(s) (manager inclus), $NDIS déconnecté(s)/jamais connecté(s) (voir 05-wazuh.txt)"
    [ "$NDIS" -gt 0 ] && check WARN "$NDIS agent(s) non actifs → inventaire périmé pour eux"
    runsh 05-wazuh.txt "$( [ -n "$WZC" ] && echo "$DOCKER exec $WZC " )sh -c 'du -sh /var/ossec/logs/alerts /var/ossec/logs/archives 2>/dev/null; ls /var/ossec/logs/alerts; find /var/ossec/logs/alerts -name \"ossec-alerts-*\" | sort | head -n 3'"
    OLDEST_AL="$(xin "$WZC" sh -c 'find /var/ossec/logs/alerts -name "ossec-alerts-*" | sort | head -n1' 2>/dev/null)"
    check INFO "plus ancien fichier d'alertes sur le manager : ${OLDEST_AL:-aucun}"
    if printf '%s' "$CONF" | grep -Eq '<logall_json>\s*yes'; then check OK "archives JSON (logall_json) activées"
    else check INFO "logall_json=no : seuls les événements qui déclenchent une alerte sont conservés"; fi
    if printf '%s' "$CONF" | grep -q '<integration>'; then
      check OK "intégrations : $(printf '%s' "$CONF" | grep -oE '<name>[^<]+</name>' | sed -E 's#</?name>##g' | sort -u | tr '\n' ' ')"
    else
      check WARN "aucune <integration> : les alertes Wazuh ne remontent pas vers TheHive/MISP"
    fi
    if printf '%s' "$CONF" | awk '/<vulnerability-detection>/,/<\/vulnerability-detection>/' | grep -Eq '<enabled>\s*yes'; then
      check OK "détection de vulnérabilités activée"
    else check WARN "détection de vulnérabilités non activée (ou config < 4.8)"; fi
  fi
  # syscollector (inventaire)
  SC="$(printf '%s' "$CONF" | awk '/<wodle name="syscollector">/,/<\/wodle>/')"
  if [ -z "$SC" ]; then check WARN "syscollector non déclaré dans ossec.conf → inventaire absent"
  elif printf '%s' "$SC" | grep -Eq '<disabled>\s*yes'; then check WARN "syscollector DÉSACTIVÉ → pas d'inventaire (Hardware/Packages/Ports/...)"
  else check OK "syscollector actif, intervalle $(printf '%s' "$SC" | grep -oE '<interval>[^<]+' | head -n1 | sed 's/<interval>//') — n'enregistre que l'état COURANT"; fi
  # SCA
  if printf '%s' "$CONF" | awk '/<sca>/,/<\/sca>/' | grep -Eq '<enabled>\s*no'; then check WARN "SCA désactivé"
  else check OK "SCA actif (dans le tableau de bord SCA, il faut sélectionner un agent)"; fi
  # FIM
  SYS="$(printf '%s' "$CONF" | awk '/<syscheck>/,/<\/syscheck>/')"
  if printf '%s' "$SYS" | grep -Eq '<disabled>\s*yes'; then check WARN "FIM (syscheck) désactivé"
  else
    check INFO "FIM fréquence : $(printf '%s' "$SYS" | grep -oE '<frequency>[^<]+' | head -n1 | sed 's/<frequency>//')s"
    printf '%s' "$SYS" | grep -q 'report_changes="yes"' && check OK "FIM report_changes présent (diff du contenu conservé)" \
      || check WARN "FIM sans report_changes : l'état AVANT modification (contenu) n'est pas conservé"
    printf '%s' "$SYS" | grep -Eq 'realtime="yes"|whodata="yes"' && check OK "FIM realtime/whodata présent" \
      || check INFO "FIM uniquement planifié (pas realtime/whodata)"
  fi
  # Docker listener
  if printf '%s' "$CONF" | awk '/<wodle name="docker-listener">/,/<\/wodle>/' | grep -Eq '<disabled>\s*no'; then
    check OK "docker-listener activé"
  elif [ -n "$DOCKER" ]; then
    check WARN "docker présent mais docker-listener non activé → tableau de bord Wazuh 'Docker' vide"
  else
    check INFO "docker-listener non activé (pas de docker sur l'hôte)"
  fi
  printf '%s' "$CONF" | grep -q '<active-response>' && check INFO "active-response déclarée (voir 05-wazuh-ossec.conf)"
fi

# ------------------------------------------------------ 5. Wazuh API (facultatif)
if [ -n "${WAZUH_API_URL:-}" ] && [ -n "${WAZUH_API_USER:-}" ]; then
  echo "[*] API Wazuh"
  section "API Wazuh (inventaire par agent)"
  if [ -z "${WAZUH_API_PASS:-}" ]; then read -rsp "Mot de passe API Wazuh ($WAZUH_API_USER) : " WAZUH_API_PASS; echo; fi
  TOKEN="$(curl -sk -u "$WAZUH_API_USER:$WAZUH_API_PASS" -X POST "$WAZUH_API_URL/security/user/authenticate?raw=true" 2>/dev/null)"
  if [ -z "$TOKEN" ] || printf '%s' "$TOKEN" | grep -q '"error"'; then
    check WARN "authentification API Wazuh échouée"
  else
    api() { curl -sk -H "Authorization: Bearer $TOKEN" "$WAZUH_API_URL$1"; }
    api '/agents?limit=500&select=id,name,ip,status,version,lastKeepAlive,os.name,os.version,group' >"$OUT/06-api-agents.json"
    if have jq; then
      for id in $(jq -r '.data.affected_items[].id' "$OUT/06-api-agents.json"); do
        n="$(jq -r --arg i "$id" '.data.affected_items[]|select(.id==$i)|.name' "$OUT/06-api-agents.json")"
        for c in os hardware packages ports processes netaddr hotfixes users groups services browser_extensions; do
          r="$(api "/syscollector/$id/$c?limit=1")"
          cnt="$(printf '%s' "$r" | jq -r '.data.total_affected_items // "n/a"' 2>/dev/null)"
          printf '%s %s %s %s\n' "$id" "$n" "$c" "${cnt:-n/a}"
        done
        printf '%s %s scan_time %s\n' "$id" "$n" "$(api "/syscollector/$id/os" | jq -r '.data.affected_items[0].scan.time // "jamais"' 2>/dev/null)"
        printf '%s %s sca %s\n' "$id" "$n" "$(api "/sca/$id" | jq -c '[.data.affected_items[]|{policy:.policy_id,score,pass,fail}]' 2>/dev/null)"
      done >"$OUT/06-api-inventory.txt"
      check INFO "inventaire par agent (nb d'éléments par catégorie) : 06-api-inventory.txt"
      awk '$3=="packages" && ($4=="0"||$4=="n/a"){print $2}' "$OUT/06-api-inventory.txt" | sort -u | while read -r a; do
        check WARN "agent $a : aucun package inventorié (syscollector inactif ?)"; done
    else
      check INFO "jq absent : seule la liste des agents a été récupérée"
    fi
  fi
fi

# ------------------------------------------------ 6. Wazuh indexer / OpenSearch
if [ -n "${OS_URL:-}" ] && [ -n "${OS_USER:-}" ]; then
  echo "[*] OpenSearch"
  section "Wazuh indexer / OpenSearch"
  if [ -z "${OS_PASS:-}" ]; then read -rsp "Mot de passe OpenSearch ($OS_USER) : " OS_PASS; echo; fi
  osq() { curl -sk -u "$OS_USER:$OS_PASS" "$OS_URL/$1"; }
  osq '_cluster/health?pretty' >"$OUT/07-os-health.json"
  osq '_cat/indices?v&s=index&h=health,status,index,docs.count,store.size,creation.date.string' >"$OUT/07-os-indices.txt"
  osq '_cat/allocation?v' >"$OUT/07-os-allocation.txt"
  osq '_plugins/_ism/policies' >"$OUT/07-os-ism.json"
  osq '_snapshot?pretty' | redact >"$OUT/07-os-snapshots.json"
  H="$(grep -oE '"status" : "[a-z]+"' "$OUT/07-os-health.json" | head -n1 | grep -oE '[a-z]+"$' | tr -d '"')"
  case "$H" in green) check OK "cluster $H";; yellow) check INFO "cluster yellow (normal en mono-nœud)";; *) check WARN "cluster : ${H:-injoignable}";; esac
  NA="$(grep -c 'wazuh-alerts-' "$OUT/07-os-indices.txt")"
  FIRST="$(grep -oE 'wazuh-alerts-[^ ]+' "$OUT/07-os-indices.txt" | sort | head -n1)"
  check INFO "$NA index wazuh-alerts-* (plus ancien : ${FIRST:-aucun})"
  for p in wazuh-states-inventory wazuh-states-vulnerabilities arkime; do
    grep -q "$p" "$OUT/07-os-indices.txt" && check OK "index $p* présents" || check MISS "aucun index $p* dans cet OpenSearch"
  done
  grep -q '"policy_id"' "$OUT/07-os-ism.json" && check INFO "politiques ISM (rétention) : $(grep -oE '"policy_id" ?: ?"[^"]+"' "$OUT/07-os-ism.json" | cut -d'"' -f4 | tr '\n' ' ')" \
    || check WARN "aucune politique ISM : pas de rétention maîtrisée (disque plein → index en lecture seule)"
  grep -q '"type"' "$OUT/07-os-snapshots.json" && check OK "dépôt de snapshots déclaré" \
    || check WARN "aucun dépôt de snapshots : pas de copie figée des alertes/inventaires"
fi

# -------------------------------------------------------------- 7. CrowdSec
echo "[*] CrowdSec / fail2ban"
section "CrowdSec / fail2ban"
CSC="$(find_ctr 'crowdsec')"
if have cscli || [ -n "$CSC" ]; then
  for a in "version" "bouncers list" "machines list" "collections list" "alerts list --limit 50" "decisions list --limit 50"; do
    # shellcheck disable=SC2086
    run 08-crowdsec.txt xin "$CSC" cscli $a
  done
  CSCONF="$(xin "$CSC" cat /etc/crowdsec/config.yaml 2>/dev/null)"
  printf '%s\n' "$CSCONF" | redact >"$OUT/08-crowdsec-config.yaml"
  MA="$(printf '%s' "$CSCONF" | awk '/flush:/,0' | grep -m1 -oE 'max_age:\s*\S+' | awk '{print $2}')"
  check WARN "CrowdSec : purge des alertes après ${MA:-7d (défaut)} — exporter avant perte"
  NB="$(xin "$CSC" cscli bouncers list -o raw 2>/dev/null | tail -n +2 | grep -c .)"
  [ "${NB:-0}" -eq 0 ] && check WARN "CrowdSec : aucun bouncer → détection sans blocage" || check OK "CrowdSec : $NB bouncer(s)"
else
  check MISS "CrowdSec absent"
fi
if have fail2ban-client; then
  run 08-fail2ban.txt fail2ban-client status
  for j in $(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:\s*//p' | tr ',' ' '); do run 08-fail2ban.txt fail2ban-client status "$j"; done
  PA="$(fail2ban-client get dbpurgeage 2>/dev/null | grep -oE '[0-9]+' | head -n1)"
  if [ -n "$PA" ] && [ "$PA" -lt 2592000 ]; then check WARN "fail2ban : historique purgé après $((PA/86400)) j (dbpurgeage)"
  else check INFO "fail2ban dbpurgeage : ${PA:-?} s"; fi
else
  check MISS "fail2ban absent"
fi

# ------------------------------------------ 8. Velociraptor / GLPI / pile SOC
echo "[*] Velociraptor, GLPI, pile SOC"
section "Velociraptor / GLPI / Terraform / pile SOC"
if pgrep -af velociraptor >/dev/null 2>&1 || [ -n "$(find_ctr velociraptor)" ]; then
  runsh 09-velociraptor.txt 'pgrep -af velociraptor; systemctl status --no-pager "*velociraptor*" 2>/dev/null | head -n 20'
  check OK "Velociraptor présent (client ou serveur)"
else
  check WARN "Velociraptor absent : pas de collecte forensique possible à distance sur cet hôte"
fi

GA=""
for b in glpi-agent fusioninventory-agent; do have "$b" && GA="$b"; done
if [ -n "$GA" ]; then
  run 09-glpi-agent.txt "$GA" --version
  runsh 09-glpi-agent.txt "grep -rhE '^\s*(server|tag|delaytime|no-task|tasks)\s*=' /etc/glpi-agent /etc/fusioninventory 2>/dev/null"
  runsh 09-glpi-agent.txt "systemctl status --no-pager $GA 2>/dev/null | head -n 15; journalctl -u $GA -n 30 --no-pager 2>/dev/null"
  SRV="$(grep -rhE '^\s*server\s*=' /etc/glpi-agent /etc/fusioninventory 2>/dev/null | head -n1 | redact)"
  if [ -n "$SRV" ]; then check OK "$GA installé, $SRV"; else check WARN "$GA installé mais aucun 'server =' → n'envoie rien à GLPI"; fi
else
  check WARN "agent GLPI absent → cet hôte n'alimente pas la CMDB GLPI"
fi

for s in thehive cortex misp cassandra arkime minio opensearch wazuh-indexer wazuh-dashboard glpi velociraptor; do
  c="$(find_ctr "$s")"
  u="$(systemctl list-units --type=service --all --no-pager --plain 2>/dev/null | grep -Ei "$s" | awk '{print $1" ("$4")"}' | tr '\n' ' ')"
  [ -n "$c$u" ] && check INFO "$s : ${c:+conteneur $c }${u}"
done
for f in /opt/arkime/etc/config.ini /data/moloch/etc/config.ini; do
  [ -f "$f" ] || continue
  runsh 09-arkime.txt "grep -Ei '^\s*(interface|pcapDir|freeSpaceG|maxFileSizeG|elasticsearch|usersElasticsearch|pcapWriteMethod)' $f"
  FS="$(grep -Ei '^\s*freeSpaceG' "$f" | head -n1)"
  check INFO "Arkime ${FS:-freeSpaceG=5% (défaut)} → les PCAP les plus anciens sont écrasés"
done

# Terraform : fichiers et état (types de ressources seulement, jamais les attributs)
runsh 09-terraform.txt 'find /root /home /opt /srv /var/lib -xdev -maxdepth 6 \( -name "*.tf" -o -name "terraform.tfstate*" -o -name ".terraform.lock.hcl" \) -printf "%TY-%Tm-%Td %TH:%TM %s %p\n" 2>/dev/null | sort'
TFS="$(find /root /home /opt /srv /var/lib -xdev -maxdepth 6 -name 'terraform.tfstate' 2>/dev/null)"
TFD="$(find /root /home /opt /srv /var/lib -xdev -maxdepth 6 -name '*.tf' -printf '%h\n' 2>/dev/null | sort -u)"
if [ -z "$TFD" ] && [ -z "$TFS" ]; then
  check INFO "aucun code/état Terraform trouvé sur cet hôte"
else
  for d in $TFD; do runsh 09-terraform.txt "grep -hE -A4 '^\s*(backend|provider|required_providers)' $d/*.tf"; done
  # shellcheck disable=SC2046
  grep -hqE 'backend\s+"(s3|http|remote|pg|consul)"' $(printf '%s/*.tf ' $TFD) 2>/dev/null \
    && check OK "Terraform : backend distant déclaré" \
    || check WARN "Terraform : état local (pas de backend distant versionné) → pas d'historique de l'état cloud"
  if have jq; then
    for s in $TFS; do
      runsh 09-terraform.txt "echo '--- $s'; jq -r '[.resources[]|.type]|group_by(.)|map(\"\(.[0]) x\(length)\")[]' '$s'"
    done
  fi
fi

# ------------------------------------------------------------------ fin
cat >>"$SUMMARY" <<'EOF'

-----------------------------------------------------------------------
Rappel : ce résultat contient des IP/noms d'hôtes/configs (secrets masqués).
NE PAS le pousser dans le dépôt Git public. Le transmettre par canal privé.
EOF

TAR="$OUT.tar.gz"
tar -C "$(dirname "$OUT")" -czf "$TAR" "$(basename "$OUT")" 2>/dev/null
sha256sum "$TAR" >"$TAR.sha256"
echo
cat "$SUMMARY"
echo
echo "[*] Terminé : $TAR"
echo "    sha256 : $(cut -d' ' -f1 "$TAR.sha256")"
