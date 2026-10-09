#!/usr/bin/env bash
# Contrôle de durcissement Wazuh, en lecture seule. N'affiche jamais de secret ni d'adresse privée.
# Usage : wazuh-durcissement-audit.sh manager [conteneur_manager] [conteneur_indexer]   (sur l'hôte du manager)
#         wazuh-durcissement-audit.sh agent                                             (sur chaque hôte surveillé)
# Sortie : une ligne par contrôle « OK|KO|A_VOIR <id> <libellé> — <preuve> », puis les compteurs.
set -u
MODE="${1:-manager}"; MGR="${2:-wam_master}"; IDX="${3:-wai_indexer}"
ok=0; ko=0; av=0
r() { # r <statut> <id> <libellé> <preuve>
	case "$1" in OK) ok=$((ok+1));; KO) ko=$((ko+1));; *) av=$((av+1));; esac
	printf '%-6s %-4s %s — %s\n' "$1" "$2" "$3" "$4" | sed -E 's/\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/<ip>/g'
}
x() { docker exec "$MGR" sh -c "$1" 2>/dev/null; }
conf() { x "cat /var/ossec/etc/ossec.conf"; }
bloc() { conf | tr -d '\n' | grep -o "<$1>.*</$1>" | head -1; }
jours_validite() { local fin; fin=$(openssl x509 -enddate -noout 2>/dev/null | cut -d= -f2) || return 1; [ -n "$fin" ] || return 1; echo $(( ( $(date -d "$fin" +%s) - $(date +%s) ) / 86400 )); }

echo "# Contrôle de durcissement Wazuh — mode $MODE — $(hostname) — $(date -u +%FT%TZ)"

if [ "$MODE" = manager ]; then
	docker inspect "$MGR" >/dev/null 2>&1 || { echo "conteneur $MGR introuvable"; exit 2; }
	auth=$(bloc auth)

	# --- Enrôlement des agents
	if echo "$auth" | grep -q '<disabled>yes</disabled>'; then r OK M01 "Enrôlement automatique (authd)" "désactivé"
	elif echo "$auth" | grep -q '<use_password>yes</use_password>' && x "test -s /var/ossec/etc/authd.pass" ; then r OK M01 "Enrôlement protégé par mot de passe" "use_password=yes, authd.pass présent"
	else r KO M01 "Enrôlement protégé par mot de passe" "authd actif sans mot de passe : tout hôte qui joint le port 1515 peut s'enrôler"; fi
	if echo "$auth" | grep -q '<ssl_agent_ca>[^<]'; then r OK M02 "Certificat d'agent exigé à l'enrôlement" "ssl_agent_ca défini"
	else r A_VOIR M02 "Certificat d'agent exigé à l'enrôlement" "ssl_agent_ca vide (recommandé si une PKI d'agents existe)"; fi
	if echo "$auth" | grep -q '<force>.*<enabled>yes</enabled>'; then r A_VOIR M03 "Remplacement d'un agent homonyme" "force.enabled=yes : un hôte peut usurper le nom d'un agent déconnecté"
	else r OK M03 "Remplacement d'un agent homonyme" "force désactivé"; fi

	# --- Canal agents → manager
	rem=$(bloc remote)
	echo "$rem" | grep -q '<connection>secure</connection>' && r OK M04 "Canal agents chiffré (remote secure)" "connection=secure" || r KO M04 "Canal agents chiffré (remote secure)" "connection secure absente"

	# --- Exposition réseau des ports publiés par Docker
	for c in "$MGR" "$IDX" wad_dashboard; do
		docker inspect "$c" >/dev/null 2>&1 || continue
		pub=$(docker inspect --format '{{range $p,$b := .HostConfig.PortBindings}}{{range $b}}{{$p}}@{{.HostIp}} {{end}}{{end}}' "$c")
		large=$(echo "$pub" | tr ' ' '\n' | grep -E '@(0\.0\.0\.0|::|)$' | sed 's/@.*//' | paste -sd, -)
		if [ -n "$large" ]; then r KO M05 "Ports de $c liés à une adresse précise" "publiés sur toutes les interfaces : $large"
		else r OK M05 "Ports de $c liés à une adresse précise" "${pub:-aucun port publié}"; fi
	done

	# --- API du manager
	api=$(x "cat /var/ossec/api/configuration/api.yaml")
	echo "$api" | grep -Eq '^\s*https:' && echo "$api" | grep -A2 -E '^\s*https:' | grep -q 'enabled: *no' && r KO M06 "API en HTTPS" "https.enabled=no" || r OK M06 "API en HTTPS" "HTTPS par défaut ou explicite"
	echo "$api" | grep -Eq '^\s*max_login_attempts:' && r OK M07 "API : limite de tentatives" "max_login_attempts défini" || r A_VOIR M07 "API : limite de tentatives" "valeur par défaut (50 par période)"

	# --- Cluster : clé par défaut des images Docker publiques
	cl=$(bloc cluster)
	if echo "$cl" | grep -q '<disabled>no</disabled>'; then
		k=$(echo "$cl" | grep -o '<key>[^<]*</key>' | sed 's/<[^>]*>//g' | sha256sum | cut -c1-16)
		[ "$k" = "$(printf 'c98b62a9b6169ac5f67dae55ae4a9088' | sha256sum | cut -c1-16)" ] && r KO M08 "Clé de cluster personnalisée" "clé par défaut de wazuh-docker (publique)" || r OK M08 "Clé de cluster personnalisée" "clé différente de la valeur publique (empreinte comparée, non affichée)"
	else r OK M08 "Clé de cluster personnalisée" "cluster désactivé"; fi

	# --- Certificats
	d=$(x "cat /var/ossec/etc/sslmanager.cert" | jours_validite) && { [ "$d" -gt 30 ] && r OK M09 "Certificat d'enrôlement valide" "$d jours restants" || r KO M09 "Certificat d'enrôlement valide" "$d jours restants"; } || r A_VOIR M09 "Certificat d'enrôlement valide" "sslmanager.cert illisible"
	if docker inspect "$IDX" >/dev/null 2>&1; then
		for f in $(docker exec "$IDX" sh -c 'ls /usr/share/wazuh-indexer/certs/*.pem /usr/share/wazuh-indexer/config/certs/*.pem /etc/wazuh-indexer/certs/*.pem 2>/dev/null | grep -v -i key'); do
			d=$(docker exec "$IDX" cat "$f" 2>/dev/null | jours_validite) || continue
			[ "$d" -gt 30 ] && r OK M10 "Certificat indexeur $(basename "$f")" "$d jours restants" || r KO M10 "Certificat indexeur $(basename "$f")" "$d jours restants"
		done
	fi

	# --- Détection
	vd=$(bloc vulnerability-detection)
	echo "$vd" | grep -q '<enabled>yes</enabled>' && r OK M11 "Détection de vulnérabilités" "activée" || r KO M11 "Détection de vulnérabilités" "désactivée ou absente"
	nar=$(conf | grep -c '<active-response>')
	[ "$nar" -gt 0 ] && r OK M12 "Réponse active configurée" "$nar bloc(s) active-response" || r A_VOIR M12 "Réponse active configurée" "aucun bloc : détection sans réaction automatique"
	conf | grep -q '<logall_json>yes</logall_json>' && r OK M13 "Archive de tous les événements (logall_json)" "activée" || r A_VOIR M13 "Archive de tous les événements (logall_json)" "seules les alertes sont conservées : pas de reconstitution a posteriori"

	# --- Qualité de la détection : bruit et règles génériques
	today=$(date -u +%Y-%m-%d)
	tot=$(x "grep -c '\"timestamp\":\"$today' /var/ossec/logs/alerts/alerts.json"); tot=${tot:-0}
	gen=$(x "grep '\"timestamp\":\"$today' /var/ossec/logs/alerts/alerts.json | grep -c '\"id\":\"1002\"'"); gen=${gen:-0}
	if [ "$tot" -gt 0 ]; then pct=$(( gen * 100 / tot ))
		[ "$pct" -lt 10 ] && r OK M14 "Part de la règle générique 1002" "$gen / $tot alertes aujourd'hui ($pct %)" || r KO M14 "Part de la règle générique 1002" "$gen / $tot alertes aujourd'hui ($pct %) : des flux arrivent sans règle dédiée"
	else r A_VOIR M14 "Part de la règle générique 1002" "aucune alerte aujourd'hui"; fi

	# --- Intégrations : envoi réel
	for i in $(conf | tr -d '\n' | grep -o '<integration>[^/]*<name>[^<]*' | sed 's/.*<name>//'); do
		s=$(x "grep -c '$i' /var/ossec/logs/integrations.log"); e=$(x "grep '$i' /var/ossec/logs/integrations.log | grep -c -i -E 'error|fail|échec|refus'")
		[ "${s:-0}" -gt 0 ] && [ "${e:-0}" -eq 0 ] && r OK M15 "Intégration $i" "$s lignes, 0 erreur" || r KO M15 "Intégration $i" "${e:-?} erreur(s) sur ${s:-0} lignes de integrations.log"
	done
	# URL interne à fournir par l'appelant (voir CLAUDE.local.md) : aucun nom d'hôte réel ici.
	if [ -n "${GLPI_API_URL:-}" ]; then
		x "python3 -c 'import urllib.request;urllib.request.urlopen(\"$GLPI_API_URL\",timeout=8)'" && r OK M16 "Autorité de certification interne reconnue par le manager" "URL interne vérifiée" || r KO M16 "Autorité de certification interne reconnue par le manager" "certificat interne refusé depuis le conteneur : une intégration HTTPS interne échouera"
	else
		r A_VOIR M16 "Autorité de certification interne reconnue par le manager" "GLPI_API_URL non fourni : contrôle ignoré"
	fi

	# --- Parc d'agents
	l=$(x "/var/ossec/bin/agent_control -l")
	act=$(echo "$l" | grep -c 'Active'); dis=$(echo "$l" | grep -c -E 'Disconnected'); nev=$(echo "$l" | grep -c -E 'Never connected')
	[ "$dis$nev" = "00" ] && r OK M17 "Agents déconnectés" "$act actifs, 0 déconnecté" || r KO M17 "Agents déconnectés" "$act actifs, $dis déconnectés, $nev jamais connectés"
	doub=$(echo "$l" | sed -n 's/.*Name: \([^,]*\),.*/\1/p' | sed -E 's/-(systemd|docker|host|container)$//' | sort | uniq -d | paste -sd, -)
	[ -z "$doub" ] && r OK M18 "Agents en double sur un même hôte" "aucun" || r KO M18 "Agents en double sur un même hôte" "$doub : chaque événement est compté deux fois"
	# --- Zero Trust : posture, inventoire, renseignement sur les menaces
	conf | tr -d '\n' | grep -o '<sca>.*</sca>' | grep -q '<enabled>yes</enabled>' && r OK M19 "Évaluation de configuration (SCA)" "activée sur le manager" || r KO M19 "Évaluation de configuration (SCA)" "désactivée : pas de mesure de posture"
	conf | tr -d '\n' | grep -o '<wodle name="syscollector">.*' | grep -q '<disabled>no</disabled>' && r OK M20 "Inventaire des actifs (syscollector)" "activé" || r A_VOIR M20 "Inventaire des actifs (syscollector)" "non trouvé dans ossec.conf du manager (vérifier la config des groupes)"
	nl=$(x "ls /var/ossec/etc/lists" | grep -v -E '^(amazon|audit-keys|security-eventchannel|malicious-ioc)' | wc -l)
	[ "$nl" -gt 0 ] && r OK M21 "Listes de menaces personnalisées (CDB)" "$nl liste(s) propres" || r A_VOIR M21 "Listes de menaces personnalisées (CDB)" "aucune liste propre : pas d'IOC maison (CrowdSec, MISP)"
	ti=$(conf | tr -d '\n' | grep -o '<integration>[^/]*<name>[^<]*' | sed 's/.*<name>//' | grep -c -i -E 'virustotal|misp|maltiverse|crowdsec|opencti')
	[ "$ti" -gt 0 ] && r OK M22 "Renseignement sur les menaces branché" "$ti intégration(s)" || r A_VOIR M22 "Renseignement sur les menaces branché" "aucune (MISP, VirusTotal, CrowdSec absents de la chaîne)"
fi

if [ "$MODE" = agent ]; then
	# --- Hôte surveillé
	sa=$(systemctl is-active wazuh-agent 2>/dev/null); ca=$(docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null | grep -i wazuh-agent | cut -d' ' -f1 | paste -sd, -)
	docker ps >/dev/null 2>&1 || r A_VOIR A00 "Visibilité des conteneurs" "$(id -un) ne peut pas lister Docker : un agent conteneurisé peut exister sans être vu (contrôler aussi agent_control -l sur le manager)"
	[ "$sa" = active ] || [ -n "$ca" ] && r OK A01 "Agent Wazuh présent" "service=${sa:-absent} conteneur=${ca:-aucun}" || r KO A01 "Agent Wazuh présent" "aucun agent"
	[ "$sa" = active ] && [ -n "$ca" ] && r KO A02 "Un seul agent par hôte" "service ET conteneur ($ca) : doublons d'alertes" || r OK A02 "Un seul agent par hôte" "un seul chemin de collecte"
	for c in ${ca//,/ }; do
		p=$(docker inspect --format '{{.HostConfig.Privileged}}' "$c"); s=$(docker inspect --format '{{range .Mounts}}{{.Source}} {{end}}' "$c" | grep -c docker.sock)
		[ "$p" = true ] && r KO A03 "Conteneur agent $c non privilégié" "privileged=true : root complet sur l'hôte" || r OK A03 "Conteneur agent $c non privilégié" "privileged=false"
		[ "$s" -gt 0 ] && r KO A04 "Conteneur agent $c sans socket Docker" "docker.sock monté : contrôle total de Docker (un montage en lecture seule ne protège pas)" || r OK A04 "Conteneur agent $c sans socket Docker" "socket absent"
	done
	systemctl is-active auditd >/dev/null 2>&1 && r OK A05 "auditd actif" "actif" || r KO A05 "auditd actif" "absent : pas de traçabilité des commandes privilégiées"
	[ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = yes ] && r OK A06 "Horloge synchronisée" "NTP synchronisé" || r KO A06 "Horloge synchronisée" "non synchronisée : corrélation horaire faussée"
	sudo -n true 2>/dev/null && r KO A07 "Compte d'exploitation sans sudo sans mot de passe" "$(id -un) obtient root sans mot de passe" || r OK A07 "Compte d'exploitation sans sudo sans mot de passe" "mot de passe exigé"
	id -nG | grep -qw docker && r A_VOIR A08 "Compte d'exploitation hors groupe docker" "$(id -un) dans docker (équivaut à root)" || r OK A08 "Compte d'exploitation hors groupe docker" "non membre"
fi

echo "# Bilan : $ok OK, $ko KO, $av à voir"
