#!/usr/bin/env python3
"""Intégration Wazuh « custom-supervision » : classe, tague et notifie par e-mail.

Appelée par wazuh-integratord pour chaque alerte qui passe les filtres <level>/<group>
de ossec.conf :  custom-supervision <fichier_alerte> <api_key> <hook_url> [...]

- hook_url : smtp://hote:25  (sans TLS)  |  smtps://hote:465  |  smtp+starttls://hote:587
- api_key  : "utilisateur:motdepasse" SMTP si authentification, sinon vide
- Réglages : /var/ossec/etc/talos-supervision.json (voir talos-supervision.json.example)

Chaque alerte reçoit :
  catégorie  (compromission, authentification, integrite, comptes, vulnerabilite,
              conformite, reseau, messagerie, conteneur, disponibilite, autre)
  gravité    1 à 5 — 1 = information, 5 = critique. Déduite du niveau Wazuh, et
             relevée d'un cran si l'actif porte asset.criticality=haute.
  tags       N<gravité>, gravite:<nom>, catégorie, labels de l'actif
             (agent.labels.asset.*), techniques MITRE, groupes de règle

             niveau Wazuh  gravité TALOS
                  >= 14        5  critique     notifié
                  12-13        4  majeur       notifié
                   9-11        3  moyen        non notifié (seuil par défaut)
                    6-8        2  faible       non notifié
                   <= 5        1  information  non notifié

Seules les alertes de gravité >= `niveau_min` (4 par défaut) sont envoyées ; en dessous,
l'alerte reste dans Wazuh mais n'encombre pas la boîte de supervision.
Les tags sont dans l'objet du mail et dans les en-têtes X-TALOS-* (filtrage côté boîte).

Anti-inondation : au plus N mails/heure par (règle, agent) et M/heure au total ;
les alertes retenues sont comptées et signalées dans le mail suivant.
TALOS_DRYRUN=1 : affiche le mail au lieu de l'envoyer.
"""
import fcntl
import json
import os
import smtplib
import socket
import ssl
import sys
import time
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from urllib.parse import urlparse

WAZUH_PATH = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
CONFIG_FILE = os.path.join(WAZUH_PATH, "etc", "talos-supervision.json")
STATE_FILE = os.environ.get("TALOS_STATE") or os.path.join(WAZUH_PATH, "var", "talos-supervision.state")
LOG_FILE = os.path.join(WAZUH_PATH, "logs", "integrations.log")

DEFAULTS = {
    "to": ["supervision@youzurz.com"],
    "from": "wazuh@" + socket.getfqdn(),
    "subject_prefix": "[TALOS]",
    "max_per_key_per_hour": 3,
    "max_per_hour": 60,
    # Gravité 1 (information) à 5 (critique). En dessous de ce seuil : aucune notification.
    "niveau_min": 4,
    # Disjoncteur : après N échecs d'affilée, on suspend les tentatives pendant X secondes.
    "max_consecutive_failures": 5,
    "mute_seconds_after_failures": 900,
}

# Première règle qui correspond l'emporte : l'ordre compte.
CATEGORIES = [
    ("compromission", {"rootcheck", "rootkit", "trojan", "malware", "virustotal", "yara",
                       "exploit_attempt", "attack", "shellshock", "webshell"}),
    ("comptes", {"adduser", "addgroup", "account_changed", "groupadd", "usermod",
                 "sudo", "su", "privilege_escalation"}),
    ("authentification", {"authentication_failed", "authentication_failures",
                          "authentication_success", "invalid_login", "multiple_auth_failures"}),
    ("integrite", {"syscheck", "syscheck_file", "syscheck_entry_added",
                   "syscheck_entry_modified", "syscheck_entry_deleted", "syscheck_registry"}),
    ("vulnerabilite", {"vulnerability-detector"}),
    ("conformite", {"sca", "oscap", "ciscat", "policy_monitoring", "policy_changed"}),
    ("messagerie", {"postfix", "sendmail", "dovecot", "exim", "spam", "imapd", "mail"}),
    ("conteneur", {"docker", "podman", "kubernetes"}),
    ("reseau", {"web", "accesslog", "web_scan", "recon", "firewall", "ids", "suricata",
                "crowdsec", "fail2ban", "iptables", "nginx", "apache", "connection_attempt"}),
    ("disponibilite", {"service_availability", "system_error", "system_shutdown",
                       "ossec", "agent_disconnected", "low_diskspace"}),
]
# Échelle de gravité TALOS : 1 = le moins grave, 5 = le plus grave.
# (Attention : c'est l'INVERSE de l'échelle Wazuh « level », et de l'ancienne P1..P4.)
# Seuil de notification par défaut : 4. En dessous, l'alerte est classée et tracée,
# mais aucun message n'est envoyé.
NIVEAUX = {5: "critique", 4: "majeur", 3: "moyen", 2: "faible", 1: "information"}

# Correspondance niveau Wazuh (0-15) → gravité TALOS (1-5).
# Lue de haut en bas : le premier seuil atteint gagne.
SEUILS_WAZUH = [(14, 5), (12, 4), (9, 3), (6, 2), (0, 1)]

CRITICITE_HAUTE = ("haute", "high", "critique", "critical")


def log(msg):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(time.strftime("%Y/%m/%d %H:%M:%S") + " custom-supervision: " + msg + "\n")
    except OSError:
        pass


def load_config():
    cfg = dict(DEFAULTS)
    try:
        with open(CONFIG_FILE) as f:
            cfg.update(json.load(f))
    except FileNotFoundError:
        pass
    if isinstance(cfg["to"], str):
        cfg["to"] = [a.strip() for a in cfg["to"].split(",") if a.strip()]
    return cfg


def flatten(d, prefix=""):
    """{"asset": {"role": "x"}} ou {"asset.role": "x"} -> {"asset.role": "x"}"""
    out = {}
    for k, v in (d or {}).items():
        key = prefix + k
        if isinstance(v, dict):
            out.update(flatten(v, key + "."))
        else:
            out[key] = str(v)
    return out


def classify(alert):
    rule = alert.get("rule", {})
    groups = set(rule.get("groups", []))
    category = next((name for name, gs in CATEGORIES if groups & gs), "autre")

    level = int(rule.get("level", 0))
    niveau = next(n for seuil, n in SEUILS_WAZUH if level >= seuil)

    labels = flatten(alert.get("agent", {}).get("labels"))
    # Un actif critique monte l'alerte d'un cran : sur un serveur sensible, un fait
    # ordinaire ailleurs mérite d'être vu.
    if labels.get("asset.criticality", "").lower() in CRITICITE_HAUTE:
        niveau = min(niveau + 1, 5)

    # Tags : le niveau d'abord, sous deux formes, pour pouvoir filtrer côté boîte aux
    # lettres aussi bien sur « N4 » que sur « gravite:majeur ».
    tags = ["N%d" % niveau, "gravite:" + NIVEAUX[niveau], category]
    tags += ["%s:%s" % (k.split(".", 1)[-1], v) for k, v in sorted(labels.items())
             if k.startswith("asset.")]
    mitre = rule.get("mitre", {})
    tags += ["mitre:" + t for t in mitre.get("id", [])]
    tags += ["group:" + g for g in sorted(groups)]
    return category, niveau, labels, tags


def _with_state(mutate):
    """Ouvre l'état sous verrou exclusif, applique mutate(st), enregistre, rend son résultat.
    L'état est remis à zéro à chaque heure, sauf les compteurs de messages retenus et le
    disjoncteur, qui doivent survivre au changement d'heure."""
    now = int(time.time())
    hour = now - now % 3600
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "a+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.seek(0)
        try:
            st = json.load(f)
        except ValueError:
            st = {}
        if st.get("hour") != hour:
            st = {"hour": hour, "total": 0, "keys": {},
                  "suppressed": st.get("suppressed", {}),
                  "fail_streak": st.get("fail_streak", 0),
                  "muted_until": st.get("muted_until", 0)}
        for k, v in (("total", 0), ("keys", {}), ("suppressed", {}),
                     ("fail_streak", 0), ("muted_until", 0)):
            st.setdefault(k, v)
        out = mutate(st, now)
        f.seek(0)
        f.truncate()
        json.dump(st, f)
    return out


def throttle(key, cfg):
    """Réserve un envoi. Retourne (envoyer?, nb_retenues_pour_cette_clé).

    La réservation est PROVISOIRE : si l'envoi échoue, release() la rend, pour qu'un
    message jamais parti ne consomme pas le quota des alertes qui, elles, partiront.
    Un disjoncteur coupe les tentatives quand le relais refuse en série : sans lui, chaque
    alerte retente, le relais voit des milliers de rejets et son antispam finit par
    apprendre que nos alertes sont du spam."""
    mute = int(cfg.get("mute_seconds_after_failures", 900))
    max_fail = int(cfg.get("max_consecutive_failures", 5))

    def mutate(st, now):
        if max_fail and st["fail_streak"] >= max_fail and now < st["muted_until"]:
            st["suppressed"][key] = st["suppressed"].get(key, 0) + 1
            return False, 0
        if (st["keys"].get(key, 0) >= cfg["max_per_key_per_hour"]
                or st["total"] >= cfg["max_per_hour"]):
            st["suppressed"][key] = st["suppressed"].get(key, 0) + 1
            return False, 0
        st["keys"][key] = st["keys"].get(key, 0) + 1
        st["total"] += 1
        return True, st["suppressed"].pop(key, 0)

    return _with_state(mutate)


def release(key, suppressed, mute_seconds=900):
    """Rend une réservation dont l'envoi a échoué et arme le disjoncteur.
    Retourne True si le disjoncteur vient de se déclencher (pour ne le journaliser qu'une fois)."""
    def mutate(st, now):
        if st["keys"].get(key, 0) > 0:
            st["keys"][key] -= 1
        if st["total"] > 0:
            st["total"] -= 1
        # le message n'est jamais parti : il compte lui-même comme retenu
        st["suppressed"][key] = st["suppressed"].get(key, 0) + suppressed + 1
        st["fail_streak"] += 1
        was_open = now < st["muted_until"]
        st["muted_until"] = now + mute_seconds
        return not was_open
    return _with_state(mutate)


def mark_success():
    """Réarme le disjoncteur après un envoi réussi."""
    def mutate(st, _now):
        st["fail_streak"] = 0
        st["muted_until"] = 0
    _with_state(mutate)


def build_mail(alert, cfg, category, niveau, labels, tags, suppressed):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    role = labels.get("asset.role", "")
    subject = "%s[N%d %s][%s]%s %s — %s (règle %s, niv. Wazuh %s)" % (
        cfg["subject_prefix"], niveau, NIVEAUX[niveau], category,
        "[%s]" % role if role else "",
        agent.get("name", "?"), rule.get("description", "?"), rule.get("id", "?"),
        rule.get("level", "?"))

    lines = [
        "Gravité       : %d/5 (%s)" % (niveau, NIVEAUX[niveau]),
        "Catégorie     : " + category,
        "Tags          : " + ", ".join(tags),
        "Horodatage    : " + str(alert.get("timestamp", "")),
        "Agent         : %s (id %s, ip %s)" % (agent.get("name"), agent.get("id"), agent.get("ip", "-")),
        "Manager       : " + str(alert.get("manager", {}).get("name", "")),
        "Règle         : %s niv.%s — %s" % (rule.get("id"), rule.get("level"), rule.get("description")),
        "Emplacement   : " + str(alert.get("location", "")),
    ]
    for k in ("srcip", "srcuser", "dstuser"):
        if alert.get("data", {}).get(k):
            lines.append("%-14s: %s" % (k, alert["data"][k]))
    if "syscheck" in alert:
        sc = alert["syscheck"]
        lines.append("Fichier       : %s (%s)" % (sc.get("path"), sc.get("event")))
        if sc.get("diff"):
            lines.append("Diff          :\n" + sc["diff"][:2000])
    if labels:
        lines.append("Actif (labels): " + ", ".join("%s=%s" % kv for kv in sorted(labels.items())))
    if suppressed:
        lines.append("\n%d alerte(s) identique(s) (même règle, même agent) retenue(s) "
                     "par l'anti-inondation depuis le dernier envoi." % suppressed)
    lines += ["", "--- Alerte complète ---", json.dumps(alert, indent=2, ensure_ascii=False)[:20000]]

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg["from"]
    msg["To"] = ", ".join(cfg["to"])
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=cfg["from"].split("@")[-1])
    msg["X-TALOS-Level"] = str(niveau)
    msg["X-TALOS-Severity"] = NIVEAUX[niveau]
    msg["X-TALOS-Category"] = category
    msg["X-TALOS-Asset"] = role or agent.get("name", "")
    msg["X-TALOS-Tags"] = " ".join(tags)[:900]
    msg["X-TALOS-Rule"] = str(rule.get("id", ""))
    msg.set_content("\n".join(lines))
    return msg


def send(msg, hook_url, api_key):
    u = urlparse(hook_url or "smtp://127.0.0.1:25")
    host, port = u.hostname or "127.0.0.1", u.port
    if u.scheme == "smtps":
        s = smtplib.SMTP_SSL(host, port or 465, timeout=30, context=ssl.create_default_context())
    else:
        s = smtplib.SMTP(host, port or 25, timeout=30)
        if u.scheme == "smtp+starttls":
            s.starttls(context=ssl.create_default_context())
    try:
        if api_key and ":" in api_key:
            user, pwd = api_key.split(":", 1)
            s.login(user, pwd)
        s.send_message(msg)
    finally:
        s.quit()


def main(argv):
    if len(argv) < 2:
        log("usage: custom-supervision <alert_file> [api_key] [hook_url]")
        return 1
    alert_file = argv[1]
    api_key = argv[2] if len(argv) > 2 else ""
    hook_url = argv[3] if len(argv) > 3 else ""
    cfg = load_config()
    with open(alert_file) as f:
        alert = json.load(f)

    category, niveau, labels, tags = classify(alert)
    # Seuil de notification : en dessous, l'alerte reste dans Wazuh mais n'est pas notifiée.
    if niveau < int(cfg.get("niveau_min", 4)):
        return 0
    key = "%s|%s" % (alert.get("rule", {}).get("id"), alert.get("agent", {}).get("id"))
    ok, suppressed = throttle(key, cfg)
    if not ok:
        return 0
    msg = build_mail(alert, cfg, category, niveau, labels, tags, suppressed)
    if os.environ.get("TALOS_DRYRUN"):
        print(msg)
        return 0
    mute = int(cfg.get("mute_seconds_after_failures", 900))
    try:
        send(msg, hook_url, api_key)
    except Exception as e:  # noqa: BLE001 — integratord ne doit jamais planter
        if release(key, suppressed, mute):
            log("échec d'envoi (%s) : %s — tentatives suspendues %d s "
                "(les alertes restent comptées comme retenues)" % (hook_url, e, mute))
        return 2
    mark_success()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
