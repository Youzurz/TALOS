#!/var/ossec/framework/python/bin/python3
"""Intégration Wazuh → GLPI : chaque alerte retenue devient un incident GLPI.

Appel par wazuh-integratord : custom-glpi <fichier_alerte> [api_key] [hook_url]
Réglages : /var/ossec/etc/talos-glpi.json (root:wazuh, 640), jamais affiché ni journalisé :
  {"url": "https://<glpi-interne>/apirest.php", "app_token": "...", "user_token": "...",
   "ca_bundle": "/var/ossec/etc/yuz-ca.pem", "niveau_min": 8, "entities_id": 0}
Test à blanc : TALOS_DRYRUN=1 TALOS_GLPI_STATE=/tmp/g.state custom-glpi alerte.json
"""
import json
import os
import ssl
import sys
import time
import urllib.request

CONF = os.environ.get("TALOS_GLPI_CONF", "/var/ossec/etc/talos-glpi.json")
STATE = os.environ.get("TALOS_GLPI_STATE", "/var/ossec/logs/talos-glpi.state")
LOG_FILE = "/var/ossec/logs/integrations.log"
DRYRUN = os.environ.get("TALOS_DRYRUN") == "1"
FENETRE = 3600          # dédoublonnage : une seule fiche par clé et par heure
MAX_PAR_HEURE = 30      # plafond global de fiches créées par heure


def log(msg):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(time.strftime("%Y/%m/%d %H:%M:%S") + " custom-glpi: " + msg + "\n")
    except OSError:
        pass


def priorite(level):
    # Même barème que custom-supervision : P1 ≥ 13, P2 ≥ 10, P3 ≥ 7, sinon P4
    if level >= 13:
        return "P1", 5
    if level >= 10:
        return "P2", 4
    if level >= 7:
        return "P3", 3
    return "P4", 2


def cle_dedoublonnage(alert):
    data = alert.get("data", {})
    corr = data.get("correlation_id")
    if corr:
        return "corr:" + str(corr)
    # Deux agents peuvent lire le même fichier (H72) : la clé ignore l'agent si l'empreinte existe
    empreinte = data.get("event", {}).get("public_ip_sha256_16") if isinstance(data.get("event"), dict) else None
    if empreinte:
        return "ip:%s:%s" % (alert.get("rule", {}).get("id"), empreinte)
    return "regle:%s:%s" % (alert.get("rule", {}).get("id"), alert.get("agent", {}).get("name"))


def charger_etat():
    try:
        with open(STATE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def autoriser(etat, cle, maintenant):
    etat = {k: v for k, v in etat.items() if maintenant - v < FENETRE}
    if cle in etat:
        return etat, False
    if len(etat) >= MAX_PAR_HEURE:
        return etat, False
    return etat, True


def construire_ticket(alert, conf):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    level = int(rule.get("level", 0))
    prio, urgence = priorite(level)
    data = alert.get("data", {})
    qq = data.get("qqoqccp", {}) if isinstance(data.get("qqoqccp"), dict) else {}
    titre = "[TALOS][%s] %s — %s" % (prio, agent.get("name", "?"), rule.get("description", "alerte Wazuh"))[:250]
    lignes = [
        "Alerte Wazuh convertie en incident par custom-glpi.",
        "",
        "Qui      : %s" % (qq.get("qui") or data.get("srcuser") or "—"),
        "Quoi     : %s (règle %s, niveau %s)" % (rule.get("description", "—"), rule.get("id", "—"), level),
        "Où       : agent %s" % agent.get("name", "—"),
        "Quand    : %s" % alert.get("timestamp", "—"),
        "Comment  : groupes %s ; MITRE %s" % (",".join(rule.get("groups", [])), ",".join(rule.get("mitre", {}).get("id", [])) or "—"),
        "Combien  : %s" % (qq.get("combien") or rule.get("firedtimes", "—")),
        "Pourquoi : %s" % (qq.get("pourquoi") or "priorité %s" % prio),
        "",
        "Identifiant d'alerte Wazuh : %s" % alert.get("id", "—"),
        "Corrélation : %s" % cle_dedoublonnage(alert),
    ]
    return {"input": {
        "name": titre,
        "content": "\n".join(lignes),
        "type": 1,                      # 1 = incident
        "urgency": urgence,
        "impact": urgence,
        "entities_id": int(conf.get("entities_id", 0)),
    }}


def appel(conf, chemin, methode, entetes, corps=None):
    ctx = ssl.create_default_context(cafile=conf.get("ca_bundle") or None)
    req = urllib.request.Request(conf["url"].rstrip("/") + chemin, method=methode,
                                 data=json.dumps(corps).encode() if corps is not None else None,
                                 headers=dict(entetes, **{"Content-Type": "application/json"}))
    with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
        return r.status, json.loads(r.read().decode() or "null")


def envoyer(conf, ticket):
    base = {"App-Token": conf["app_token"]}
    _, sess = appel(conf, "/initSession", "GET", dict(base, Authorization="user_token " + conf["user_token"]))
    jeton = sess["session_token"]
    try:
        statut, rep = appel(conf, "/Ticket", "POST", dict(base, **{"Session-Token": jeton}), ticket)
        return statut, rep.get("id") if isinstance(rep, dict) else None
    finally:
        try:
            appel(conf, "/killSession", "GET", dict(base, **{"Session-Token": jeton}))
        except Exception:
            pass


def main():
    if len(sys.argv) < 2:
        log("argument manquant : fichier d'alerte")
        sys.exit(1)
    with open(sys.argv[1]) as f:
        alert = json.load(f)
    with open(CONF) as f:
        conf = json.load(f)
    level = int(alert.get("rule", {}).get("level", 0))
    if level < int(conf.get("niveau_min", 8)):
        return
    maintenant = time.time()
    cle = cle_dedoublonnage(alert)
    etat, ok = autoriser(charger_etat(), cle, maintenant)
    if not ok:
        log("ignorée (doublon ou plafond horaire) : %s" % cle)
        return
    ticket = construire_ticket(alert, conf)
    if DRYRUN:
        print(json.dumps(ticket, ensure_ascii=False, indent=1))
        return
    try:
        statut, ident = envoyer(conf, ticket)
    except Exception as e:  # message sans jeton : seule la classe et le texte de l'erreur
        log("échec de création d'incident (%s) pour %s" % (type(e).__name__, cle))
        sys.exit(1)
    etat[cle] = maintenant
    try:
        with open(STATE, "w") as f:
            json.dump(etat, f)
    except OSError:
        log("état non écrit : %s" % STATE)
    log("incident GLPI créé : HTTP %s, id %s, %s" % (statut, ident, cle))


if __name__ == "__main__":
    main()
