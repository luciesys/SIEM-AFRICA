#!/usr/bin/env python3
# ================================================================
#  SIEM Africa — Module 3 : Agent intelligent
#  Fichier  : agent/agent.py
# ================================================================

import os
import sys
import json
import time
import sqlite3
import smtplib
import logging
import subprocess
import threading
import socket
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict

# ================================================================
# CONFIGURATION
# ================================================================
ENV_FILE    = "/opt/siem-africa/.env"
DB_PATH     = "/opt/siem-africa/siem_africa.db"
ALERTS_JSON = "/var/ossec/logs/alerts/alerts.json"
LOG_FILE    = "/var/log/siem-africa/agent.log"
AGENT_DIR   = "/opt/siem-africa/agent"
PID_FILE    = "/var/run/siem-agent.pid"

def load_env():
    """Charger la configuration depuis .env"""
    config = {
        "POLLING_INTERVAL":       10,
        "CORRELATION_WINDOW":     60,
        "CORRELATION_THRESHOLD":  3,
        "ACTIVE_RESPONSE_DELAY":  300,
        "HONEYPOT_ENABLED":       "1",
        "HONEYPOT_SSH_PORT":      2222,
        "HONEYPOT_HTTP_PORT":     8888,
        "HONEYPOT_MYSQL_PORT":    3307,
        "SMTP_HOST":              "smtp.gmail.com",
        "SMTP_PORT":              587,
        "SMTP_USER":              "",
        "SMTP_PASSWORD":          "",
        "ALERT_EMAIL":            "",
        "LANG":                   "fr",
        "FP_SEUIL_SCORE":         40,
        "SERVER_IP":              "127.0.0.1",
    }
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    config[k.strip()] = v.strip()

    # Convertir les entiers
    for k in ["POLLING_INTERVAL","CORRELATION_WINDOW","CORRELATION_THRESHOLD",
              "ACTIVE_RESPONSE_DELAY","HONEYPOT_SSH_PORT","HONEYPOT_HTTP_PORT",
              "HONEYPOT_MYSQL_PORT","SMTP_PORT","FP_SEUIL_SCORE"]:
        try:
            config[k] = int(config[k])
        except (ValueError, KeyError):
            pass
    return config

# ================================================================
# LOGGING
# ================================================================
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger("siem-agent")

# ================================================================
# BASE DE DONNEES
# ================================================================
def get_db():
    """Connexion SQLite thread-safe"""
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def chercher_signature(rule_id, sid_snort=None):
    """Chercher une signature dans la base"""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT * FROM attaques
            WHERE rule_id = ? OR (sid_snort IS NOT NULL AND sid_snort = ?)
            LIMIT 1
        """, (rule_id, sid_snort))
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception as e:
        log.error(f"Erreur DB chercher_signature: {e}")
        return None

def sauver_alerte(alerte_data):
    """Sauvegarder une alerte dans la base"""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO alertes (
                timestamp_alerte, rule_id, sid_snort, attaque_id,
                nom_attaque, nom_attaque_en, categorie,
                gravite, gravite_label, actions_fr, actions_en,
                mitre_id, mitre_tactique, mitre_technique,
                ip_source, ip_destination, port_source, port_destination,
                protocole, pays_source, agent_id, machine_nom,
                score_confiance, est_faux_positif_predit, raison_fp_predit,
                statut, est_honeypot, est_correllee, raw_alert
            ) VALUES (
                ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
            )
        """, (
            alerte_data.get("timestamp_alerte", datetime.now().isoformat()),
            alerte_data.get("rule_id", 0),
            alerte_data.get("sid_snort"),
            alerte_data.get("attaque_id"),
            alerte_data.get("nom_attaque", "Alerte inconnue"),
            alerte_data.get("nom_attaque_en", "Unknown alert"),
            alerte_data.get("categorie", "Inconnu"),
            alerte_data.get("gravite", 2),
            alerte_data.get("gravite_label", "Moyenne"),
            json.dumps(alerte_data.get("actions_fr", []), ensure_ascii=False),
            json.dumps(alerte_data.get("actions_en", []), ensure_ascii=False),
            alerte_data.get("mitre_id"),
            alerte_data.get("mitre_tactique"),
            alerte_data.get("mitre_technique"),
            alerte_data.get("ip_source"),
            alerte_data.get("ip_destination"),
            alerte_data.get("port_source"),
            alerte_data.get("port_destination"),
            alerte_data.get("protocole"),
            alerte_data.get("pays_source"),
            alerte_data.get("agent_id"),
            alerte_data.get("machine_nom"),
            alerte_data.get("score_confiance", 100),
            1 if alerte_data.get("est_faux_positif_predit") else 0,
            alerte_data.get("raison_fp_predit"),
            "Nouveau",
            1 if alerte_data.get("est_honeypot") else 0,
            1 if alerte_data.get("est_correllee") else 0,
            json.dumps(alerte_data.get("raw_alert", {}), ensure_ascii=False)[:4000],
        ))
        conn.commit()
        alerte_id = cur.lastrowid
        conn.close()
        return alerte_id
    except Exception as e:
        log.error(f"Erreur DB sauver_alerte: {e}")
        return None

def sauver_alerte_inconnue(rule_id, sid_snort, description, ip_source, ip_dest):
    """Sauvegarder une alerte non identifiee"""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO attaques_inconnues
                (rule_id, sid_snort, description, ip_source, ip_destination,
                 nb_occurrences, derniere_fois)
            VALUES (?,?,?,?,?,1, datetime('now'))
            ON CONFLICT(rule_id) DO UPDATE SET
                nb_occurrences = nb_occurrences + 1,
                derniere_fois = datetime('now')
        """, (rule_id, sid_snort, description, ip_source, ip_dest))
        conn.commit()
        conn.close()
    except Exception as e:
        log.error(f"Erreur DB sauver_alerte_inconnue: {e}")

def ip_en_whitelist(ip):
    """Verifier si une IP est en whitelist"""
    if not ip:
        return False
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT 1 FROM ips_whitelist
            WHERE ip = ? AND est_actif = 1
        """, (ip,))
        result = cur.fetchone()
        conn.close()
        return result is not None
    except:
        return False

def get_emails_alertes():
    """Recuperer tous les emails de notification actifs"""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT email FROM emails_alertes WHERE est_actif = 1")
        emails = [row["email"] for row in cur.fetchall()]
        conn.close()
        return emails
    except:
        return []

def get_nb_faux_positifs_ip(ip):
    """Nombre de faux positifs connus pour cette IP"""
    if not ip:
        return 0
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT COUNT(*) as nb FROM faux_positifs
            WHERE ip_source = ? AND est_actif = 1
        """, (ip,))
        row = cur.fetchone()
        conn.close()
        return row["nb"] if row else 0
    except:
        return 0

def get_nb_alertes_ip_24h(ip):
    """Nombre d'alertes pour cette IP dans les 24 dernieres heures"""
    if not ip:
        return 0
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT COUNT(*) as nb FROM alertes
            WHERE ip_source = ?
            AND timestamp_alerte >= datetime('now', '-24 hours')
        """, (ip,))
        row = cur.fetchone()
        conn.close()
        return row["nb"] if row else 0
    except:
        return 0

def signature_fp_frequente(rule_id):
    """Verifier si une signature genere souvent des faux positifs"""
    if not rule_id:
        return False
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT fp_frequence FROM attaques WHERE rule_id = ?", (rule_id,))
        row = cur.fetchone()
        conn.close()
        return row and row["fp_frequence"] == 1
    except:
        return False

# ================================================================
# CALCUL DU SCORE DE CONFIANCE (faux positif)
# ================================================================
def calculer_score_confiance(ip, rule_id):
    """
    Calculer le score de confiance 0-100
    Plus le score est bas, plus c'est probablement un faux positif
    """
    score = 100
    raisons = []

    # IP en whitelist = score 0
    if ip_en_whitelist(ip):
        return 0, "IP en liste blanche"

    # Historique faux positifs IP
    nb_fp = get_nb_faux_positifs_ip(ip)
    if nb_fp > 0:
        reduction = min(nb_fp * 15, 40)
        score -= reduction
        raisons.append(
            f"Cette IP a deja genere {nb_fp} faux positif(s) confirme(s)"
        )

    # Signature connue pour faux positifs
    if signature_fp_frequente(rule_id):
        score -= 20
        raisons.append("Cette signature genere frequemment des faux positifs")

    # Heure de l'alerte
    heure = datetime.now().hour
    if 8 <= heure <= 18:          # heures de bureau
        score -= 10
        raisons.append("Alerte pendant les heures de bureau (peut etre normal)")
    elif heure < 6 or heure > 22: # nuit profonde
        score += 20

    # Frequence des alertes depuis cette IP
    nb_24h = get_nb_alertes_ip_24h(ip)
    if nb_24h < 3:
        score -= 15
        raisons.append(f"IP peu active ({nb_24h} alerte(s) en 24h)")
    elif nb_24h > 50:
        score += 25

    score = max(0, min(100, score))
    raison = " | ".join(raisons) if raisons else None
    return score, raison

# ================================================================
# CORRELATION DES ALERTES
# ================================================================
class CorrelationManager:
    """Gestionnaire de correlation des alertes"""

    def __init__(self, window_sec, threshold):
        self.window    = window_sec
        self.threshold = threshold
        self.historique = defaultdict(list)  # (ip, rule_id) -> [timestamps]
        self.lock = threading.Lock()

    def est_correllee(self, ip, rule_id):
        """Verifier si une alerte est correlee (meme IP + meme regle dans la fenetre)"""
        if not ip:
            return False
        key = (ip, rule_id)
        maintenant = datetime.now()
        limite = maintenant - timedelta(seconds=self.window)

        with self.lock:
            # Nettoyer l'historique
            self.historique[key] = [
                t for t in self.historique[key] if t > limite
            ]
            self.historique[key].append(maintenant)
            nb = len(self.historique[key])

        return nb >= self.threshold

# ================================================================
# NOTIFICATIONS EMAIL
# ================================================================
def envoyer_email(config, alerte):
    """Envoyer un email de notification pour une alerte"""
    smtp_user = config.get("SMTP_USER", "")
    smtp_pass = config.get("SMTP_PASSWORD", "")
    smtp_host = config.get("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(config.get("SMTP_PORT", 587))
    server_ip = config.get("SERVER_IP", "127.0.0.1")
    langue    = config.get("LANG", "fr")

    # Recuperer les emails destinataires depuis la DB
    emails_db = get_emails_alertes()
    # Ajouter l'email du .env si defini
    email_env = config.get("ALERT_EMAIL", "")
    if email_env and email_env not in emails_db:
        emails_db.append(email_env)

    if not emails_db:
        log.warning("Aucun email destinataire configure")
        return False
    if not smtp_user or not smtp_pass:
        log.warning("SMTP non configure — email non envoye")
        return False

    gravite      = alerte.get("gravite", 2)
    gravite_label= alerte.get("gravite_label", "Moyenne")
    score        = alerte.get("score_confiance", 100)
    est_fp       = alerte.get("est_faux_positif_predit", False)
    raison_fp    = alerte.get("raison_fp_predit", "")
    nom_attaque  = alerte.get("nom_attaque", "Alerte inconnue")
    ip_source    = alerte.get("ip_source", "Inconnue")
    machine      = alerte.get("machine_nom", "Inconnue")
    mitre_id     = alerte.get("mitre_id", "")
    mitre_tac    = alerte.get("mitre_tactique", "")

    try:
        actions = json.loads(alerte.get("actions_fr", "[]"))
    except:
        actions = []

    # Icone gravite
    icones = {4: "🔴", 3: "🟠", 2: "🟡", 1: "🟢"}
    icone  = icones.get(gravite, "🟡")

    if langue == "en":
        sujet = f"[SIEM Africa] {icone} {gravite_label.upper()} Alert — {nom_attaque}"
    else:
        sujet = f"[SIEM Africa] {icone} Alerte {gravite_label.upper()} — {nom_attaque}"

    # Corps du message
    if langue == "en":
        corps = f"""
SIEM Africa — Security Alert
{'='*50}

Type       : {nom_attaque}
Source IP  : {ip_source}
Machine    : {machine}
Severity   : {icone} {gravite_label.upper()} ({gravite}/4)
MITRE      : {mitre_id} — {mitre_tac}
Date       : {datetime.now().strftime('%d/%m/%Y at %H:%M:%S')}

"""
        if est_fp and score < int(config.get("FP_SEUIL_SCORE", 40)):
            corps += f"""⚠️  FALSE POSITIVE WARNING : Confidence score {score}/100
    Reason : {raison_fp}
    This alert may be a false positive. Please verify before acting.

"""
        if actions:
            corps += "✅ RECOMMENDED ACTIONS:\n"
            for i, action in enumerate(actions, 1):
                corps += f"   {i}. {action}\n"
        corps += f"""
🔗 View alert: http://{server_ip}:8000/alertes/

— SIEM Africa | github.com/luciesys/SIEM-AFRICA
"""
    else:
        corps = f"""
SIEM Africa — Alerte de Securite
{'='*50}

Type       : {nom_attaque}
IP source  : {ip_source}
Machine    : {machine}
Gravite    : {icone} {gravite_label.upper()} ({gravite}/4)
MITRE      : {mitre_id} — {mitre_tac}
Date       : {datetime.now().strftime('%d/%m/%Y a %H:%M:%S')}

"""
        if est_fp and score < int(config.get("FP_SEUIL_SCORE", 40)):
            corps += f"""⚠️  AVERTISSEMENT FAUX POSITIF : Score de confiance {score}/100
    Raison : {raison_fp}
    Cette alerte pourrait etre un faux positif. Verifiez avant d'agir.

"""
        if actions:
            corps += "✅ ACTIONS RECOMMANDEES:\n"
            for i, action in enumerate(actions, 1):
                corps += f"   {i}. {action}\n"
        corps += f"""
🔗 Voir l'alerte : http://{server_ip}:8000/alertes/

— SIEM Africa | github.com/luciesys/SIEM-AFRICA
"""

    try:
        msg = MIMEMultipart()
        msg["From"]    = smtp_user
        msg["To"]      = ", ".join(emails_db)
        msg["Subject"] = sujet
        msg.attach(MIMEText(corps, "plain", "utf-8"))

        with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, emails_db, msg.as_string())

        log.info(f"Email envoye a : {', '.join(emails_db)}")
        return True

    except Exception as e:
        log.error(f"Erreur envoi email : {e}")
        return False

def enregistrer_notification(alerte_id, email, statut, erreur=None):
    """Enregistrer la notification dans la base"""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO notifications (alerte_id, email_dest, canal, statut, erreur)
            VALUES (?, ?, 'Email', ?, ?)
        """, (alerte_id, email, statut, erreur))
        conn.commit()
        conn.close()
    except Exception as e:
        log.error(f"Erreur enregistrer_notification: {e}")

# ================================================================
# ACTIVE RESPONSE — Blocage IP automatique
# ================================================================
def bloquer_ip(ip, duree_sec=300):
    """Bloquer une IP via iptables (gravite 4 uniquement)"""
    if not ip or ip in ("127.0.0.1", "::1"):
        return False
    try:
        # Ajouter la regle iptables
        subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, timeout=10
        )
        log.info(f"IP bloquee via iptables : {ip} (duree: {duree_sec}s)")

        # Sauvegarder dans la base
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO ips_bloquees
                (ip, type_blocage, raison, bloque_le, expire_le, est_actif)
            VALUES (?, 'Auto', 'Active Response automatique — Gravite 4',
                    datetime('now'),
                    datetime('now', '+' || ? || ' seconds'),
                    1)
        """, (ip, duree_sec))
        conn.commit()
        conn.close()

        # Programmer le deblocage automatique
        def debloquer():
            time.sleep(duree_sec)
            try:
                subprocess.run(
                    ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True, timeout=10
                )
                log.info(f"IP debloquee automatiquement : {ip}")
                conn2 = get_db()
                cur2 = conn2.cursor()
                cur2.execute(
                    "UPDATE ips_bloquees SET est_actif = 0 WHERE ip = ?", (ip,)
                )
                conn2.commit()
                conn2.close()
            except Exception as e:
                log.error(f"Erreur deblocage {ip}: {e}")

        threading.Thread(target=debloquer, daemon=True).start()
        return True

    except Exception as e:
        log.error(f"Erreur blocage IP {ip}: {e}")
        return False

# ================================================================
# HONEYPOT
# ================================================================
class Honeypot:
    """Faux services pour detecter les attaquants"""

    def __init__(self, config, correlateur):
        self.config     = config
        self.correlateur = correlateur
        self.actif      = config.get("HONEYPOT_ENABLED", "1") == "1"
        self.ssh_port   = int(config.get("HONEYPOT_SSH_PORT", 2222))
        self.http_port  = int(config.get("HONEYPOT_HTTP_PORT", 8888))
        self.mysql_port = int(config.get("HONEYPOT_MYSQL_PORT", 3307))

    def demarrer(self):
        if not self.actif:
            return
        log.info(f"Honeypot active : SSH:{self.ssh_port} HTTP:{self.http_port} MySQL:{self.mysql_port}")
        for port, nom in [
            (self.ssh_port,   "SSH"),
            (self.http_port,  "HTTP"),
            (self.mysql_port, "MySQL"),
        ]:
            threading.Thread(
                target=self._ecouter, args=(port, nom), daemon=True
            ).start()

    def _ecouter(self, port, service):
        """Ecouter sur un port et enregistrer les connexions"""
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", port))
            srv.listen(5)
            log.info(f"Honeypot {service} en ecoute sur le port {port}")

            while True:
                try:
                    conn, addr = srv.accept()
                    ip_attaquant = addr[0]
                    log.warning(f"HONEYPOT {service} port {port} : connexion depuis {ip_attaquant}")

                    # Enregistrer l'alerte honeypot
                    alerte = {
                        "timestamp_alerte": datetime.now().isoformat(),
                        "rule_id":          99000 + port,
                        "nom_attaque":      f"Connexion Honeypot {service} (port {port})",
                        "nom_attaque_en":   f"Honeypot {service} Connection (port {port})",
                        "categorie":        "Honeypot",
                        "gravite":          4,
                        "gravite_label":    "Critique",
                        "ip_source":        ip_attaquant,
                        "score_confiance":  100,  # Honeypot = jamais faux positif
                        "est_honeypot":     True,
                        "actions_fr":       ["Bloquer IP immediatement",
                                             "Analyser IP source",
                                             "Verifier si scan en cours"],
                        "actions_en":       ["Block IP immediately",
                                             "Analyze source IP",
                                             "Check if scan in progress"],
                        "raw_alert":        {"honeypot": service, "port": port},
                    }

                    alerte_id = sauver_alerte(alerte)
                    if alerte_id:
                        envoyer_email(self.config, alerte)
                        enregistrer_notification(alerte_id, self.config.get("ALERT_EMAIL",""), "envoye")
                        # Blocage immediat pour les honeypots
                        bloquer_ip(ip_attaquant, 3600)  # 1 heure

                    # Fermer la connexion
                    try:
                        conn.close()
                    except:
                        pass

                except Exception as e:
                    if "too many open files" not in str(e).lower():
                        log.error(f"Erreur connexion honeypot {service}: {e}")

        except OSError as e:
            log.error(f"Impossible de demarrer honeypot {service} port {port}: {e}")

# ================================================================
# TRAITEMENT DES ALERTES WAZUH
# ================================================================
class AgentSIEM:
    """Agent principal de traitement des alertes"""

    def __init__(self):
        self.config     = load_env()
        self.correlateur = CorrelationManager(
            window_sec=self.config["CORRELATION_WINDOW"],
            threshold=self.config["CORRELATION_THRESHOLD"]
        )
        self.honeypot   = Honeypot(self.config, self.correlateur)
        self.derniere_pos = 0
        self.alertes_traitees = set()  # Eviter les doublons

    def lire_nouvelles_alertes(self):
        """Lire les nouvelles alertes depuis alerts.json"""
        if not os.path.exists(ALERTS_JSON):
            return []

        try:
            taille_actuelle = os.path.getsize(ALERTS_JSON)
            if taille_actuelle == self.derniere_pos:
                return []
            if taille_actuelle < self.derniere_pos:
                self.derniere_pos = 0  # Fichier recree

            alertes = []
            with open(ALERTS_JSON, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self.derniere_pos)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        alerte = json.loads(line)
                        alertes.append(alerte)
                    except json.JSONDecodeError:
                        continue
                self.derniere_pos = f.tell()
            return alertes

        except Exception as e:
            log.error(f"Erreur lecture alerts.json: {e}")
            return []

    def extraire_infos(self, alerte_wazuh):
        """Extraire les informations cles d'une alerte Wazuh"""
        rule    = alerte_wazuh.get("rule", {})
        data    = alerte_wazuh.get("data", {})
        agent   = alerte_wazuh.get("agent", {})
        srcip   = (
            data.get("srcip") or
            alerte_wazuh.get("data", {}).get("src_ip") or
            alerte_wazuh.get("srcip")
        )
        dstip   = data.get("dstip") or data.get("dst_ip")

        return {
            "rule_id":      rule.get("id"),
            "sid_snort":    data.get("id"),  # Pour Snort
            "description":  rule.get("description", ""),
            "gravite_wazuh":rule.get("level", 0),
            "ip_source":    srcip,
            "ip_destination": dstip,
            "port_source":  data.get("src_port"),
            "port_destination": data.get("dst_port"),
            "protocole":    data.get("protocol"),
            "agent_id":     agent.get("id"),
            "machine_nom":  agent.get("name"),
            "timestamp":    alerte_wazuh.get("timestamp",
                            datetime.now().isoformat()),
        }

    def mapper_gravite(self, level_wazuh):
        """Convertir le niveau Wazuh (0-15) vers notre gravite (1-4)"""
        if level_wazuh >= 12:   return 4, "Critique"
        elif level_wazuh >= 8:  return 3, "Haute"
        elif level_wazuh >= 4:  return 2, "Moyenne"
        else:                   return 1, "Faible"

    def traiter_alerte(self, alerte_wazuh):
        """Traiter une alerte Wazuh"""
        infos = self.extraire_infos(alerte_wazuh)
        rule_id  = infos["rule_id"]
        ip       = infos["ip_source"]

        # Eviter les doublons recents
        cle = f"{rule_id}_{ip}_{infos.get('port_destination')}"
        if cle in self.alertes_traitees:
            return
        self.alertes_traitees.add(cle)
        # Nettoyer le cache si trop grand
        if len(self.alertes_traitees) > 1000:
            self.alertes_traitees.clear()

        # Chercher la signature dans la base
        sig = chercher_signature(rule_id, infos.get("sid_snort"))

        if sig:
            # Signature connue
            gravite       = sig["gravite"]
            gravite_label = sig["gravite_label"]
            try:
                actions_fr = json.loads(sig["actions_fr"] or "[]")
                actions_en = json.loads(sig["actions_en"] or "[]")
            except:
                actions_fr = []
                actions_en = []

            alerte = {
                "timestamp_alerte": infos["timestamp"],
                "rule_id":          rule_id,
                "sid_snort":        infos.get("sid_snort"),
                "attaque_id":       sig["id"],
                "nom_attaque":      sig["nom"],
                "nom_attaque_en":   sig.get("nom_en", sig["nom"]),
                "categorie":        sig["categorie"],
                "gravite":          gravite,
                "gravite_label":    gravite_label,
                "actions_fr":       actions_fr,
                "actions_en":       actions_en,
                "mitre_id":         sig.get("mitre_id"),
                "mitre_tactique":   sig.get("mitre_tactique"),
                "mitre_technique":  sig.get("mitre_technique"),
                "ip_source":        ip,
                "ip_destination":   infos.get("ip_destination"),
                "port_source":      infos.get("port_source"),
                "port_destination": infos.get("port_destination"),
                "protocole":        infos.get("protocole"),
                "agent_id":         infos.get("agent_id"),
                "machine_nom":      infos.get("machine_nom"),
                "raw_alert":        alerte_wazuh,
            }
        else:
            # Signature inconnue — enregistrer pour enrichissement manuel
            gravite, gravite_label = self.mapper_gravite(infos["gravite_wazuh"])
            sauver_alerte_inconnue(
                rule_id, infos.get("sid_snort"),
                infos["description"], ip, infos.get("ip_destination")
            )
            alerte = {
                "timestamp_alerte": infos["timestamp"],
                "rule_id":          rule_id,
                "nom_attaque":      infos["description"] or "Alerte non identifiee",
                "nom_attaque_en":   infos["description"] or "Unidentified alert",
                "categorie":        "Inconnu",
                "gravite":          gravite,
                "gravite_label":    gravite_label,
                "ip_source":        ip,
                "ip_destination":   infos.get("ip_destination"),
                "machine_nom":      infos.get("machine_nom"),
                "est_inconnue":     True,
                "raw_alert":        alerte_wazuh,
                "actions_fr":       ["Analyser l'alerte manuellement",
                                     "Verifier dans les logs systeme",
                                     "Enrichir la signature dans le dashboard"],
                "actions_en":       ["Analyze alert manually",
                                     "Check system logs",
                                     "Enrich signature in dashboard"],
            }

        # Calcul score faux positif
        score, raison_fp = calculer_score_confiance(ip, rule_id)
        alerte["score_confiance"]        = score
        alerte["est_faux_positif_predit"] = score < int(self.config.get("FP_SEUIL_SCORE", 40))
        alerte["raison_fp_predit"]        = raison_fp

        # Correlation
        est_cor = self.correlateur.est_correllee(ip, rule_id)
        alerte["est_correllee"] = est_cor
        if est_cor:
            log.info(f"Alerte correlee : {rule_id} depuis {ip}")
            return  # Ne pas notifier les alertes correlees

        # Sauvegarder
        alerte_id = sauver_alerte(alerte)
        if not alerte_id:
            return

        log.info(
            f"Alerte [{alerte['gravite_label']}] {alerte['nom_attaque']} "
            f"depuis {ip} — score={score}"
        )

        # Notification email (gravite >= 2)
        if alerte["gravite"] >= 2:
            ok = envoyer_email(self.config, alerte)
            statut = "envoye" if ok else "echec"
            emails = get_emails_alertes()
            for email in emails:
                enregistrer_notification(alerte_id, email, statut)

        # Active Response : blocage auto si gravite 4
        if alerte["gravite"] == 4 and ip:
            delai = int(self.config.get("ACTIVE_RESPONSE_DELAY", 300))
            log.warning(
                f"Active Response : blocage de {ip} dans {delai}s"
            )
            def bloquer_apres_delai():
                time.sleep(delai)
                bloquer_ip(ip, 3600)
            threading.Thread(target=bloquer_apres_delai, daemon=True).start()

    def demarrer(self):
        """Boucle principale de l'agent"""
        log.info("=" * 60)
        log.info("  SIEM Africa Agent v3.0 — Demarrage")
        log.info(f"  Polling : toutes les {self.config['POLLING_INTERVAL']}s")
        log.info(f"  Correlation : {self.config['CORRELATION_THRESHOLD']} alertes en {self.config['CORRELATION_WINDOW']}s")
        log.info(f"  Active Response : gravite 4 → blocage apres {self.config['ACTIVE_RESPONSE_DELAY']}s")
        log.info(f"  Honeypot : {self.config.get('HONEYPOT_ENABLED','1') == '1'}")
        log.info("=" * 60)

        # Demarrer le honeypot dans des threads separes
        self.honeypot.demarrer()

        # Attendre que alerts.json soit pret
        for _ in range(30):
            if os.path.exists(ALERTS_JSON):
                break
            log.info(f"En attente de {ALERTS_JSON}...")
            time.sleep(5)

        if os.path.exists(ALERTS_JSON):
            # Positionner a la fin du fichier existant
            self.derniere_pos = os.path.getsize(ALERTS_JSON)
            log.info(f"alerts.json trouve ({self.derniere_pos} octets existants ignores)")
        else:
            log.warning(f"alerts.json introuvable : {ALERTS_JSON}")

        # Boucle principale
        while True:
            try:
                nouvelles = self.lire_nouvelles_alertes()
                for alerte in nouvelles:
                    try:
                        self.traiter_alerte(alerte)
                    except Exception as e:
                        log.error(f"Erreur traitement alerte : {e}")

            except Exception as e:
                log.error(f"Erreur boucle principale : {e}")

            time.sleep(self.config["POLLING_INTERVAL"])

# ================================================================
# MAIN
# ================================================================
if __name__ == "__main__":
    # Ecrire le PID
    os.makedirs(os.path.dirname(PID_FILE), exist_ok=True)
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))

    agent = AgentSIEM()
    agent.demarrer()
