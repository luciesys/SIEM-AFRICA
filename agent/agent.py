#!/usr/bin/env python3
# ================================================================
#  SIEM Africa — Module 3 : Agent intelligent
#  Fichier  : agent/agent.py
#  Usage    : python3 agent.py
#  Service  : siem-agent.service
#  Version  : 1.0
# ================================================================
#
#  Ce que fait cet agent :
#  1. Interroge l'API Wazuh toutes les 10 secondes
#  2. Compare chaque alerte avec la base SQLite (table attaques)
#  3. Enrichit l'alerte : nom, gravité, contre-mesure iptables
#  4. Stocke les attaques inconnues dans attaques_inconnues
#  5. Corrèle : 3+ alertes même IP en 60s → CRITIQUE
#  6. Stocke l'alerte enrichie dans la table alertes
#  7. Envoie email pour les alertes Critique et Haute
# ================================================================

import os
import sys
import time
import json
import sqlite3
import logging
import smtplib
import urllib.request
import urllib.error
import ssl
import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ================================================================
# CONFIGURATION — chargée depuis /opt/siem-africa/.env
# ================================================================
def load_config(env_file='/opt/siem-africa/.env'):
    """Charge la configuration depuis le fichier .env"""
    config = {
        # Wazuh API
        'WAZUH_HOST':           '127.0.0.1',
        'WAZUH_PORT':           '55000',
        'WAZUH_USER':           'wazuh-api',
        'WAZUH_PASSWORD':       '',
        # Base de données
        'DB_PATH':              '/opt/siem-africa/siem_africa.db',
        # Agent
        'POLLING_INTERVAL':     '10',
        'CORRELATION_WINDOW':   '60',
        'CORRELATION_THRESHOLD':'3',
        # Email
        'SMTP_HOST':            'smtp.gmail.com',
        'SMTP_PORT':            '587',
        'SMTP_USER':            '',
        'SMTP_PASSWORD':        '',
        'ALERT_EMAIL':          '',
        # Langue
        'LANG':                 'fr',
    }
    if os.path.exists(env_file):
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, _, val = line.partition('=')
                    config[key.strip()] = val.strip().strip('"')
    return config


# ================================================================
# LOGGING
# ================================================================
def setup_logging():
    log_dir = '/var/log/siem-africa'
    os.makedirs(log_dir, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(f'{log_dir}/agent.log'),
            logging.StreamHandler(sys.stdout),
        ]
    )
    return logging.getLogger('siem-africa-agent')


# ================================================================
# WAZUH API CLIENT
# ================================================================
class WazuhClient:
    """Client pour l'API REST Wazuh"""

    def __init__(self, host, port, user, password, logger):
        self.base_url = f'https://{host}:{port}'
        self.user     = user
        self.password = password
        self.token    = None
        self.token_ts = 0
        self.token_ttl = 870  # 14.5 minutes (token expire a 15min)
        self.logger   = logger
        # Désactiver la vérification SSL (certificat auto-signé)
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def _request(self, method, endpoint, body=None, headers=None):
        """Effectue une requête HTTP vers l'API Wazuh"""
        url = f'{self.base_url}{endpoint}'
        h = headers or {}
        data = None
        if body:
            data = json.dumps(body).encode('utf-8')
            h['Content-Type'] = 'application/json'
        req = urllib.request.Request(url, data=data, headers=h, method=method)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=10) as resp:
                return json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            body_txt = e.read().decode('utf-8', errors='ignore')
            self.logger.error(f'HTTP {e.code} sur {endpoint}: {body_txt[:200]}')
            return None
        except Exception as e:
            self.logger.error(f'Erreur requête {endpoint}: {e}')
            return None

    def authenticate(self):
        """Obtient ou renouvelle le token JWT Wazuh"""
        import base64
        credentials = base64.b64encode(
            f'{self.user}:{self.password}'.encode()
        ).decode()
        result = self._request(
            'GET',
            '/security/user/authenticate',
            headers={'Authorization': f'Basic {credentials}'}
        )
        if result and 'data' in result:
            self.token    = result['data']['token']
            self.token_ts = time.time()
            self.logger.info('Token Wazuh obtenu')
            return True
        self.logger.error('Echec authentification Wazuh')
        return False

    def get_token(self):
        """Retourne le token, le renouvelle si nécessaire"""
        if not self.token or (time.time() - self.token_ts) > self.token_ttl:
            self.authenticate()
        return self.token

    def get_alerts(self, after_ts=None, limit=100):
        """Récupère les alertes depuis l'API Wazuh"""
        token = self.get_token()
        if not token:
            return []
        params = f'?limit={limit}&sort=-timestamp'
        if after_ts:
            # Format ISO 8601 pour le filtre
            params += f'&q=timestamp>{after_ts}'
        result = self._request(
            'GET',
            f'/security/events{params}',
            headers={'Authorization': f'Bearer {token}'}
        )
        if result and 'data' in result:
            items = result['data'].get('affected_items', [])
            return items
        # Essayer l'endpoint alternatif
        result = self._request(
            'GET',
            f'/alerts{params}',
            headers={'Authorization': f'Bearer {token}'}
        )
        if result and 'data' in result:
            return result['data'].get('affected_items', [])
        return []

    def get_agents(self):
        """Récupère la liste des agents Wazuh"""
        token = self.get_token()
        if not token:
            return []
        result = self._request(
            'GET',
            '/agents?limit=500',
            headers={'Authorization': f'Bearer {token}'}
        )
        if result and 'data' in result:
            return result['data'].get('affected_items', [])
        return []


# ================================================================
# BASE DE DONNEES
# ================================================================
class Database:
    """Gestionnaire de la base de données SQLite"""

    def __init__(self, db_path, logger):
        self.db_path = db_path
        self.logger  = logger

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def find_attack(self, rule_id, sid_snort=None):
        """Cherche une signature dans la base par rule_id ou sid_snort"""
        with self._connect() as conn:
            # Chercher d'abord par rule_id
            row = conn.execute(
                'SELECT * FROM attaques WHERE rule_id = ? AND faux_positif = 0',
                (rule_id,)
            ).fetchone()
            if row:
                return dict(row)
            # Chercher par sid_snort si fourni
            if sid_snort:
                row = conn.execute(
                    'SELECT * FROM attaques WHERE sid_snort = ? AND faux_positif = 0',
                    (sid_snort,)
                ).fetchone()
                if row:
                    return dict(row)
        return None

    def is_faux_positif(self, ip_source, rule_id):
        """Vérifie si cette combinaison IP + rule_id est un faux positif confirmé"""
        with self._connect() as conn:
            row = conn.execute(
                'SELECT id FROM faux_positifs WHERE ip_source = ? AND rule_id = ?',
                (ip_source, rule_id)
            ).fetchone()
            return row is not None

    def get_param(self, cle, default=''):
        """Récupère un paramètre de configuration"""
        with self._connect() as conn:
            row = conn.execute(
                'SELECT valeur FROM parametres WHERE cle = ?',
                (cle,)
            ).fetchone()
            return row['valeur'] if row else default

    def save_alert(self, alert_data):
        """Enregistre une alerte enrichie dans la base"""
        with self._connect() as conn:
            cursor = conn.execute('''
                INSERT INTO alertes (
                    timestamp_alerte, rule_id, sid_snort, attaque_id,
                    nom_attaque, nom_attaque_en, categorie,
                    gravite, gravite_label, action_recommandee, contre_mesure,
                    ip_source, ip_destination, port_source, port_destination,
                    protocole, pays_source, ville_source,
                    agent_id, machine_nom, machine_os,
                    est_inconnue, description_wazuh,
                    est_correllee, correlation_count, statut
                ) VALUES (
                    ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?,
                    ?, ?, ?
                )
            ''', (
                alert_data.get('timestamp_alerte'),
                alert_data.get('rule_id'),
                alert_data.get('sid_snort'),
                alert_data.get('attaque_id'),
                alert_data.get('nom_attaque'),
                alert_data.get('nom_attaque_en'),
                alert_data.get('categorie'),
                alert_data.get('gravite'),
                alert_data.get('gravite_label'),
                alert_data.get('action_recommandee'),
                alert_data.get('contre_mesure'),
                alert_data.get('ip_source'),
                alert_data.get('ip_destination'),
                alert_data.get('port_source'),
                alert_data.get('port_destination'),
                alert_data.get('protocole'),
                alert_data.get('pays_source'),
                alert_data.get('ville_source'),
                alert_data.get('agent_id'),
                alert_data.get('machine_nom'),
                alert_data.get('machine_os'),
                alert_data.get('est_inconnue', 0),
                alert_data.get('description_wazuh'),
                alert_data.get('est_correllee', 0),
                alert_data.get('correlation_count', 1),
                'Nouveau',
            ))
            return cursor.lastrowid

    def save_unknown_attack(self, rule_id, description, gravite_wazuh):
        """Enregistre ou met à jour une attaque inconnue"""
        with self._connect() as conn:
            existing = conn.execute(
                'SELECT id, nb_occurrences FROM attaques_inconnues WHERE rule_id = ?',
                (rule_id,)
            ).fetchone()
            now = datetime.datetime.now().isoformat()
            if existing:
                conn.execute('''
                    UPDATE attaques_inconnues
                    SET nb_occurrences = ?,
                        derniere_vue   = ?
                    WHERE rule_id = ?
                ''', (existing['nb_occurrences'] + 1, now, rule_id))
            else:
                conn.execute('''
                    INSERT INTO attaques_inconnues
                    (rule_id, description_wazuh, gravite_wazuh, nb_occurrences,
                     premiere_vue, derniere_vue)
                    VALUES (?, ?, ?, 1, ?, ?)
                ''', (rule_id, description, gravite_wazuh, now, now))

    def get_recent_alerts_from_ip(self, ip_source, window_seconds):
        """Compte les alertes récentes depuis une IP pour la corrélation"""
        with self._connect() as conn:
            since = (
                datetime.datetime.now() -
                datetime.timedelta(seconds=window_seconds)
            ).isoformat()
            row = conn.execute('''
                SELECT COUNT(*) as nb
                FROM alertes
                WHERE ip_source = ?
                  AND timestamp_alerte >= ?
                  AND statut = "Nouveau"
            ''', (ip_source, since)).fetchone()
            return row['nb'] if row else 0

    def update_correlation(self, alert_id, count):
        """Marque une alerte comme corrélée et met à jour sa gravité"""
        with self._connect() as conn:
            conn.execute('''
                UPDATE alertes
                SET est_correllee   = 1,
                    correlation_count = ?,
                    gravite         = 4,
                    gravite_label   = "Critique"
                WHERE id = ?
            ''', (count, alert_id))

    def save_agent(self, agent_data):
        """Met à jour les informations d'un agent Wazuh"""
        with self._connect() as conn:
            existing = conn.execute(
                'SELECT id FROM agents WHERE agent_wazuh_id = ?',
                (agent_data['agent_wazuh_id'],)
            ).fetchone()
            now = datetime.datetime.now().isoformat()
            if existing:
                conn.execute('''
                    UPDATE agents
                    SET nom          = ?,
                        ip           = ?,
                        os           = ?,
                        statut       = ?,
                        derniere_vue = ?
                    WHERE agent_wazuh_id = ?
                ''', (
                    agent_data.get('nom', ''),
                    agent_data.get('ip', ''),
                    agent_data.get('os', ''),
                    agent_data.get('statut', 'Actif'),
                    now,
                    agent_data['agent_wazuh_id'],
                ))
            else:
                conn.execute('''
                    INSERT INTO agents
                    (agent_wazuh_id, nom, ip, os, statut, derniere_vue, cree_le)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    agent_data['agent_wazuh_id'],
                    agent_data.get('nom', ''),
                    agent_data.get('ip', ''),
                    agent_data.get('os', ''),
                    agent_data.get('statut', 'Actif'),
                    now, now,
                ))

    def save_notification(self, alerte_id, type_notif, destinataire, succes, erreur=None):
        """Enregistre une notification dans l'historique"""
        with self._connect() as conn:
            now = datetime.datetime.now().isoformat()
            conn.execute('''
                INSERT INTO notifications
                (alerte_id, type_notif, destinataire, envoye, envoye_le, erreur)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                alerte_id,
                type_notif,
                destinataire,
                1 if succes else 0,
                now if succes else None,
                erreur,
            ))

    def alert_already_processed(self, wazuh_alert_id, timestamp):
        """Vérifie si une alerte Wazuh a déjà été traitée (évite les doublons)"""
        with self._connect() as conn:
            # Vérification basée sur le timestamp et la description Wazuh
            row = conn.execute('''
                SELECT id FROM alertes
                WHERE description_wazuh LIKE ?
                  AND timestamp_alerte = ?
            ''', (f'%{wazuh_alert_id}%', timestamp)).fetchone()
            return row is not None


# ================================================================
# SERVICE D'EMAIL
# ================================================================
class EmailService:
    """Envoie des notifications email pour les alertes critiques"""

    def __init__(self, config, logger):
        self.smtp_host  = config.get('SMTP_HOST', 'smtp.gmail.com')
        self.smtp_port  = int(config.get('SMTP_PORT', 587))
        self.smtp_user  = config.get('SMTP_USER', '')
        self.smtp_pass  = config.get('SMTP_PASSWORD', '')
        self.dest_email = config.get('ALERT_EMAIL', '')
        self.lang       = config.get('LANG', 'fr')
        self.logger     = logger

    def is_configured(self):
        return bool(self.smtp_user and self.smtp_pass and self.dest_email)

    def send_alert(self, alert_data, alert_id):
        """Envoie un email de notification pour une alerte"""
        if not self.is_configured():
            return False

        gravite     = alert_data.get('gravite_label', 'Inconnue')
        nom         = alert_data.get('nom_attaque', 'Attaque inconnue')
        ip          = alert_data.get('ip_source', 'N/A')
        machine     = alert_data.get('machine_nom', 'N/A')
        pays        = alert_data.get('pays_source', 'N/A')
        action      = alert_data.get('action_recommandee', 'N/A')
        contre      = alert_data.get('contre_mesure', 'N/A')
        timestamp   = alert_data.get('timestamp_alerte', 'N/A')
        correllee   = alert_data.get('est_correllee', 0)
        corr_count  = alert_data.get('correlation_count', 1)

        sujet = f'[SIEM Africa] {gravite} — {nom}'
        if correllee:
            sujet = f'[SIEM Africa] CRITIQUE CORRELLEE — {nom}'

        if self.lang == 'en':
            corps = f"""
SIEM Africa — Security Alert #{alert_id}
{'='*50}

Severity     : {gravite}
Attack       : {nom}
Source IP    : {ip}
Country      : {pays}
Machine      : {machine}
Detected at  : {timestamp}
"""
            if correllee:
                corps += f'CORRELATED  : YES — {corr_count} alerts from same IP in 60s\n'
            corps += f"""
Recommended action : {action}
Iptables command   : {contre}

Dashboard : http://YOUR_SERVER:5000
{'='*50}
SIEM Africa — Cybersecurity for African SMEs
"""
        else:
            corps = f"""
SIEM Africa — Alerte de securite #{alert_id}
{'='*50}

Gravite           : {gravite}
Attaque           : {nom}
IP source         : {ip}
Pays              : {pays}
Machine concernee : {machine}
Detectee le       : {timestamp}
"""
            if correllee:
                corps += f'CORRELEE          : OUI — {corr_count} alertes meme IP en 60s\n'
            corps += f"""
Action recommandee : {action}
Commande iptables  : {contre}

Dashboard : http://VOTRE_SERVEUR:5000
{'='*50}
SIEM Africa — Cybersecurite pour PME africaines
"""
        try:
            msg = MIMEMultipart()
            msg['From']    = self.smtp_user
            msg['To']      = self.dest_email
            msg['Subject'] = sujet
            msg.attach(MIMEText(corps, 'plain', 'utf-8'))

            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_pass)
                server.sendmail(self.smtp_user, self.dest_email, msg.as_string())

            self.logger.info(f'Email envoye pour alerte #{alert_id}')
            return True
        except Exception as e:
            self.logger.error(f'Erreur envoi email : {e}')
            return False


# ================================================================
# GEOLOCALISATION
# ================================================================
def geolocate_ip(ip):
    """Obtient le pays et la ville d'une IP via ip-api.com (gratuit)"""
    if not ip or ip.startswith(('10.', '192.168.', '172.', '127.')):
        return None, None  # IP privée — pas de géolocalisation
    try:
        url = f'http://ip-api.com/json/{ip}?fields=country,city,status'
        req = urllib.request.Request(url, headers={'User-Agent': 'SIEM-Africa/1.0'})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            if data.get('status') == 'success':
                return data.get('country'), data.get('city')
    except Exception:
        pass
    return None, None


# ================================================================
# PARSEUR D'ALERTES WAZUH
# ================================================================
def parse_wazuh_alert(raw_alert):
    """Extrait les informations utiles d'une alerte Wazuh brute"""
    if not raw_alert:
        return None

    result = {
        'wazuh_id':        raw_alert.get('id', ''),
        'timestamp_alerte': None,
        'rule_id':         None,
        'sid_snort':       None,
        'ip_source':       None,
        'ip_destination':  None,
        'port_source':     None,
        'port_destination':None,
        'protocole':       None,
        'agent_id':        None,
        'machine_nom':     None,
        'machine_os':      None,
        'description_wazuh':None,
        'gravite_wazuh':   0,
    }

    # Timestamp
    ts = raw_alert.get('timestamp', '')
    if ts:
        try:
            dt = datetime.datetime.fromisoformat(ts.replace('Z', '+00:00'))
            result['timestamp_alerte'] = dt.strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            result['timestamp_alerte'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    else:
        result['timestamp_alerte'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Règle Wazuh
    rule = raw_alert.get('rule', {})
    result['rule_id']          = rule.get('id')
    result['description_wazuh'] = rule.get('description', '')
    result['gravite_wazuh']    = rule.get('level', 0)

    # Agent (machine surveillée)
    agent = raw_alert.get('agent', {})
    result['agent_id']   = agent.get('id', '')
    result['machine_nom'] = agent.get('name', '')

    # Données réseau
    data = raw_alert.get('data', {})
    src_ip   = (data.get('srcip') or data.get('src_ip') or
                data.get('source', {}).get('ip') if isinstance(data.get('source'), dict) else None)
    dst_ip   = (data.get('dstip') or data.get('dst_ip') or
                data.get('destination', {}).get('ip') if isinstance(data.get('destination'), dict) else None)

    result['ip_source']      = src_ip
    result['ip_destination'] = dst_ip

    # SID Snort (dans les données Snort)
    snort_data = data.get('snort', {})
    if isinstance(snort_data, dict):
        result['sid_snort'] = snort_data.get('sid')

    # Port et protocole
    result['port_source']      = data.get('srcport') or data.get('src_port')
    result['port_destination'] = data.get('dstport') or data.get('dst_port')
    result['protocole']        = data.get('protocol') or data.get('proto')

    # OS depuis les infos système
    syscheck = raw_alert.get('syscheck', {})
    result['machine_os'] = raw_alert.get('agent', {}).get('version', '')

    # Convertir rule_id en int
    if result['rule_id']:
        try:
            result['rule_id'] = int(result['rule_id'])
        except (ValueError, TypeError):
            result['rule_id'] = None

    return result


# ================================================================
# GRAVITE EN LABEL
# ================================================================
GRAVITE_LABELS = {1: 'Faible', 2: 'Moyenne', 3: 'Haute', 4: 'Critique'}

def gravite_to_label(gravite):
    return GRAVITE_LABELS.get(gravite, 'Inconnue')

def wazuh_level_to_gravite(level):
    """Convertit le level Wazuh (0-15) en gravité SIEM Africa (1-4)"""
    if level >= 13:  return 4  # Critique
    if level >= 9:   return 3  # Haute
    if level >= 6:   return 2  # Moyenne
    return 1                   # Faible


# ================================================================
# AGENT PRINCIPAL
# ================================================================
class SiemAgent:

    def __init__(self):
        self.logger = setup_logging()
        self.config = load_config()
        self.db     = Database(self.config['DB_PATH'], self.logger)
        self.wazuh  = WazuhClient(
            host     = self.config['WAZUH_HOST'],
            port     = self.config['WAZUH_PORT'],
            user     = self.config['WAZUH_USER'],
            password = self.config['WAZUH_PASSWORD'],
            logger   = self.logger,
        )
        self.email  = EmailService(self.config, self.logger)

        self.polling_interval  = int(self.config.get('POLLING_INTERVAL', 10))
        self.corr_window       = int(self.config.get('CORRELATION_WINDOW', 60))
        self.corr_threshold    = int(self.config.get('CORRELATION_THRESHOLD', 3))
        self.last_poll_ts      = None

        # Cache des IPs géolocalisées pour éviter trop d'appels API
        self.geo_cache = {}

        self.logger.info('SIEM Africa — Agent demarre')
        self.logger.info(f'Wazuh : {self.config["WAZUH_HOST"]}:{self.config["WAZUH_PORT"]}')
        self.logger.info(f'Base  : {self.config["DB_PATH"]}')
        self.logger.info(f'Poll  : toutes les {self.polling_interval}s')
        self.logger.info(f'Corr  : {self.corr_threshold} alertes en {self.corr_window}s')

    def geolocate(self, ip):
        """Géolocalise une IP avec cache"""
        if not ip:
            return None, None
        if ip in self.geo_cache:
            return self.geo_cache[ip]
        pays, ville = geolocate_ip(ip)
        self.geo_cache[ip] = (pays, ville)
        return pays, ville

    def sync_agents(self):
        """Synchronise les agents Wazuh avec la base de données"""
        agents = self.wazuh.get_agents()
        for agent in agents:
            self.db.save_agent({
                'agent_wazuh_id': str(agent.get('id', '')),
                'nom':   agent.get('name', ''),
                'ip':    agent.get('ip', ''),
                'os':    agent.get('os', {}).get('name', '') if isinstance(agent.get('os'), dict) else '',
                'statut':
                    'Actif'   if agent.get('status') == 'active'      else
                    'Inactif' if agent.get('status') == 'disconnected' else
                    'Actif',
                'version_wazuh': agent.get('version', ''),
            })
        if agents:
            self.logger.info(f'Agents synchronises : {len(agents)}')

    def process_alert(self, raw_alert):
        """Traite une alerte brute Wazuh"""
        parsed = parse_wazuh_alert(raw_alert)
        if not parsed or not parsed.get('rule_id'):
            return

        rule_id   = parsed['rule_id']
        sid_snort = parsed.get('sid_snort')
        ip_source = parsed.get('ip_source')
        timestamp = parsed.get('timestamp_alerte')

        # Vérifier faux positif
        if ip_source and self.db.is_faux_positif(ip_source, rule_id):
            self.logger.debug(f'Faux positif ignore : rule_id={rule_id} ip={ip_source}')
            return

        # Chercher la signature dans la base
        attack = self.db.find_attack(rule_id, sid_snort)

        if attack:
            # ── Attaque CONNUE ────────────────────────────────
            gravite    = attack['gravite']
            alert_data = {
                'timestamp_alerte':  timestamp,
                'rule_id':           rule_id,
                'sid_snort':         sid_snort or attack.get('sid_snort'),
                'attaque_id':        attack['id'],
                'nom_attaque':       attack['nom'],
                'nom_attaque_en':    attack.get('nom_en', ''),
                'categorie':         attack['categorie'],
                'gravite':           gravite,
                'gravite_label':     gravite_to_label(gravite),
                'action_recommandee':attack['action_recommandee'],
                'contre_mesure':     attack.get('contre_mesure', ''),
                'est_inconnue':      0,
                'description_wazuh': parsed['description_wazuh'],
            }
        else:
            # ── Attaque INCONNUE ──────────────────────────────
            gravite_wazuh = parsed.get('gravite_wazuh', 0)
            gravite       = wazuh_level_to_gravite(gravite_wazuh)
            alert_data = {
                'timestamp_alerte':  timestamp,
                'rule_id':           rule_id,
                'sid_snort':         sid_snort,
                'attaque_id':        None,
                'nom_attaque':       f'Attaque inconnue (rule_id:{rule_id})',
                'nom_attaque_en':    f'Unknown attack (rule_id:{rule_id})',
                'categorie':         'Inconnu',
                'gravite':           gravite,
                'gravite_label':     gravite_to_label(gravite),
                'action_recommandee':'Alerter',
                'contre_mesure':     None,
                'est_inconnue':      1,
                'description_wazuh': parsed['description_wazuh'],
            }
            self.db.save_unknown_attack(
                rule_id,
                parsed['description_wazuh'],
                gravite_wazuh
            )

        # Données réseau
        alert_data.update({
            'ip_source':       ip_source,
            'ip_destination':  parsed.get('ip_destination'),
            'port_source':     parsed.get('port_source'),
            'port_destination':parsed.get('port_destination'),
            'protocole':       parsed.get('protocole'),
            'agent_id':        parsed.get('agent_id'),
            'machine_nom':     parsed.get('machine_nom'),
            'machine_os':      parsed.get('machine_os'),
        })

        # Géolocalisation
        if ip_source:
            pays, ville = self.geolocate(ip_source)
            alert_data['pays_source']  = pays
            alert_data['ville_source'] = ville

        # Corrélation
        corr_count = 0
        est_correllee = 0
        if ip_source:
            corr_count = self.db.get_recent_alerts_from_ip(
                ip_source, self.corr_window)
            if corr_count >= self.corr_threshold - 1:
                est_correllee = 1
                # Escalader en CRITIQUE
                alert_data['gravite']       = 4
                alert_data['gravite_label'] = 'Critique'
                self.logger.warning(
                    f'CORRELATION : {corr_count+1} alertes de {ip_source} '
                    f'en {self.corr_window}s — escalade CRITIQUE'
                )

        alert_data['est_correllee']     = est_correllee
        alert_data['correlation_count'] = corr_count + 1

        # Sauvegarder l'alerte
        alert_id = self.db.save_alert(alert_data)

        # Mettre à jour la corrélation si nécessaire
        if est_correllee and alert_id:
            self.db.update_correlation(alert_id, corr_count + 1)

        # Log
        nom = alert_data.get('nom_attaque', 'Inconnu')
        grav = alert_data.get('gravite_label', '?')
        self.logger.info(
            f'Alerte #{alert_id} | {grav} | {nom} | IP: {ip_source}'
            + (f' | CORRELEE x{corr_count+1}' if est_correllee else '')
        )

        # Notification email pour Critique et Haute
        if alert_data.get('gravite', 0) >= 3 and alert_id:
            if self.email.is_configured():
                succes = self.email.send_alert(alert_data, alert_id)
                self.db.save_notification(
                    alert_id, 'Email',
                    self.email.dest_email,
                    succes,
                    None if succes else 'Echec envoi SMTP'
                )

    def poll(self):
        """Un cycle de polling de l'API Wazuh"""
        try:
            alerts = self.wazuh.get_alerts(
                after_ts=self.last_poll_ts,
                limit=100
            )
            if alerts:
                self.logger.info(f'{len(alerts)} nouvelles alertes')
                for alert in alerts:
                    self.process_alert(alert)

            self.last_poll_ts = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        except Exception as e:
            self.logger.error(f'Erreur polling : {e}')

    def run(self):
        """Boucle principale de l'agent"""
        self.logger.info('Authentification Wazuh...')
        if not self.wazuh.authenticate():
            self.logger.error('Impossible de s authentifier a Wazuh. Attente 30s...')
            time.sleep(30)

        # Synchronisation initiale des agents
        self.sync_agents()
        agent_sync_counter = 0

        self.logger.info(f'Polling demarré — intervalle : {self.polling_interval}s')

        while True:
            try:
                self.poll()
                agent_sync_counter += 1
                # Re-synchroniser les agents toutes les 5 minutes
                if agent_sync_counter >= (300 // self.polling_interval):
                    self.sync_agents()
                    agent_sync_counter = 0
                time.sleep(self.polling_interval)
            except KeyboardInterrupt:
                self.logger.info('Agent arrete par l utilisateur')
                break
            except Exception as e:
                self.logger.error(f'Erreur inattendue : {e}')
                time.sleep(self.polling_interval)


# ================================================================
# ENTRYPOINT
# ================================================================
if __name__ == '__main__':
    agent = SiemAgent()
    agent.run()
