#!/usr/bin/env python3
# ================================================================
#  SIEM Africa — Module 3 : Agent intelligent
#  Fichier  : agent/agent.py
#  Version  : 2.0 — Complet
#
#  Composants :
#  1.  Verification prerequis (Snort + Wazuh)
#  2.  Detection automatique MDP Wazuh
#  3.  Polling API Wazuh toutes les 10s
#  4.  Enrichissement SQLite (380 signatures + MITRE)
#  5.  Detection comportementale (5 regles)
#  6.  Machine Learning — Isolation Forest
#  7.  Correlation (simple + multi-etapes APT)
#  8.  Active Response (timer 5 min)
#  9.  Honeypot (faux services SSH/HTTP/MySQL)
#  10. Notifications email SMTP
#  11. Stockage SQLite
# ================================================================

import os
import sys
import time
import json
import sqlite3
import logging
import smtplib
import socket
import threading
import subprocess
import urllib.request
import urllib.error
import ssl
import datetime
import tarfile
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ML — installe si absent
try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
    ML_DISPONIBLE = True
except ImportError:
    ML_DISPONIBLE = False

# ================================================================
# CONFIGURATION
# ================================================================
ENV_FILE = '/opt/siem-africa/.env'

def load_env():
    config = {
        'WAZUH_HOST':            '127.0.0.1',
        'WAZUH_PORT':            '55000',
        'WAZUH_USER':            'wazuh',
        'WAZUH_PASSWORD':        '',
        'DB_PATH':               '/opt/siem-africa/siem_africa.db',
        'POLLING_INTERVAL':      '10',
        'CORRELATION_WINDOW':    '60',
        'CORRELATION_THRESHOLD': '3',
        'ACTIVE_RESPONSE_DELAY': '300',
        'SMTP_HOST':             'smtp.gmail.com',
        'SMTP_PORT':             '587',
        'SMTP_USER':             '',
        'SMTP_PASSWORD':         '',
        'ALERT_EMAIL':           '',
        'LANG':                  'fr',
        'ML_APPRENTISSAGE_JOURS':'7',
        'HONEYPOT_ENABLED':      '1',
        'HONEYPOT_SSH_PORT':     '2222',
        'HONEYPOT_HTTP_PORT':    '8888',
        'HONEYPOT_MYSQL_PORT':   '3307',
    }
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, _, v = line.partition('=')
                    config[k.strip()] = v.strip().strip('"').strip("'")
    return config

# ================================================================
# LOGGING
# ================================================================
def setup_logging():
    log_dir = '/var/log/siem-africa'
    os.makedirs(log_dir, exist_ok=True)
    log_file = f'{log_dir}/agent.log'
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout),
        ]
    )
    return logging.getLogger('siem-africa')

# ================================================================
# 1. VERIFICATION DES PREREQUIS
# ================================================================
def verifier_prerequis(log):
    log.info('Verification des prerequis...')
    erreurs = []

    # Snort installe
    try:
        r = subprocess.run(['snort', '--version'],
                           capture_output=True, text=True, timeout=5)
        log.info('Snort detecte')
    except FileNotFoundError:
        erreurs.append('Snort non installe — lancez le module 1')
    except Exception as e:
        erreurs.append(f'Erreur Snort : {e}')

    # Service Snort actif
    try:
        r = subprocess.run(['systemctl', 'is-active', 'snort'],
                           capture_output=True, text=True, timeout=5)
        if r.stdout.strip() == 'active':
            log.info('Service Snort actif')
        else:
            log.warning('Service Snort non actif')
    except Exception:
        pass

    # Wazuh installe
    if not os.path.isdir('/var/ossec'):
        erreurs.append('Wazuh non installe — lancez le module 1')
    else:
        log.info('Wazuh detecte : /var/ossec present')

    # Service Wazuh Manager actif
    try:
        r = subprocess.run(['systemctl', 'is-active', 'wazuh-manager'],
                           capture_output=True, text=True, timeout=5)
        if r.stdout.strip() == 'active':
            log.info('Service Wazuh Manager actif')
        else:
            erreurs.append('Service wazuh-manager non actif — systemctl start wazuh-manager')
    except Exception:
        pass

    # Base SQLite
    config = load_env()
    db_path = config['DB_PATH']
    if not os.path.isfile(db_path):
        erreurs.append(f'Base de donnees non trouvee : {db_path} — lancez le module 2')
    else:
        try:
            conn = sqlite3.connect(db_path)
            nb = conn.execute('SELECT COUNT(*) FROM attaques').fetchone()[0]
            conn.close()
            if nb == 0:
                erreurs.append('Table attaques vide — lancez le module 2')
            else:
                log.info(f'Base SQLite OK : {nb} signatures')
        except Exception as e:
            erreurs.append(f'Erreur base de donnees : {e}')

    if erreurs:
        log.error('PREREQUIS NON SATISFAITS :')
        for e in erreurs:
            log.error(f'  -> {e}')
        return False

    log.info('Tous les prerequis sont satisfaits')
    return True

# ================================================================
# 2. DETECTION AUTOMATIQUE DU MDP WAZUH
# ================================================================
def detecter_mdp_wazuh(log):
    log.info('Detection automatique du mot de passe Wazuh...')

    # Chercher le tar dans plusieurs emplacements
    wazuh_tar = None
    for path in ['/root/wazuh-install-files.tar', '/tmp/wazuh-install-files.tar']:
        if os.path.isfile(path):
            wazuh_tar = path
            break

    if wazuh_tar:
        try:
            with tarfile.open(wazuh_tar, 'r') as tar:
                # Trouver wazuh-passwords.txt dans le tar
                pass_member = None
                for member in tar.getmembers():
                    if 'wazuh-passwords.txt' in member.name:
                        pass_member = member
                        break

                if pass_member:
                    f = tar.extractfile(pass_member)
                    content = f.read().decode('utf-8', errors='ignore')

                    # Parser le mot de passe pour api_username: 'wazuh'
                    in_wazuh = False
                    for line in content.splitlines():
                        if "api_username" in line and "'wazuh'" in line:
                            in_wazuh = True
                        elif in_wazuh and "api_password" in line:
                            # Extraire le mot de passe entre apostrophes
                            m = re.search(r"api_password.*?'([^']+)'", line)
                            if m:
                                mdp = m.group(1)
                                log.info('Mot de passe Wazuh detecte automatiquement')
                                # Mettre a jour le .env
                                _mettre_a_jour_env('WAZUH_PASSWORD', mdp)
                                _mettre_a_jour_env('WAZUH_USER', 'wazuh')
                                return mdp, 'wazuh'
                            in_wazuh = False
        except Exception as e:
            log.warning(f'Erreur lecture tar Wazuh : {e}')

    # Fallback : lire depuis .env
    config = load_env()
    if config.get('WAZUH_PASSWORD'):
        log.info('Mot de passe Wazuh lu depuis .env')
        return config['WAZUH_PASSWORD'], config.get('WAZUH_USER', 'wazuh')

    log.warning('Mot de passe Wazuh non detecte automatiquement')
    return '', 'wazuh'

def _mettre_a_jour_env(cle, valeur):
    try:
        if os.path.exists(ENV_FILE):
            with open(ENV_FILE) as f:
                contenu = f.read()
            if f'{cle}=' in contenu:
                contenu = re.sub(
                    rf'^{cle}=.*$', f'{cle}={valeur}',
                    contenu, flags=re.MULTILINE
                )
            else:
                contenu += f'\n{cle}={valeur}'
            with open(ENV_FILE, 'w') as f:
                f.write(contenu)
    except Exception:
        pass

# ================================================================
# 3. CLIENT WAZUH API
# ================================================================
class WazuhClient:

    def __init__(self, host, port, user, password, log):
        self.base_url  = f'https://{host}:{port}'
        self.user      = user
        self.password  = password
        self.token     = None
        self.token_ts  = 0
        self.log       = log
        self.ctx       = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode    = ssl.CERT_NONE

    def _requete(self, method, endpoint, headers=None):
        url = f'{self.base_url}{endpoint}'
        req = urllib.request.Request(url, headers=headers or {}, method=method)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=10) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8', errors='ignore')
            self.log.error(f'HTTP {e.code} sur {endpoint}: {body[:150]}')
            return None
        except Exception as e:
            self.log.error(f'Erreur requete {endpoint}: {e}')
            return None

    def authentifier(self):
        import base64
        creds = base64.b64encode(f'{self.user}:{self.password}'.encode()).decode()
        r = self._requete('GET', '/security/user/authenticate',
                          headers={'Authorization': f'Basic {creds}'})
        if r and 'data' in r:
            self.token    = r['data']['token']
            self.token_ts = time.time()
            self.log.info('Token Wazuh obtenu')
            return True
        self.log.error('Echec authentification Wazuh')
        return False

    def get_token(self):
        if not self.token or (time.time() - self.token_ts) > 870:
            self.authentifier()
        return self.token

    def get_alertes(self, depuis_ts=None, limit=100):
        token = self.get_token()
        if not token:
            return []
        params = f'?limit={limit}&sort=-timestamp'
        if depuis_ts:
            params += f'&q=timestamp>{depuis_ts}'
        for endpoint in [f'/security/events{params}', f'/alerts{params}']:
            r = self._requete('GET', endpoint,
                              headers={'Authorization': f'Bearer {token}'})
            if r and 'data' in r:
                return r['data'].get('affected_items', [])
        return []

    def get_agents(self):
        token = self.get_token()
        if not token:
            return []
        r = self._requete('GET', '/agents?limit=500',
                          headers={'Authorization': f'Bearer {token}'})
        if r and 'data' in r:
            return r['data'].get('affected_items', [])
        return []

# ================================================================
# 4. BASE DE DONNEES
# ================================================================
class Database:

    def __init__(self, db_path, log):
        self.db_path = db_path
        self.log     = log

    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys = ON')
        conn.execute('PRAGMA journal_mode = WAL')
        return conn

    # ── Signatures ────────────────────────────────────────────────
    def chercher_attaque(self, rule_id, sid_snort=None):
        with self._conn() as c:
            r = c.execute(
                'SELECT * FROM attaques WHERE rule_id=? AND faux_positif=0',
                (rule_id,)).fetchone()
            if r:
                return dict(r)
            if sid_snort:
                r = c.execute(
                    'SELECT * FROM attaques WHERE sid_snort=? AND faux_positif=0',
                    (sid_snort,)).fetchone()
                if r:
                    return dict(r)
        return None

    def est_faux_positif(self, ip, rule_id):
        with self._conn() as c:
            r = c.execute(
                'SELECT id FROM faux_positifs WHERE ip_source=? AND rule_id=?',
                (ip, rule_id)).fetchone()
            return r is not None

    # ── Alertes ───────────────────────────────────────────────────
    def sauver_alerte(self, data):
        with self._conn() as c:
            cur = c.execute('''
                INSERT INTO alertes (
                    timestamp_alerte, rule_id, sid_snort, attaque_id,
                    nom_attaque, nom_attaque_en, categorie,
                    gravite, gravite_label, action_recommandee, contre_mesure,
                    ip_source, ip_destination, port_source, port_destination,
                    protocole, pays_source, ville_source,
                    agent_id, machine_nom, machine_os,
                    est_inconnue, est_honeypot, description_wazuh,
                    est_correllee, correlation_count, statut
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ''', (
                data.get('timestamp_alerte'),
                data.get('rule_id'),
                data.get('sid_snort'),
                data.get('attaque_id'),
                data.get('nom_attaque'),
                data.get('nom_attaque_en'),
                data.get('categorie'),
                data.get('gravite'),
                data.get('gravite_label'),
                data.get('action_recommandee'),
                data.get('contre_mesure'),
                data.get('ip_source'),
                data.get('ip_destination'),
                data.get('port_source'),
                data.get('port_destination'),
                data.get('protocole'),
                data.get('pays_source'),
                data.get('ville_source'),
                data.get('agent_id'),
                data.get('machine_nom'),
                data.get('machine_os'),
                data.get('est_inconnue', 0),
                data.get('est_honeypot', 0),
                data.get('description_wazuh'),
                data.get('est_correllee', 0),
                data.get('correlation_count', 1),
                'Nouveau',
            ))
            return cur.lastrowid

    def sauver_attaque_inconnue(self, rule_id, description, gravite_wazuh):
        with self._conn() as c:
            existing = c.execute(
                'SELECT id, nb_occurrences FROM attaques_inconnues WHERE rule_id=?',
                (rule_id,)).fetchone()
            now = datetime.datetime.now().isoformat()
            if existing:
                c.execute(
                    'UPDATE attaques_inconnues SET nb_occurrences=?, derniere_vue=? WHERE rule_id=?',
                    (existing['nb_occurrences'] + 1, now, rule_id))
            else:
                c.execute('''
                    INSERT INTO attaques_inconnues
                    (rule_id, description_wazuh, gravite_wazuh, nb_occurrences, premiere_vue, derniere_vue)
                    VALUES (?,?,?,1,?,?)
                ''', (rule_id, description, gravite_wazuh, now, now))

    def nb_alertes_recentes_ip(self, ip, window_sec):
        with self._conn() as c:
            depuis = (datetime.datetime.now() -
                      datetime.timedelta(seconds=window_sec)).isoformat()
            r = c.execute(
                "SELECT COUNT(*) FROM alertes WHERE ip_source=? AND timestamp_alerte>=? AND statut='Nouveau'",
                (ip, depuis)).fetchone()
            return r[0] if r else 0

    def alertes_recentes_ip_categories(self, ip, window_sec):
        with self._conn() as c:
            depuis = (datetime.datetime.now() -
                      datetime.timedelta(seconds=window_sec)).isoformat()
            rows = c.execute(
                'SELECT categorie FROM alertes WHERE ip_source=? AND timestamp_alerte>=?',
                (ip, depuis)).fetchall()
            return [r['categorie'] for r in rows if r['categorie']]

    def mettre_a_jour_correlation(self, alerte_id, count):
        with self._conn() as c:
            c.execute(
                "UPDATE alertes SET est_correllee=1, correlation_count=?, gravite=4, gravite_label='Critique' WHERE id=?",
                (count, alerte_id))

    def get_param(self, cle, defaut=''):
        with self._conn() as c:
            r = c.execute('SELECT valeur FROM parametres WHERE cle=?', (cle,)).fetchone()
            return r['valeur'] if r else defaut

    # ── Agents ────────────────────────────────────────────────────
    def sauver_agent(self, data):
        with self._conn() as c:
            existing = c.execute(
                'SELECT id FROM agents WHERE agent_wazuh_id=?',
                (data['agent_wazuh_id'],)).fetchone()
            now = datetime.datetime.now().isoformat()
            if existing:
                c.execute('''
                    UPDATE agents SET nom=?, ip=?, os=?, statut=?, derniere_vue=?
                    WHERE agent_wazuh_id=?
                ''', (data.get('nom',''), data.get('ip',''), data.get('os',''),
                      data.get('statut','Actif'), now, data['agent_wazuh_id']))
            else:
                c.execute('''
                    INSERT INTO agents (agent_wazuh_id,nom,ip,os,statut,derniere_vue,cree_le)
                    VALUES (?,?,?,?,?,?,?)
                ''', (data['agent_wazuh_id'], data.get('nom',''), data.get('ip',''),
                      data.get('os',''), data.get('statut','Actif'), now, now))

    # ── Notifications ─────────────────────────────────────────────
    def sauver_notification(self, alerte_id, type_notif, dest, succes, erreur=None):
        with self._conn() as c:
            now = datetime.datetime.now().isoformat()
            c.execute('''
                INSERT INTO notifications (alerte_id,type_notif,destinataire,envoye,envoye_le,erreur)
                VALUES (?,?,?,?,?,?)
            ''', (alerte_id, type_notif, dest,
                  1 if succes else 0, now if succes else None, erreur))

    # ── Actions admin ─────────────────────────────────────────────
    def sauver_action_auto(self, alerte_id, ip, commande, resultat):
        with self._conn() as c:
            c.execute('''
                INSERT INTO actions_admin
                (timestamp_action, admin_username, alerte_id, type_action,
                 ip_concernee, commande_exec, resultat, canal)
                VALUES (?,?,?,?,?,?,?,?)
            ''', (datetime.datetime.now().isoformat(), 'siem-agent', alerte_id,
                  'Bloquer IP permanent', ip, commande, resultat, 'Automatique'))

    # ── Comportements ML ──────────────────────────────────────────
    def sauver_comportement(self, data):
        try:
            with self._conn() as c:
                c.execute('''
                    INSERT INTO comportements
                    (timestamp_mesure, nb_alertes_10min, nb_ips_uniques,
                     heure_du_jour, gravite_moyenne, ratio_inconnus,
                     nb_critiques, nb_correlees, est_anomalie, score_ml, phase)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                ''', (
                    data.get('timestamp'),
                    data.get('nb_alertes', 0),
                    data.get('nb_ips', 0),
                    data.get('heure', 0),
                    data.get('gravite_moy', 0.0),
                    data.get('ratio_inconnus', 0.0),
                    data.get('nb_critiques', 0),
                    data.get('nb_correlees', 0),
                    data.get('est_anomalie', 0),
                    data.get('score', None),
                    data.get('phase', 'apprentissage'),
                ))
        except Exception:
            pass

    def get_historique_comportements(self, jours=7):
        with self._conn() as c:
            depuis = (datetime.datetime.now() -
                      datetime.timedelta(days=jours)).isoformat()
            rows = c.execute('''
                SELECT nb_alertes_10min, nb_ips_uniques, heure_du_jour,
                       gravite_moyenne, ratio_inconnus
                FROM comportements WHERE timestamp_mesure>=?
            ''', (depuis,)).fetchall()
            return [[r[0],r[1],r[2],r[3],r[4]] for r in rows]

    def nb_comportements_total(self):
        with self._conn() as c:
            r = c.execute('SELECT COUNT(*) FROM comportements').fetchone()
            return r[0] if r else 0

# ================================================================
# 5. DETECTION COMPORTEMENTALE
# ================================================================
class DetecteurComportemental:

    def __init__(self, config, db, log):
        self.config = config
        self.db     = db
        self.log    = log

    def analyser(self, alerte_data):
        """Applique 5 regles comportementales sur une alerte"""
        gravite    = alerte_data.get('gravite', 1)
        ip         = alerte_data.get('ip_source', '')
        timestamp  = alerte_data.get('timestamp_alerte', '')
        escalade   = False
        raisons    = []

        # Regle 1 — Anomalie temporelle
        # Connexion SSH entre minuit et 6h = suspect
        try:
            heure = int(timestamp[11:13]) if len(timestamp) > 12 else datetime.datetime.now().hour
            if heure < 6 or heure >= 23:
                if alerte_data.get('port_destination') in [22, 3389, 5900]:
                    gravite   = min(gravite + 1, 4)
                    escalade  = True
                    raisons.append(f'Anomalie temporelle : connexion a distance a {heure}h')
        except Exception:
            pass

        # Regle 2 — Anomalie de volume
        # Plus de 200 alertes de la meme IP en 1 heure
        if ip:
            nb_1h = self.db.nb_alertes_recentes_ip(ip, 3600)
            if nb_1h > 200:
                gravite  = 4
                escalade = True
                raisons.append(f'Anomalie de volume : {nb_1h} alertes depuis {ip} en 1h')

        # Regle 3 — Sequence APT
        # Scan + Brute Force + Connexion reussie depuis meme IP en 10 min
        if ip:
            cats = self.db.alertes_recentes_ip_categories(ip, 600)
            a_scan = any('Reconnaissance' in c or 'Scan' in c for c in cats)
            a_bf   = any('Brute Force' in c for c in cats)
            a_intr = any('Intrusion' in c for c in cats)
            if a_scan and a_bf and a_intr:
                gravite  = 4
                escalade = True
                raisons.append(f'Sequence APT detectee depuis {ip} : Scan + BF + Intrusion')

        # Regle 4 — Fichier critique modifie la nuit
        desc = alerte_data.get('description_wazuh', '')
        fichiers_critiques = ['/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/crontab']
        try:
            heure_now = datetime.datetime.now().hour
            if any(f in desc for f in fichiers_critiques) and (heure_now < 6 or heure_now >= 22):
                gravite  = 4
                escalade = True
                raisons.append('Fichier critique modifie la nuit — backdoor possible')
        except Exception:
            pass

        # Regle 5 — Pic de trafic anormal
        # Volume > 10x la moyenne habituelle (approximation)
        if ip:
            nb_10min = self.db.nb_alertes_recentes_ip(ip, 600)
            if nb_10min > 50:
                gravite  = min(gravite + 1, 4)
                escalade = True
                raisons.append(f'Pic de trafic : {nb_10min} alertes en 10min depuis {ip}')

        if escalade:
            for r in raisons:
                self.log.warning(f'[COMPORTEMENT] {r}')

        return gravite, raisons

# ================================================================
# 6. MACHINE LEARNING — ISOLATION FOREST
# ================================================================
class ModeleML:

    def __init__(self, config, db, log):
        self.config      = config
        self.db          = db
        self.log         = log
        self.modele      = None
        self.phase       = 'apprentissage'
        self.jours_min   = int(config.get('ML_APPRENTISSAGE_JOURS', 7))
        self._dernier_entrainement = None

        if not ML_DISPONIBLE:
            self.log.warning('scikit-learn non disponible — ML desactive')

    def collecter_metriques(self):
        """Collecte les metriques actuelles du reseau"""
        now    = datetime.datetime.now()
        heure  = now.hour
        depuis = (now - datetime.timedelta(minutes=10)).isoformat()

        try:
            with self.db._conn() as c:
                nb_alertes = c.execute(
                    "SELECT COUNT(*) FROM alertes WHERE timestamp_alerte>=?",
                    (depuis,)).fetchone()[0]
                nb_ips = c.execute(
                    "SELECT COUNT(DISTINCT ip_source) FROM alertes WHERE timestamp_alerte>=?",
                    (depuis,)).fetchone()[0]
                grav_moy = c.execute(
                    "SELECT AVG(gravite) FROM alertes WHERE timestamp_alerte>=?",
                    (depuis,)).fetchone()[0] or 0.0
                nb_inconnus = c.execute(
                    "SELECT COUNT(*) FROM alertes WHERE timestamp_alerte>=? AND est_inconnue=1",
                    (depuis,)).fetchone()[0]
                nb_critiques = c.execute(
                    "SELECT COUNT(*) FROM alertes WHERE timestamp_alerte>=? AND gravite=4",
                    (depuis,)).fetchone()[0]
                nb_correlees = c.execute(
                    "SELECT COUNT(*) FROM alertes WHERE timestamp_alerte>=? AND est_correllee=1",
                    (depuis,)).fetchone()[0]

            ratio_inconnus = nb_inconnus / max(nb_alertes, 1)
            return {
                'timestamp':    now.isoformat(),
                'nb_alertes':   nb_alertes,
                'nb_ips':       nb_ips,
                'heure':        heure,
                'gravite_moy':  round(float(grav_moy), 2),
                'ratio_inconnus': round(ratio_inconnus, 2),
                'nb_critiques': nb_critiques,
                'nb_correlees': nb_correlees,
            }
        except Exception as e:
            self.log.error(f'Erreur collecte metriques ML : {e}')
            return None

    def entrainer(self):
        """Entraine le modele Isolation Forest"""
        if not ML_DISPONIBLE:
            return False
        historique = self.db.get_historique_comportements(self.jours_min)
        if len(historique) < 50:
            return False
        try:
            X = np.array(historique)
            self.modele = IsolationForest(contamination=0.05, random_state=42, n_estimators=100)
            self.modele.fit(X)
            self._dernier_entrainement = datetime.datetime.now()
            self.log.info(f'Modele ML entraine sur {len(historique)} observations')
            return True
        except Exception as e:
            self.log.error(f'Erreur entrainement ML : {e}')
            return False

    def predire(self, metriques):
        """Retourne True si anomalie detectee"""
        if not ML_DISPONIBLE or self.modele is None:
            return False, None
        try:
            X = np.array([[
                metriques['nb_alertes'],
                metriques['nb_ips'],
                metriques['heure'],
                metriques['gravite_moy'],
                metriques['ratio_inconnus'],
            ]])
            score   = self.modele.score_samples(X)[0]
            predict = self.modele.predict(X)[0]
            return predict == -1, round(float(score), 4)
        except Exception as e:
            self.log.error(f'Erreur prediction ML : {e}')
            return False, None

    def cycle(self):
        """Un cycle ML complet : collecter + entrainer si besoin + predire"""
        if not ML_DISPONIBLE:
            return

        metriques = self.collecter_metriques()
        if not metriques:
            return

        # Determiner la phase
        nb_obs = self.db.nb_comportements_total()
        seuil  = self.jours_min * 144  # 144 mesures par jour (toutes les 10 min)

        if nb_obs < seuil:
            self.phase = 'apprentissage'
            anomalie   = False
            score      = None
        else:
            self.phase = 'detection'
            # Re-entrainer chaque semaine
            if (self.modele is None or
                    self._dernier_entrainement is None or
                    (datetime.datetime.now() - self._dernier_entrainement).days >= 7):
                self.entrainer()
            anomalie, score = self.predire(metriques)

        # Sauvegarder
        metriques['est_anomalie'] = 1 if anomalie else 0
        metriques['score']        = score
        metriques['phase']        = self.phase
        self.db.sauver_comportement(metriques)

        if anomalie:
            self.log.warning(
                f'[ML] Anomalie comportementale detectee ! '
                f'Score={score} | Alertes={metriques["nb_alertes"]} | '
                f'IPs={metriques["nb_ips"]} | Heure={metriques["heure"]}h'
            )

# ================================================================
# 7. CORRELATION
# ================================================================
class Correlateur:

    def __init__(self, config, db, log):
        self.db        = db
        self.log       = log
        self.window    = int(config.get('CORRELATION_WINDOW', 60))
        self.threshold = int(config.get('CORRELATION_THRESHOLD', 3))

    def analyser(self, ip, alerte_id):
        """Detecte la correlation et escalade si necessaire"""
        if not ip:
            return False, 0

        nb = self.db.nb_alertes_recentes_ip(ip, self.window)

        if nb >= self.threshold - 1:
            self.log.warning(
                f'[CORRELATION] {nb+1} alertes de {ip} en {self.window}s — escalade CRITIQUE'
            )
            if alerte_id:
                self.db.mettre_a_jour_correlation(alerte_id, nb + 1)
            return True, nb + 1

        return False, nb + 1

# ================================================================
# 8. ACTIVE RESPONSE — TIMER 5 MINUTES
# ================================================================
class ActiveResponse:

    def __init__(self, config, db, log):
        self.db    = db
        self.log   = log
        self.delai = int(config.get('ACTIVE_RESPONSE_DELAY', 300))
        # {alerte_id: threading.Timer}
        self._timers = {}
        self._lock   = threading.Lock()

    def programmer(self, alerte_id, ip, contre_mesure):
        """Programme un blocage automatique si l'admin ne reagit pas"""
        if not ip or not alerte_id:
            return

        def _executer():
            with self._lock:
                self._timers.pop(alerte_id, None)

            # Verifier si l'alerte a ete traitee par l'admin
            try:
                with self.db._conn() as c:
                    row = c.execute(
                        "SELECT statut FROM alertes WHERE id=?",
                        (alerte_id,)).fetchone()
                    if row and row['statut'] not in ('Nouveau',):
                        self.log.info(
                            f'[ACTIVE RESPONSE] Alerte #{alerte_id} deja traitee — annulation')
                        return
            except Exception:
                pass

            # Executer la contre-mesure iptables
            commande = contre_mesure.replace('{IP}', ip) if contre_mesure else \
                       f'iptables -A INPUT -s {ip} -j DROP'

            try:
                result = subprocess.run(
                    commande, shell=True, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    self.log.warning(
                        f'[ACTIVE RESPONSE] IP {ip} bloquee automatiquement '
                        f'(alerte #{alerte_id}) — admin non reactif en {self.delai}s'
                    )
                    self.db.sauver_action_auto(alerte_id, ip, commande, 'Succes')
                    # Enregistrer dans ips_bloquees
                    with self.db._conn() as c:
                        c.execute('''
                            INSERT OR IGNORE INTO ips_bloquees
                            (ip, type_blocage, bloque_le, raison, alerte_id, est_actif)
                            VALUES (?,?,?,?,?,1)
                        ''', (ip, 'Permanent',
                              datetime.datetime.now().isoformat(),
                              'Blocage automatique Active Response',
                              alerte_id))
                else:
                    self.log.error(f'[ACTIVE RESPONSE] Echec blocage {ip}: {result.stderr}')
                    self.db.sauver_action_auto(alerte_id, ip, commande, 'Echec')
            except Exception as e:
                self.log.error(f'[ACTIVE RESPONSE] Erreur : {e}')
                self.db.sauver_action_auto(alerte_id, ip, commande, 'Echec')

        timer = threading.Timer(self.delai, _executer)
        timer.daemon = True
        with self._lock:
            self._timers[alerte_id] = timer
        timer.start()
        self.log.info(
            f'[ACTIVE RESPONSE] Timer {self.delai}s programme pour alerte #{alerte_id} (IP: {ip})')

    def annuler(self, alerte_id):
        """Annule le timer si l'admin a agi"""
        with self._lock:
            timer = self._timers.pop(alerte_id, None)
        if timer:
            timer.cancel()
            self.log.info(f'[ACTIVE RESPONSE] Timer annule pour alerte #{alerte_id}')

# ================================================================
# 9. HONEYPOT
# ================================================================
class Honeypot:

    def __init__(self, config, db, log, agent):
        self.config  = config
        self.db      = db
        self.log     = log
        self.agent   = agent
        self.actif   = config.get('HONEYPOT_ENABLED', '1') == '1'
        self.threads = []

    def demarrer(self):
        if not self.actif:
            return
        services = [
            (int(self.config.get('HONEYPOT_SSH_PORT',   '2222')), 'SSH',   self._handler_ssh),
            (int(self.config.get('HONEYPOT_HTTP_PORT',  '8888')), 'HTTP',  self._handler_http),
            (int(self.config.get('HONEYPOT_MYSQL_PORT', '3307')), 'MySQL', self._handler_mysql),
        ]
        for port, nom, handler in services:
            t = threading.Thread(
                target=self._ecouter, args=(port, nom, handler),
                daemon=True, name=f'Honeypot-{nom}'
            )
            t.start()
            self.threads.append(t)
            self.log.info(f'[HONEYPOT] Faux service {nom} demarre sur le port {port}')

    def _ecouter(self, port, nom, handler):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(('0.0.0.0', port))
            srv.listen(5)
            while True:
                try:
                    conn, addr = srv.accept()
                    ip_source  = addr[0]
                    t = threading.Thread(
                        target=handler,
                        args=(conn, ip_source, port, nom),
                        daemon=True
                    )
                    t.start()
                except Exception:
                    pass
        except OSError as e:
            self.log.warning(f'[HONEYPOT] Port {port} ({nom}) : {e}')

    def _alerter(self, ip, port, nom, donnees=''):
        self.log.warning(
            f'[HONEYPOT] Connexion SUSPECTE sur faux {nom} (port {port}) depuis {ip}')
        alerte = {
            'timestamp_alerte':  datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'rule_id':           9000 + port,
            'sid_snort':         None,
            'attaque_id':        None,
            'nom_attaque':       f'Honeypot {nom} — Acces suspect',
            'nom_attaque_en':    f'Honeypot {nom} — Suspicious access',
            'categorie':         'Honeypot',
            'gravite':           4,
            'gravite_label':     'Critique',
            'action_recommandee':'Bloquer IP immediatement',
            'contre_mesure':     f'iptables -A INPUT -s {{IP}} -j DROP',
            'ip_source':         ip,
            'est_inconnue':      0,
            'est_honeypot':      1,
            'description_wazuh': f'Connexion honeypot {nom} port {port}. Donnees: {donnees[:100]}',
            'est_correllee':     0,
            'correlation_count': 1,
        }
        pays, ville = geolocate_ip(ip)
        alerte['pays_source']  = pays
        alerte['ville_source'] = ville
        alerte_id = self.db.sauver_alerte(alerte)
        if alerte_id and self.agent:
            self.agent.active_response.programmer(
                alerte_id, ip, f'iptables -A INPUT -s {ip} -j DROP')

    def _handler_ssh(self, conn, ip, port, nom):
        try:
            conn.sendall(b'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n')
            data = conn.recv(1024).decode('utf-8', errors='ignore')
            self._alerter(ip, port, nom, data)
            conn.close()
        except Exception:
            pass

    def _handler_http(self, conn, ip, port, nom):
        try:
            data = conn.recv(1024).decode('utf-8', errors='ignore')
            conn.sendall(
                b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n'
                b'<html><body>Admin Panel</body></html>'
            )
            self._alerter(ip, port, nom, data[:200])
            conn.close()
        except Exception:
            pass

    def _handler_mysql(self, conn, ip, port, nom):
        try:
            # Banner MySQL
            conn.sendall(b'\x4a\x00\x00\x00\x0a5.7.40\x00')
            data = conn.recv(256)
            self._alerter(ip, port, nom, str(data[:50]))
            conn.close()
        except Exception:
            pass

# ================================================================
# 10. NOTIFICATIONS EMAIL
# ================================================================
class EmailService:

    def __init__(self, config, log):
        self.smtp_host = config.get('SMTP_HOST', 'smtp.gmail.com')
        self.smtp_port = int(config.get('SMTP_PORT', 587))
        self.smtp_user = config.get('SMTP_USER', '')
        self.smtp_pass = config.get('SMTP_PASSWORD', '')
        self.dest      = config.get('ALERT_EMAIL', '')
        self.lang      = config.get('LANG', 'fr')
        self.log       = log

    def configure(self):
        return bool(self.smtp_user and self.smtp_pass and self.dest)

    def envoyer(self, alerte_data, alerte_id):
        if not self.configure():
            return False

        gravite  = alerte_data.get('gravite_label', 'Inconnue')
        nom      = alerte_data.get('nom_attaque', 'Attaque inconnue')
        ip       = alerte_data.get('ip_source', 'N/A')
        pays     = alerte_data.get('pays_source', 'N/A')
        machine  = alerte_data.get('machine_nom', 'N/A')
        action   = alerte_data.get('action_recommandee', 'N/A')
        contre   = alerte_data.get('contre_mesure', 'N/A')
        mitre    = alerte_data.get('mitre_id', '')
        correllee= alerte_data.get('est_correllee', 0)
        honeypot = alerte_data.get('est_honeypot', 0)
        ts       = alerte_data.get('timestamp_alerte', 'N/A')

        if self.lang == 'en':
            sujet = f'[SIEM Africa] {gravite} — {nom}'
            corps = (
                f'SIEM Africa — Alert #{alerte_id}\n'
                f'{"="*50}\n\n'
                f'Severity  : {gravite}\n'
                f'Attack    : {nom}\n'
                f'Source IP : {ip}\n'
                f'Country   : {pays}\n'
                f'Machine   : {machine}\n'
                f'Detected  : {ts}\n'
            )
            if mitre:
                corps += f'MITRE     : {mitre}\n'
            if correllee:
                corps += f'CORRELATED: YES — multiple alerts from same IP\n'
            if honeypot:
                corps += f'HONEYPOT  : YES — attacker touched fake service\n'
            corps += (
                f'\nRecommended: {action}\n'
                f'iptables   : {contre}\n'
                f'\nDashboard  : http://YOUR_SERVER:8000\n'
            )
        else:
            sujet = f'[SIEM Africa] {gravite} — {nom}'
            corps = (
                f'SIEM Africa — Alerte #{alerte_id}\n'
                f'{"="*50}\n\n'
                f'Gravite    : {gravite}\n'
                f'Attaque    : {nom}\n'
                f'IP source  : {ip}\n'
                f'Pays       : {pays}\n'
                f'Machine    : {machine}\n'
                f'Detectee   : {ts}\n'
            )
            if mitre:
                corps += f'MITRE      : {mitre}\n'
            if correllee:
                corps += f'CORRELEE   : OUI — plusieurs alertes meme IP\n'
            if honeypot:
                corps += f'HONEYPOT   : OUI — attaquant sur faux service\n'
            corps += (
                f'\nAction     : {action}\n'
                f'iptables   : {contre}\n'
                f'\nDashboard  : http://VOTRE_SERVEUR:8000\n'
            )

        try:
            msg            = MIMEMultipart()
            msg['From']    = self.smtp_user
            msg['To']      = self.dest
            msg['Subject'] = sujet
            msg.attach(MIMEText(corps, 'plain', 'utf-8'))
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as srv:
                srv.starttls()
                srv.login(self.smtp_user, self.smtp_pass)
                srv.sendmail(self.smtp_user, self.dest, msg.as_string())
            self.log.info(f'Email envoye pour alerte #{alerte_id}')
            return True
        except Exception as e:
            self.log.error(f'Erreur email : {e}')
            return False

# ================================================================
# GEOLOCALISATION
# ================================================================
_geo_cache = {}

def geolocate_ip(ip):
    if not ip or ip.startswith(('10.', '192.168.', '172.', '127.')):
        return None, None
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        url = f'http://ip-api.com/json/{ip}?fields=country,city,status'
        req = urllib.request.Request(url, headers={'User-Agent': 'SIEM-Africa/2.0'})
        with urllib.request.urlopen(req, timeout=3) as r:
            data = json.loads(r.read().decode())
            if data.get('status') == 'success':
                result = data.get('country'), data.get('city')
                _geo_cache[ip] = result
                return result
    except Exception:
        pass
    return None, None

# ================================================================
# PARSEUR ALERTES WAZUH
# ================================================================
def parser_alerte(raw):
    if not raw:
        return None
    r = {
        'timestamp_alerte': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'rule_id':          None,
        'sid_snort':        None,
        'ip_source':        None,
        'ip_destination':   None,
        'port_source':      None,
        'port_destination': None,
        'protocole':        None,
        'agent_id':         '',
        'machine_nom':      '',
        'machine_os':       '',
        'description_wazuh':'',
        'gravite_wazuh':    0,
    }

    ts = raw.get('timestamp', '')
    if ts:
        try:
            dt = datetime.datetime.fromisoformat(ts.replace('Z', '+00:00'))
            r['timestamp_alerte'] = dt.strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            pass

    rule                   = raw.get('rule', {})
    r['rule_id']           = rule.get('id')
    r['description_wazuh'] = rule.get('description', '')
    r['gravite_wazuh']     = rule.get('level', 0)

    agent             = raw.get('agent', {})
    r['agent_id']     = agent.get('id', '')
    r['machine_nom']  = agent.get('name', '')

    data = raw.get('data', {})
    r['ip_source']       = (data.get('srcip') or data.get('src_ip') or
                             (data.get('source', {}).get('ip') if isinstance(data.get('source'), dict) else None))
    r['ip_destination']  = (data.get('dstip') or data.get('dst_ip'))
    r['port_source']     = data.get('srcport') or data.get('src_port')
    r['port_destination']= data.get('dstport') or data.get('dst_port')
    r['protocole']       = data.get('protocol') or data.get('proto')

    snort = data.get('snort', {})
    if isinstance(snort, dict):
        r['sid_snort'] = snort.get('sid')

    if r['rule_id']:
        try:
            r['rule_id'] = int(r['rule_id'])
        except (ValueError, TypeError):
            r['rule_id'] = None

    return r

def wazuh_level_to_gravite(level):
    if level >= 13: return 4
    if level >= 9:  return 3
    if level >= 6:  return 2
    return 1

LABELS = {1: 'Faible', 2: 'Moyenne', 3: 'Haute', 4: 'Critique'}

# ================================================================
# AGENT PRINCIPAL
# ================================================================
class SiemAgent:

    def __init__(self):
        self.log    = setup_logging()
        self.config = load_env()

        # Detection MDP Wazuh au demarrage
        mdp, user = detecter_mdp_wazuh(self.log)
        if mdp:
            self.config['WAZUH_PASSWORD'] = mdp
            self.config['WAZUH_USER']     = user

        self.db      = Database(self.config['DB_PATH'], self.log)
        self.wazuh   = WazuhClient(
            self.config['WAZUH_HOST'], self.config['WAZUH_PORT'],
            self.config['WAZUH_USER'], self.config['WAZUH_PASSWORD'], self.log)
        self.email          = EmailService(self.config, self.log)
        self.comportemental = DetecteurComportemental(self.config, self.db, self.log)
        self.ml             = ModeleML(self.config, self.db, self.log)
        self.correlateur    = Correlateur(self.config, self.db, self.log)
        self.active_response= ActiveResponse(self.config, self.db, self.log)
        self.honeypot       = Honeypot(self.config, self.db, self.log, self)

        self.polling_interval = int(self.config.get('POLLING_INTERVAL', 10))
        self.last_poll_ts     = None
        self._sync_counter    = 0

    def traiter_alerte(self, raw):
        parsed = parser_alerte(raw)
        if not parsed or not parsed.get('rule_id'):
            return

        rule_id   = parsed['rule_id']
        sid_snort = parsed.get('sid_snort')
        ip        = parsed.get('ip_source')

        # Verifier faux positif
        if ip and self.db.est_faux_positif(ip, rule_id):
            return

        # 4. Enrichissement SQLite + MITRE
        attaque = self.db.chercher_attaque(rule_id, sid_snort)

        if attaque:
            gravite    = attaque['gravite']
            alerte = {
                'timestamp_alerte':  parsed['timestamp_alerte'],
                'rule_id':           rule_id,
                'sid_snort':         sid_snort or attaque.get('sid_snort'),
                'attaque_id':        attaque['id'],
                'nom_attaque':       attaque['nom'],
                'nom_attaque_en':    attaque.get('nom_en', ''),
                'categorie':         attaque['categorie'],
                'gravite':           gravite,
                'gravite_label':     LABELS.get(gravite, 'Inconnue'),
                'action_recommandee':attaque['action_recommandee'],
                'contre_mesure':     attaque.get('contre_mesure', ''),
                'mitre_id':          attaque.get('mitre_id', ''),
                'mitre_tactique':    attaque.get('mitre_tactique', ''),
                'est_inconnue':      0,
                'description_wazuh': parsed['description_wazuh'],
            }
        else:
            gravite = wazuh_level_to_gravite(parsed['gravite_wazuh'])
            alerte = {
                'timestamp_alerte':  parsed['timestamp_alerte'],
                'rule_id':           rule_id,
                'sid_snort':         sid_snort,
                'attaque_id':        None,
                'nom_attaque':       f'Inconnue (rule_id:{rule_id})',
                'nom_attaque_en':    f'Unknown (rule_id:{rule_id})',
                'categorie':         'Inconnu',
                'gravite':           gravite,
                'gravite_label':     LABELS.get(gravite, 'Inconnue'),
                'action_recommandee':'Alerter',
                'contre_mesure':     '',
                'est_inconnue':      1,
                'description_wazuh': parsed['description_wazuh'],
            }
            self.db.sauver_attaque_inconnue(
                rule_id, parsed['description_wazuh'], parsed['gravite_wazuh'])

        # Donnees reseau
        alerte.update({
            'ip_source':        ip,
            'ip_destination':   parsed.get('ip_destination'),
            'port_source':      parsed.get('port_source'),
            'port_destination': parsed.get('port_destination'),
            'protocole':        parsed.get('protocole'),
            'agent_id':         parsed.get('agent_id'),
            'machine_nom':      parsed.get('machine_nom'),
            'machine_os':       parsed.get('machine_os'),
            'est_honeypot':     0,
        })

        # Geolocalisation
        if ip:
            pays, ville = geolocate_ip(ip)
            alerte['pays_source']  = pays
            alerte['ville_source'] = ville

        # 5. Detection comportementale
        gravite_final, raisons = self.comportemental.analyser(alerte)
        alerte['gravite']      = gravite_final
        alerte['gravite_label']= LABELS.get(gravite_final, 'Inconnue')

        # 11. Sauvegarder
        alerte_id = self.db.sauver_alerte(alerte)

        # 7. Correlation
        correllee, count = self.correlateur.analyser(ip, alerte_id)
        alerte['est_correllee']     = 1 if correllee else 0
        alerte['correlation_count'] = count

        # Log
        self.log.info(
            f'Alerte #{alerte_id} | {alerte["gravite_label"]} | '
            f'{alerte["nom_attaque"]} | IP: {ip}'
            + (f' | CORRELEE x{count}' if correllee else '')
            + (f' | MITRE: {alerte.get("mitre_id","")}' if alerte.get('mitre_id') else '')
        )

        # 8. Active Response si CRITIQUE
        if alerte['gravite'] == 4 and alerte_id and ip:
            self.active_response.programmer(
                alerte_id, ip, alerte.get('contre_mesure', ''))

        # 10. Email si >= Haute
        if alerte['gravite'] >= 3 and alerte_id:
            if self.email.configure():
                ok = self.email.envoyer(alerte, alerte_id)
                self.db.sauver_notification(
                    alerte_id, 'Email', self.email.dest, ok,
                    None if ok else 'Echec SMTP')

    def poll(self):
        try:
            alertes = self.wazuh.get_alertes(
                depuis_ts=self.last_poll_ts, limit=100)
            if alertes:
                self.log.info(f'{len(alertes)} nouvelles alertes Wazuh')
                for a in alertes:
                    self.traiter_alerte(a)
            self.last_poll_ts = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        except Exception as e:
            self.log.error(f'Erreur polling : {e}')

    def run(self):
        self.log.info('=' * 60)
        self.log.info('SIEM Africa — Agent v2.0 demarre')
        self.log.info(f'Wazuh  : {self.config["WAZUH_HOST"]}:{self.config["WAZUH_PORT"]}')
        self.log.info(f'Base   : {self.config["DB_PATH"]}')
        self.log.info(f'Poll   : toutes les {self.polling_interval}s')
        self.log.info(f'Corr.  : {self.config["CORRELATION_THRESHOLD"]} alertes en {self.config["CORRELATION_WINDOW"]}s')
        self.log.info(f'AR     : timer {self.config["ACTIVE_RESPONSE_DELAY"]}s')
        self.log.info(f'ML     : {"actif" if ML_DISPONIBLE else "inactif (installer scikit-learn)"}')
        self.log.info(f'Honeypot : {"actif" if self.config.get("HONEYPOT_ENABLED","1")=="1" else "inactif"}')
        self.log.info('=' * 60)

        # Verification prerequis
        if not verifier_prerequis(self.log):
            self.log.error('Arret — prerequis non satisfaits')
            sys.exit(1)

        # Authentification Wazuh
        if not self.wazuh.authentifier():
            self.log.warning('Wazuh non disponible — nouvelle tentative dans 30s')
            time.sleep(30)

        # Demarrer le honeypot dans des threads
        self.honeypot.demarrer()

        # Synchronisation initiale des agents
        self._sync_agents()

        # Cycle ML initial
        threading.Thread(target=self._cycle_ml, daemon=True).start()

        self.log.info('Polling demarre')

        while True:
            try:
                self.poll()
                self._sync_counter += 1
                # Sync agents toutes les 5 minutes
                if self._sync_counter >= (300 // self.polling_interval):
                    self._sync_agents()
                    self._sync_counter = 0
                time.sleep(self.polling_interval)
            except KeyboardInterrupt:
                self.log.info('Agent arrete')
                break
            except Exception as e:
                self.log.error(f'Erreur inattendue : {e}')
                time.sleep(self.polling_interval)

    def _sync_agents(self):
        agents = self.wazuh.get_agents()
        for a in agents:
            self.db.sauver_agent({
                'agent_wazuh_id': str(a.get('id', '')),
                'nom':    a.get('name', ''),
                'ip':     a.get('ip', ''),
                'os':     a.get('os', {}).get('name', '') if isinstance(a.get('os'), dict) else '',
                'statut': 'Actif' if a.get('status') == 'active' else 'Inactif',
            })
        if agents:
            self.log.info(f'Agents synchronises : {len(agents)}')

    def _cycle_ml(self):
        """Thread ML — tourne toutes les 10 minutes"""
        while True:
            try:
                self.ml.cycle()
            except Exception as e:
                self.log.error(f'Erreur cycle ML : {e}')
            time.sleep(600)

# ================================================================
# ENTRYPOINT
# ================================================================
if __name__ == '__main__':
    agent = SiemAgent()
    agent.run()
