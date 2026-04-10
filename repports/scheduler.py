#!/usr/bin/env python3
# ================================================================
#  SIEM Africa — Module 6 : Planificateur de rapports
#  Fichier  : reports/scheduler.py
#  Version  : 2.0
#
#  Rapports automatiques :
#  - Hebdomadaire : chaque lundi 08h00
#  - Trimestriel  : 1er jour du trimestre 07h00
#  - Annuel       : 1er janvier 07h00
#  - Incident     : automatique apres resolution d'alerte
# ================================================================

import os
import sys
import time
import logging
import sqlite3
import datetime
import threading

# ── Logging ───────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('/var/log/siem-africa/reports.log'),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger('siem-reports')

# ── Configuration ─────────────────────────────────────────────────
ENV_FILE = '/opt/siem-africa/.env'

def load_env():
    cfg = {
        'DB_PATH':     '/opt/siem-africa/siem_africa.db',
        'REPORTS_DIR': '/opt/siem-africa/rapports',
        'LANG':        'fr',
    }
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, _, v = line.partition('=')
                    cfg[k.strip()] = v.strip().strip('"').strip("'")
    return cfg

# Importer le generateur
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from report_generator import generer_rapport

# ── Etat ──────────────────────────────────────────────────────────
_last_check_ts  = None
_alertes_traitees = set()  # IDs alertes deja traitees pour rapport incident

# ── Verifier les alertes resolues ─────────────────────────────────
def check_alertes_resolues():
    global _last_check_ts, _alertes_traitees
    cfg = load_env()
    try:
        with sqlite3.connect(cfg['DB_PATH'], timeout=5) as conn:
            conn.row_factory = sqlite3.Row
            # Chercher alertes critiques ou hautes recemment resolues
            depuis = _last_check_ts or (
                datetime.datetime.now() - datetime.timedelta(minutes=5)
            ).isoformat()

            rows = conn.execute('''
                SELECT id FROM alertes
                WHERE statut = 'Resolu'
                AND gravite >= 3
                AND timestamp_alerte >= ?
            ''', (depuis,)).fetchall()

            _last_check_ts = datetime.datetime.now().isoformat()

            for row in rows:
                aid = row['id']
                if aid not in _alertes_traitees:
                    _alertes_traitees.add(aid)
                    log.info(f'Rapport incident pour alerte #{aid}')
                    try:
                        pdf, xlsx = generer_rapport('incident', alerte_id=aid)
                        log.info(f'Rapport incident #{aid} genere : PDF={pdf} Excel={xlsx}')
                    except Exception as e:
                        log.error(f'Erreur rapport incident #{aid} : {e}')

    except Exception as e:
        log.error(f'Erreur check_alertes_resolues : {e}')

# ── Rapport hebdomadaire ───────────────────────────────────────────
def rapport_hebdomadaire():
    log.info('Generation rapport hebdomadaire...')
    try:
        pdf, xlsx = generer_rapport('hebdomadaire')
        log.info(f'Rapport hebdomadaire genere : PDF={pdf} Excel={xlsx}')
    except Exception as e:
        log.error(f'Erreur rapport hebdomadaire : {e}')

# ── Rapport trimestriel ────────────────────────────────────────────
def rapport_trimestriel():
    log.info('Generation rapport trimestriel...')
    try:
        pdf, xlsx = generer_rapport('trimestriel')
        log.info(f'Rapport trimestriel genere : PDF={pdf} Excel={xlsx}')
    except Exception as e:
        log.error(f'Erreur rapport trimestriel : {e}')

# ── Rapport annuel ─────────────────────────────────────────────────
def rapport_annuel():
    log.info('Generation rapport annuel...')
    try:
        pdf, xlsx = generer_rapport('annuel')
        log.info(f'Rapport annuel genere : PDF={pdf} Excel={xlsx}')
    except Exception as e:
        log.error(f'Erreur rapport annuel : {e}')

# ── Planificateur maison (sans dependance externe) ─────────────────
class Scheduler:
    """Planificateur leger sans bibliotheque externe"""

    def __init__(self):
        self.derniere_semaine  = None
        self.dernier_trimestre = None
        self.derniere_annee    = None

    def verifier(self):
        now = datetime.datetime.now()

        # ── Rapport hebdomadaire : lundi a 08h00 ──────────────────
        if now.weekday() == 0 and now.hour == 8 and now.minute < 2:
            semaine = now.strftime('%Y-S%W')
            if self.derniere_semaine != semaine:
                self.derniere_semaine = semaine
                threading.Thread(target=rapport_hebdomadaire, daemon=True).start()

        # ── Rapport trimestriel : 1er jour du trimestre a 07h00 ───
        if now.day == 1 and now.month in (1, 4, 7, 10) and now.hour == 7 and now.minute < 2:
            trimestre = f'{now.year}-T{(now.month-1)//3+1}'
            if self.dernier_trimestre != trimestre:
                self.dernier_trimestre = trimestre
                threading.Thread(target=rapport_trimestriel, daemon=True).start()

        # ── Rapport annuel : 1er janvier a 07h00 ──────────────────
        if now.day == 1 and now.month == 1 and now.hour == 7 and now.minute < 2:
            annee = str(now.year)
            if self.derniere_annee != annee:
                self.derniere_annee = annee
                threading.Thread(target=rapport_annuel, daemon=True).start()

        # ── Rapports incidents : toutes les 2 minutes ─────────────
        check_alertes_resolues()

# ── MAIN ──────────────────────────────────────────────────────────
def main():
    log.info('=' * 60)
    log.info('SIEM Africa — Planificateur de rapports v2.0 demarre')
    log.info('Hebdomadaire : lundi 08h00')
    log.info('Trimestriel  : 1er jour du trimestre 07h00')
    log.info('Annuel       : 1er janvier 07h00')
    log.info('Incident     : apres chaque alerte critique/haute resolue')
    log.info('=' * 60)

    cfg = load_env()
    os.makedirs(cfg.get('REPORTS_DIR', '/opt/siem-africa/rapports'), exist_ok=True)

    scheduler = Scheduler()

    while True:
        try:
            scheduler.verifier()
        except KeyboardInterrupt:
            log.info('Planificateur arrete')
            break
        except Exception as e:
            log.error(f'Erreur planificateur : {e}')
        time.sleep(120)  # Verifier toutes les 2 minutes

if __name__ == '__main__':
    main()
