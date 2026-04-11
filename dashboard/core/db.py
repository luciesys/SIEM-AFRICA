"""
SIEM Africa — Acces direct a la base SQLite
Toutes les requetes passent par ce module
"""
import sqlite3
import datetime
from django.conf import settings


def conn():
    c = sqlite3.connect(settings.SIEM_DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys = ON')
    c.execute('PRAGMA journal_mode = WAL')
    return c


# ── Authentification ──────────────────────────────────────────────
def get_user(username):
    with conn() as c:
        return c.execute(
            'SELECT * FROM utilisateurs WHERE username=? AND est_actif=1',
            (username,)).fetchone()

def get_user_by_id(uid):
    with conn() as c:
        return c.execute('SELECT * FROM utilisateurs WHERE id=?', (uid,)).fetchone()

def verifier_mot_de_passe(password_hash, stored_hash):
    """Compare les hashs bcrypt"""
    try:
        import bcrypt
        return bcrypt.checkpw(password_hash.encode(), stored_hash.encode())
    except Exception:
        return password_hash == stored_hash

def hasher_mot_de_passe(password):
    try:
        import bcrypt
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    except Exception:
        import hashlib
        return hashlib.sha256(password.encode()).hexdigest()

def incrementer_echec(username):
    with conn() as c:
        c.execute(
            'UPDATE utilisateurs SET tentatives_echec=tentatives_echec+1 WHERE username=?',
            (username,))
        u = c.execute(
            'SELECT tentatives_echec FROM utilisateurs WHERE username=?',
            (username,)).fetchone()
        if u and u['tentatives_echec'] >= 5:
            bloque = (datetime.datetime.now() + datetime.timedelta(minutes=30)).isoformat()
            c.execute(
                'UPDATE utilisateurs SET bloque_jusqua=? WHERE username=?',
                (bloque, username))

def reset_echecs(username):
    with conn() as c:
        c.execute(
            "UPDATE utilisateurs SET tentatives_echec=0, bloque_jusqua=NULL, derniere_connexion=? WHERE username=?",
            (datetime.datetime.now().isoformat(), username))

def changer_credentials(uid, new_username, new_password_hash):
    """Change le mot de passe — email reste le login permanent"""
    with conn() as c:
        c.execute(
            'UPDATE utilisateurs SET password_hash=?, premiere_connexion=0 WHERE id=?',
            (new_password_hash, uid))

def username_existe(username, exclude_id=None):
    """Verifie si un email existe deja"""
    with conn() as c:
        if exclude_id:
            r = c.execute('SELECT id FROM utilisateurs WHERE email=? AND id!=?',
                          (username, exclude_id)).fetchone()
        else:
            r = c.execute('SELECT id FROM utilisateurs WHERE email=?',
                          (username,)).fetchone()
        return r is not None


# ── Stats dashboard ───────────────────────────────────────────────
def get_stats():
    with conn() as c:
        def count(q, p=()):
            r = c.execute(q, p).fetchone()
            return r[0] if r else 0

        now = datetime.datetime.now()
        h24 = (now - datetime.timedelta(hours=24)).isoformat()
        h1  = (now - datetime.timedelta(hours=1)).isoformat()

        return {
            'total_alertes':    count("SELECT COUNT(*) FROM alertes"),
            'alertes_24h':      count("SELECT COUNT(*) FROM alertes WHERE timestamp_alerte>=?", (h24,)),
            'critiques_actives':count("SELECT COUNT(*) FROM alertes WHERE gravite=4 AND statut='Nouveau'"),
            'hautes_actives':   count("SELECT COUNT(*) FROM alertes WHERE gravite=3 AND statut='Nouveau'"),
            'moyennes_actives': count("SELECT COUNT(*) FROM alertes WHERE gravite=2 AND statut='Nouveau'"),
            'faibles_actives':  count("SELECT COUNT(*) FROM alertes WHERE gravite=1 AND statut='Nouveau'"),
            'ips_bloquees':     count("SELECT COUNT(*) FROM ips_bloquees WHERE est_actif=1 AND type_blocage!='Whitelist'"),
            'inconnues':        count("SELECT COUNT(*) FROM attaques_inconnues WHERE enrichie=0"),
            'alertes_1h':       count("SELECT COUNT(*) FROM alertes WHERE timestamp_alerte>=?", (h1,)),
            'honeypot_24h':     count("SELECT COUNT(*) FROM alertes WHERE est_honeypot=1 AND timestamp_alerte>=?", (h24,)),
            'correlees_24h':    count("SELECT COUNT(*) FROM alertes WHERE est_correllee=1 AND timestamp_alerte>=?", (h24,)),
        }

def get_graphique_7j():
    """Alertes par jour sur les 7 derniers jours"""
    with conn() as c:
        res = []
        for i in range(6, -1, -1):
            d = datetime.datetime.now() - datetime.timedelta(days=i)
            debut = d.strftime('%Y-%m-%d 00:00:00')
            fin   = d.strftime('%Y-%m-%d 23:59:59')
            nb = c.execute(
                "SELECT COUNT(*) FROM alertes WHERE timestamp_alerte BETWEEN ? AND ?",
                (debut, fin)).fetchone()[0]
            res.append({'date': d.strftime('%d/%m'), 'nb': nb})
        return res

def get_top_categories(limit=5):
    with conn() as c:
        rows = c.execute('''
            SELECT categorie, COUNT(*) as nb
            FROM alertes WHERE categorie IS NOT NULL AND categorie != ''
            GROUP BY categorie ORDER BY nb DESC LIMIT ?
        ''', (limit,)).fetchall()
        return [dict(r) for r in rows]


# ── Alertes ───────────────────────────────────────────────────────
def get_alertes(page=1, per_page=20, gravite=None, statut=None, search=None):
    offset = (page - 1) * per_page
    where  = ['1=1']
    params = []

    if gravite:
        where.append('a.gravite=?'); params.append(int(gravite))
    if statut:
        where.append('a.statut=?'); params.append(statut)
    if search:
        where.append("(a.ip_source LIKE ? OR a.nom_attaque LIKE ? OR a.machine_nom LIKE ?)")
        s = f'%{search}%'
        params += [s, s, s]

    w = ' AND '.join(where)
    with conn() as c:
        total = c.execute(f'SELECT COUNT(*) FROM alertes a WHERE {w}', params).fetchone()[0]
        rows  = c.execute(f'''
            SELECT a.*, u.username as resolu_par_nom
            FROM alertes a
            LEFT JOIN utilisateurs u ON a.resolu_par=u.id
            WHERE {w}
            ORDER BY a.timestamp_alerte DESC
            LIMIT ? OFFSET ?
        ''', params + [per_page, offset]).fetchall()
        return [dict(r) for r in rows], total

def get_alerte(aid):
    with conn() as c:
        r = c.execute('''
            SELECT a.*, u.username as resolu_par_nom,
                   at.nom as attaque_nom_complet, at.mitre_id, at.mitre_tactique,
                   at.contre_mesure, at.action_recommandee
            FROM alertes a
            LEFT JOIN utilisateurs u ON a.resolu_par=u.id
            LEFT JOIN attaques at ON a.attaque_id=at.id
            WHERE a.id=?
        ''', (aid,)).fetchone()
        return dict(r) if r else None

def changer_statut_alerte(aid, statut, user_id):
    with conn() as c:
        c.execute(
            'UPDATE alertes SET statut=?, resolu_par=? WHERE id=?',
            (statut, user_id, aid))

def marquer_faux_positif(aid, user_id, ip, rule_id):
    with conn() as c:
        now = datetime.datetime.now().isoformat()
        c.execute("UPDATE alertes SET statut='Faux positif', resolu_par=? WHERE id=?",
                  (user_id, aid))
        c.execute('''
            INSERT OR IGNORE INTO faux_positifs
            (ip_source, rule_id, confirme_par, confirme_le) VALUES (?,?,?,?)
        ''', (ip, rule_id, user_id, now))


# ── IPs bloquees ─────────────────────────────────────────────────
def get_ips_bloquees(type_blocage=None):
    with conn() as c:
        q = '''
            SELECT i.*, u.username as bloque_par_nom
            FROM ips_bloquees i
            LEFT JOIN utilisateurs u ON i.bloque_par=u.id
            WHERE i.est_actif=1
        '''
        params = []
        if type_blocage:
            q += ' AND i.type_blocage=?'; params.append(type_blocage)
        q += ' ORDER BY i.bloque_le DESC'
        return [dict(r) for r in c.execute(q, params).fetchall()]

def bloquer_ip(ip, type_blocage, user_id, alerte_id, raison):
    with conn() as c:
        now = datetime.datetime.now().isoformat()
        existing = c.execute('SELECT id FROM ips_bloquees WHERE ip=?', (ip,)).fetchone()
        if existing:
            c.execute('''
                UPDATE ips_bloquees SET type_blocage=?, bloque_par=?, bloque_le=?,
                raison=?, est_actif=1 WHERE ip=?
            ''', (type_blocage, user_id, now, raison, ip))
        else:
            c.execute('''
                INSERT INTO ips_bloquees
                (ip, type_blocage, bloque_par, alerte_id, raison, bloque_le, est_actif)
                VALUES (?,?,?,?,?,?,1)
            ''', (ip, type_blocage, user_id, alerte_id, raison, now))

def debloquer_ip(ip_id):
    with conn() as c:
        c.execute('UPDATE ips_bloquees SET est_actif=0 WHERE id=?', (ip_id,))


# ── Attaques inconnues ────────────────────────────────────────────
def get_attaques_inconnues(enrichie=None):
    with conn() as c:
        q = 'SELECT * FROM attaques_inconnues'
        if enrichie is not None:
            q += f' WHERE enrichie={int(enrichie)}'
        q += ' ORDER BY nb_occurrences DESC'
        return [dict(r) for r in c.execute(q).fetchall()]

def enrichir_inconnue(inco_id, data, user_id):
    with conn() as c:
        now = datetime.datetime.now().isoformat()
        c.execute('''
            UPDATE attaques_inconnues
            SET nom_manuel=?, categorie_manuelle=?, gravite_manuelle=?,
                action_manuelle=?, enrichie=1, enrichie_par=?, enrichie_le=?
            WHERE id=?
        ''', (data['nom'], data['categorie'], data['gravite'],
              data.get('action', ''), user_id, now, inco_id))
        # Optionnel : ajouter dans la table attaques
        inco = c.execute('SELECT * FROM attaques_inconnues WHERE id=?', (inco_id,)).fetchone()
        if inco:
            c.execute('''
                INSERT OR IGNORE INTO attaques
                (rule_id, nom, nom_en, categorie, gravite, action_recommandee,
                 frequence_afrique, faux_positif)
                VALUES (?,?,?,?,?,?,?,0)
            ''', (inco['rule_id'], data['nom'], data['nom'],
                  data['categorie'], data['gravite'],
                  data.get('action', ''), 'Rare'))


# ── Parametres ────────────────────────────────────────────────────
def get_all_params():
    with conn() as c:
        rows = c.execute('SELECT cle, valeur, description FROM parametres ORDER BY cle').fetchall()
        return {r['cle']: {'valeur': r['valeur'], 'desc': r['description'] or ''} for r in rows}

def set_param(cle, valeur):
    with conn() as c:
        c.execute('UPDATE parametres SET valeur=? WHERE cle=?', (valeur, cle))

def get_param(cle, defaut=''):
    with conn() as c:
        r = c.execute('SELECT valeur FROM parametres WHERE cle=?', (cle,)).fetchone()
        return r['valeur'] if r else defaut


# ── Actions admin ─────────────────────────────────────────────────
def log_action(user_id, alerte_id, type_action, ip, commande, resultat, canal='Dashboard'):
    with conn() as c:
        c.execute('''
            INSERT INTO actions_admin
            (timestamp_action, admin_username, alerte_id, type_action,
             ip_concernee, commande_exec, resultat, canal)
            VALUES (?,?,?,?,?,?,?,?)
        ''', (datetime.datetime.now().isoformat(),
              str(user_id), alerte_id, type_action,
              ip, commande, resultat, canal))

def get_actions_recentes(limit=20):
    with conn() as c:
        return [dict(r) for r in c.execute('''
            SELECT a.*, u.username
            FROM actions_admin a
            LEFT JOIN utilisateurs u ON a.admin_username=CAST(u.id AS TEXT)
            ORDER BY a.timestamp_action DESC LIMIT ?
        ''', (limit,)).fetchall()]


# ── Rapports ──────────────────────────────────────────────────────
def get_rapports(limit=20):
    with conn() as c:
        return [dict(r) for r in c.execute('''
            SELECT r.*, u.username as genere_par_nom
            FROM rapports r
            LEFT JOIN utilisateurs u ON r.genere_par=u.id
            ORDER BY r.cree_le DESC LIMIT ?
        ''', (limit,)).fetchall()]
