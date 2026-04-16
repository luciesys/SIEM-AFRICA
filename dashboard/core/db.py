"""
SIEM Africa — Couche d'accès base de données SQLite
Toutes les requêtes passent par ce module
"""
import sqlite3
import json
import hashlib
import os
import re
from datetime import datetime, timedelta
from django.conf import settings

try:
    import bcrypt as _bcrypt
except ImportError:
    _bcrypt = None


def get_conn():
    conn = sqlite3.connect(settings.SIEM_DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


# ── Authentification ─────────────────────────────────────────────

def authentifier(username, password):
    """Vérifier username/password — retourne l'utilisateur ou None"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT * FROM utilisateurs
            WHERE username = ? AND est_actif = 1
        """, (username,))
        user = cur.fetchone()
        if not user:
            return None, "Utilisateur introuvable"

        # Vérifier si compte bloqué
        if user['bloque_jusqua']:
            bloque = datetime.fromisoformat(user['bloque_jusqua'])
            if datetime.now() < bloque:
                return None, f"Compte bloqué jusqu'à {bloque.strftime('%H:%M')}"
            else:
                cur.execute("""
                    UPDATE utilisateurs SET tentatives_echec=0, bloque_jusqua=NULL
                    WHERE id=?
                """, (user['id'],))
                conn.commit()

        # Vérifier le mot de passe
        ph = user['password_hash']
        if _bcrypt is not None:
            ok = _bcrypt.checkpw(password.encode(), ph.encode())
        else:
            ok = (hashlib.sha256(password.encode()).hexdigest() == ph)

        if not ok:
            tentatives = user['tentatives_echec'] + 1
            bloque_jusqua = None
            if tentatives >= 5:
                bloque_jusqua = (datetime.now() + timedelta(minutes=30)).strftime('%Y-%m-%d %H:%M:%S')
            cur.execute("""
                UPDATE utilisateurs
                SET tentatives_echec=?, bloque_jusqua=?
                WHERE id=?
            """, (tentatives, bloque_jusqua, user['id']))
            conn.commit()
            restants = max(0, 5 - tentatives)
            msg = f"Mot de passe incorrect ({restants} essai(s) restant(s))"
            if bloque_jusqua:
                msg = "Compte bloqué 30 minutes après 5 tentatives échouées"
            return None, msg

        # Succès — réinitialiser les tentatives
        cur.execute("""
            UPDATE utilisateurs
            SET tentatives_echec=0, bloque_jusqua=NULL,
                derniere_connexion=datetime('now')
            WHERE id=?
        """, (user['id'],))
        conn.commit()
        return dict(user), None

    finally:
        conn.close()


def changer_credentials(user_id, new_username, new_password):
    """Changer username et password — appelé à la 1ère connexion"""
    conn = get_conn()
    try:
        # Vérifier unicité du username
        cur = conn.cursor()
        cur.execute("SELECT id FROM utilisateurs WHERE username=? AND id!=?",
                    (new_username, user_id))
        if cur.fetchone():
            return False, "Ce nom d'utilisateur est déjà pris"

        # Valider username
        if not re.match(r'^[a-zA-Z0-9_-]{6,20}$', new_username):
            return False, "Username : 6-20 caractères, lettres/chiffres/-/_ uniquement"

        # Valider MDP
        if len(new_password) < 12:
            return False, "Mot de passe : minimum 12 caractères"
        if not re.search(r'[A-Z]', new_password):
            return False, "Mot de passe : au moins 1 majuscule"
        if not re.search(r'[a-z]', new_password):
            return False, "Mot de passe : au moins 1 minuscule"
        if not re.search(r'\d', new_password):
            return False, "Mot de passe : au moins 1 chiffre"
        if not re.search(r'[@#$%&*!]', new_password):
            return False, "Mot de passe : au moins 1 caractère spécial (@#$%&*!)"

        # Hasher le nouveau MDP
        if _bcrypt is not None:
            h = _bcrypt.hashpw(new_password.encode(), _bcrypt.gensalt(rounds=12)).decode()
        else:
            h = hashlib.sha256(new_password.encode()).hexdigest()

        cur.execute("""
            UPDATE utilisateurs
            SET username=?, password_hash=?, premiere_connexion=0,
                pwd_change_le=datetime('now'),
                pwd_expire_le=datetime('now', '+90 days'),
                modifie_le=datetime('now')
            WHERE id=?
        """, (new_username, h, user_id))
        conn.commit()
        return True, "Identifiants mis à jour avec succès"
    finally:
        conn.close()


def get_credentials_initiaux():
    """Lire les credentials initiaux depuis credentials.txt"""
    cred_file = settings.SIEM_CRED_FILE
    username = password = None
    try:
        with open(cred_file) as f:
            content = f.read()
        for line in content.splitlines():
            if 'Username' in line and ':' in line:
                username = line.split(':', 1)[1].strip()
            if 'Password' in line and ':' in line and 'IMPORTANT' not in line:
                password = line.split(':', 1)[1].strip()
    except Exception:
        pass
    return username, password


# ── Statistiques dashboard ───────────────────────────────────────

def get_stats():
    """Statistiques générales pour le dashboard"""
    conn = get_conn()
    try:
        cur = conn.cursor()

        cur.execute("SELECT * FROM v_stats_dashboard")
        stats = dict(cur.fetchone() or {})

        # Alertes des 7 derniers jours par jour
        cur.execute("""
            SELECT date(timestamp_alerte) as jour,
                   COUNT(*) as nb,
                   SUM(CASE WHEN gravite=4 THEN 1 ELSE 0 END) as critique,
                   SUM(CASE WHEN gravite=3 THEN 1 ELSE 0 END) as haute,
                   SUM(CASE WHEN gravite=2 THEN 1 ELSE 0 END) as moyenne,
                   SUM(CASE WHEN gravite=1 THEN 1 ELSE 0 END) as faible
            FROM alertes
            WHERE timestamp_alerte >= datetime('now', '-7 days')
            GROUP BY date(timestamp_alerte)
            ORDER BY jour ASC
        """)
        alertes_7j = [dict(r) for r in cur.fetchall()]

        # Top catégories
        cur.execute("""
            SELECT categorie, COUNT(*) as nb
            FROM alertes
            WHERE timestamp_alerte >= datetime('now', '-7 days')
              AND categorie IS NOT NULL
            GROUP BY categorie
            ORDER BY nb DESC
            LIMIT 8
        """)
        top_categories = [dict(r) for r in cur.fetchall()]

        # Top IPs suspectes
        cur.execute("""
            SELECT ip_source, COUNT(*) as nb,
                   MAX(gravite) as gravite_max
            FROM alertes
            WHERE ip_source IS NOT NULL
              AND ip_source != ''
              AND timestamp_alerte >= datetime('now', '-7 days')
            GROUP BY ip_source
            ORDER BY nb DESC
            LIMIT 10
        """)
        top_ips = [dict(r) for r in cur.fetchall()]

        # Alertes par heure (24h)
        cur.execute("""
            SELECT strftime('%H', timestamp_alerte) as heure,
                   COUNT(*) as nb
            FROM alertes
            WHERE timestamp_alerte >= datetime('now', '-24 hours')
            GROUP BY heure
            ORDER BY heure
        """)
        par_heure = {r['heure']: r['nb'] for r in cur.fetchall()}
        alertes_par_heure = [par_heure.get(f"{h:02d}", 0) for h in range(24)]

        # Honeypots
        cur.execute("""
            SELECT COUNT(*) as nb FROM alertes
            WHERE est_honeypot=1
            AND timestamp_alerte >= datetime('now', '-24 hours')
        """)
        honeypot_24h = (cur.fetchone() or {}).get('nb', 0)

        stats['alertes_7j']       = alertes_7j
        stats['top_categories']   = top_categories
        stats['top_ips']          = top_ips
        stats['alertes_par_heure']= alertes_par_heure
        stats['honeypot_24h']     = honeypot_24h
        return stats
    finally:
        conn.close()


def get_alertes(page=1, per_page=20, gravite=None, statut=None,
                categorie=None, ip=None, honeypot=None):
    """Liste paginée des alertes avec filtres"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        where = ["1=1"]
        params = []
        if gravite:
            where.append("gravite=?"); params.append(gravite)
        if statut:
            where.append("statut=?"); params.append(statut)
        if categorie:
            where.append("categorie=?"); params.append(categorie)
        if ip:
            where.append("ip_source LIKE ?"); params.append(f"%{ip}%")
        if honeypot is not None:
            where.append("est_honeypot=?"); params.append(1 if honeypot else 0)

        where_sql = " AND ".join(where)
        cur.execute(f"SELECT COUNT(*) as nb FROM v_alertes_detail WHERE {where_sql}", params)
        total = (cur.fetchone() or {}).get('nb', 0)

        offset = (page - 1) * per_page
        cur.execute(f"""
            SELECT * FROM v_alertes_detail
            WHERE {where_sql}
            ORDER BY timestamp_alerte DESC
            LIMIT ? OFFSET ?
        """, params + [per_page, offset])
        alertes = [dict(r) for r in cur.fetchall()]

        # Parser les actions JSON
        for a in alertes:
            try:
                a['actions_list'] = json.loads(a.get('actions_fr') or '[]')
            except (json.JSONDecodeError, TypeError):
                a['actions_list'] = []

        return alertes, total, (total + per_page - 1) // per_page
    finally:
        conn.close()


def get_alerte(alerte_id):
    """Détail d'une alerte"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM v_alertes_detail WHERE id=?", (alerte_id,))
        row = cur.fetchone()
        if not row:
            return None
        a = dict(row)
        try:
            a['actions_list'] = json.loads(a.get('actions_fr') or '[]')
        except:
            a['actions_list'] = []
        try:
            a['actions_list_en'] = json.loads(a.get('actions_en') or '[]')
        except (json.JSONDecodeError, TypeError):
            a['actions_list_en'] = []
        return a
    finally:
        conn.close()


def resoudre_alerte(alerte_id, user_id, commentaire='', est_fp=False):
    """Marquer une alerte comme résolue ou faux positif"""
    conn = get_conn()
    try:
        statut = 'Faux positif' if est_fp else 'Resolu'
        cur = conn.cursor()
        cur.execute("""
            UPDATE alertes
            SET statut=?, resolu_par=?, resolu_le=datetime('now'),
                commentaire=?
            WHERE id=?
        """, (statut, user_id, commentaire, alerte_id))

        if est_fp:
            cur.execute("""
                SELECT ip_source, rule_id FROM alertes WHERE id=?
            """, (alerte_id,))
            row = cur.fetchone()
            if row:
                cur.execute("""
                    INSERT INTO faux_positifs
                        (fp_type, ip_source, rule_id, alerte_id, raison,
                         confirme_par, est_actif)
                    VALUES ('manuel', ?, ?, ?, 'Marque manuellement', ?, 1)
                """, (row['ip_source'], row['rule_id'], alerte_id, user_id))

        cur.execute("""
            INSERT INTO actions_admin (admin_id, action, alerte_id, detail, resultat)
            VALUES (?, ?, ?, ?, 'succes')
        """, (user_id, 'resoudre_alerte', alerte_id, statut))
        conn.commit()
        return True
    finally:
        conn.close()


def get_ips_bloquees():
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT ib.*, u.username as bloque_par_username
            FROM ips_bloquees ib
            LEFT JOIN utilisateurs u ON ib.bloque_par = u.id
            ORDER BY ib.bloque_le DESC
        """)
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def bloquer_ip_db(ip, type_blocage, user_id, raison='', duree_h=None):
    conn = get_conn()
    try:
        cur = conn.cursor()
        expire = None
        if duree_h:
            cur.execute("SELECT datetime('now', '+' || ? || ' hours')", (duree_h,))
            expire = cur.fetchone()[0]
        cur.execute("""
            INSERT OR REPLACE INTO ips_bloquees
                (ip, type_blocage, bloque_par, raison, bloque_le, expire_le, est_actif)
            VALUES (?, ?, ?, ?, datetime('now'), ?, 1)
        """, (ip, type_blocage, user_id, raison, expire))
        cur.execute("""
            INSERT INTO actions_admin (admin_id, action, ip_cible, detail, resultat)
            VALUES (?, 'bloquer_ip', ?, ?, 'succes')
        """, (user_id, ip, f"{type_blocage} — {raison}"))
        conn.commit()
        return True
    finally:
        conn.close()


def debloquer_ip_db(ip, user_id):
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE ips_bloquees SET est_actif=0 WHERE ip=?", (ip,))
        cur.execute("""
            INSERT INTO actions_admin (admin_id, action, ip_cible, resultat)
            VALUES (?, 'debloquer_ip', ?, 'succes')
        """, (user_id, ip))
        conn.commit()
        return True
    finally:
        conn.close()


def get_ips_whitelist():
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT iw.*, u.username as ajoute_par_username
            FROM ips_whitelist iw
            LEFT JOIN utilisateurs u ON iw.ajoute_par = u.id
            WHERE iw.est_actif=1
            ORDER BY iw.ajoute_le DESC
        """)
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def ajouter_whitelist(ip, nom, raison, user_id):
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO ips_whitelist (ip, nom, raison, ajoute_par, est_actif)
            VALUES (?, ?, ?, ?, 1)
        """, (ip, nom, raison, user_id))
        conn.commit()
        return True
    finally:
        conn.close()


def get_alertes_inconnues():
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT * FROM attaques_inconnues
            ORDER BY nb_occurrences DESC, derniere_fois DESC
            LIMIT 100
        """)
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def get_parametres():
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT cle, valeur FROM parametres")
        return {r['cle']: r['valeur'] for r in cur.fetchall()}
    finally:
        conn.close()


def get_emails_alertes():
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM emails_alertes ORDER BY est_principal DESC")
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def get_categories():
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT DISTINCT categorie FROM alertes WHERE categorie IS NOT NULL ORDER BY categorie")
        return [r['categorie'] for r in cur.fetchall()]
    finally:
        conn.close()
