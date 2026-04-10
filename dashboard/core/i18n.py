"""
SIEM Africa — Traductions FR/EN
"""

TRANSLATIONS = {
    # Navigation
    'nav_dashboard':    {'fr': 'Tableau de bord', 'en': 'Dashboard'},
    'nav_alertes':      {'fr': 'Alertes',          'en': 'Alerts'},
    'nav_ips':          {'fr': 'IPs bloquees',     'en': 'Blocked IPs'},
    'nav_inconnues':    {'fr': 'Attaques inconnues','en': 'Unknown attacks'},
    'nav_rapports':     {'fr': 'Rapports',         'en': 'Reports'},
    'nav_parametres':   {'fr': 'Parametres',       'en': 'Settings'},
    'nav_deconnexion':  {'fr': 'Deconnexion',      'en': 'Logout'},

    # Gravite
    'critique':  {'fr': 'Critique', 'en': 'Critical'},
    'haute':     {'fr': 'Haute',    'en': 'High'},
    'moyenne':   {'fr': 'Moyenne',  'en': 'Medium'},
    'faible':    {'fr': 'Faible',   'en': 'Low'},

    # Statuts
    'nouveau':       {'fr': 'Nouveau',      'en': 'New'},
    'en_cours':      {'fr': 'En cours',     'en': 'In progress'},
    'resolu':        {'fr': 'Resolu',       'en': 'Resolved'},
    'faux_positif':  {'fr': 'Faux positif', 'en': 'False positive'},

    # Actions
    'bloquer_ip':      {'fr': 'Bloquer IP',    'en': 'Block IP'},
    'debloquer':       {'fr': 'Debloquer',     'en': 'Unblock'},
    'acquitter':       {'fr': 'Acquitter',     'en': 'Acknowledge'},
    'faux_pos_btn':    {'fr': 'Faux positif',  'en': 'False positive'},
    'enrichir':        {'fr': 'Enrichir',      'en': 'Enrich'},
    'enregistrer':     {'fr': 'Enregistrer',   'en': 'Save'},
    'annuler':         {'fr': 'Annuler',       'en': 'Cancel'},
    'generer':         {'fr': 'Generer',       'en': 'Generate'},
    'telecharger':     {'fr': 'Telecharger',   'en': 'Download'},

    # Dashboard
    'alertes_actives': {'fr': 'Alertes actives',    'en': 'Active alerts'},
    'ips_bloquees_nb': {'fr': 'IPs bloquees',       'en': 'Blocked IPs'},
    'att_inconnues':   {'fr': 'Attaques inconnues', 'en': 'Unknown attacks'},
    'alertes_24h':     {'fr': 'Alertes (24h)',      'en': 'Alerts (24h)'},
    'evolution_7j':    {'fr': 'Evolution sur 7 jours','en': '7-day trend'},
    'top_categories':  {'fr': 'Top categories',     'en': 'Top categories'},
    'actions_recentes':{'fr': 'Actions recentes',   'en': 'Recent actions'},

    # Alertes
    'alerte':          {'fr': 'Alerte',         'en': 'Alert'},
    'ip_source':       {'fr': 'IP Source',      'en': 'Source IP'},
    'pays':            {'fr': 'Pays',           'en': 'Country'},
    'machine':         {'fr': 'Machine',        'en': 'Machine'},
    'heure':           {'fr': 'Heure',          'en': 'Time'},
    'statut':          {'fr': 'Statut',         'en': 'Status'},
    'mitre':           {'fr': 'MITRE ATT&CK',   'en': 'MITRE ATT&CK'},
    'categorie':       {'fr': 'Categorie',      'en': 'Category'},
    'action_recomm':   {'fr': 'Action recommandee','en': 'Recommended action'},
    'contre_mesure':   {'fr': 'Contre-mesure',  'en': 'Counter-measure'},
    'details':         {'fr': 'Details',        'en': 'Details'},
    'honeypot_tag':    {'fr': 'HONEYPOT',       'en': 'HONEYPOT'},
    'correllee_tag':   {'fr': 'CORRELEE',       'en': 'CORRELATED'},

    # Parametres
    'smtp_host':       {'fr': 'Serveur SMTP',   'en': 'SMTP Server'},
    'smtp_port':       {'fr': 'Port SMTP',      'en': 'SMTP Port'},
    'smtp_user':       {'fr': 'Email expediteur','en': 'Sender email'},
    'alert_email':     {'fr': 'Email alertes',  'en': 'Alert email'},
    'langue':          {'fr': 'Langue',         'en': 'Language'},

    # Messages
    'connexion':       {'fr': 'Connexion',       'en': 'Login'},
    'bienvenue':       {'fr': 'Bienvenue sur SIEM Africa', 'en': 'Welcome to SIEM Africa'},
    'changer_creds':   {'fr': 'Changez vos identifiants', 'en': 'Change your credentials'},
    'premiere_co_msg': {
        'fr': 'Pour votre securite, veuillez changer votre nom d\'utilisateur et votre mot de passe avant de continuer.',
        'en': 'For your security, please change your username and password before continuing.'
    },
    'erreur_login':    {'fr': 'Identifiants incorrects', 'en': 'Invalid credentials'},
    'compte_bloque':   {'fr': 'Compte bloque 30 minutes (5 echecs)', 'en': 'Account locked 30 minutes (5 failures)'},
    'succes_action':   {'fr': 'Action effectuee avec succes', 'en': 'Action completed successfully'},
    'erreur_action':   {'fr': 'Erreur lors de l\'action', 'en': 'Action failed'},
}

def t(key, lang='fr'):
    """Traduire une cle"""
    entry = TRANSLATIONS.get(key)
    if not entry:
        return key
    return entry.get(lang, entry.get('fr', key))

def get_all(lang='fr'):
    """Retourne toutes les traductions pour un template"""
    return {k: v.get(lang, v.get('fr', k)) for k, v in TRANSLATIONS.items()}
