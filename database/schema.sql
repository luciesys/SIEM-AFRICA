-- ================================================================
--  SIEM Africa — Schema base de donnees SQLite
--  Fichier  : database/schema.sql
-- ================================================================

PRAGMA foreign_keys = ON;
PRAGMA journal_mode  = WAL;
PRAGMA synchronous   = NORMAL;

-- ================================================================
-- TABLE 1 : utilisateurs
-- ================================================================
CREATE TABLE IF NOT EXISTS utilisateurs (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    username           TEXT    UNIQUE NOT NULL
                       CHECK(length(username) >= 6 AND length(username) <= 20),
    password_hash      TEXT    NOT NULL,
    role               TEXT    NOT NULL DEFAULT 'admin_securite'
                       CHECK(role IN ('admin_securite','dirigeant')),
    email_alertes      TEXT,
    langue             TEXT    NOT NULL DEFAULT 'fr'
                       CHECK(langue IN ('fr','en')),
    organisation       TEXT,
    est_actif          INTEGER NOT NULL DEFAULT 1,
    premiere_connexion INTEGER NOT NULL DEFAULT 1,
    pwd_expire_le      TEXT    DEFAULT (datetime('now','+90 days')),
    pwd_change_le      TEXT    DEFAULT (datetime('now')),
    historique_pwd     TEXT    NOT NULL DEFAULT '[]',
    tentatives_echec   INTEGER NOT NULL DEFAULT 0,
    bloque_jusqua      TEXT,
    derniere_connexion TEXT,
    cree_le            TEXT    NOT NULL DEFAULT (datetime('now')),
    modifie_le         TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_usr_username ON utilisateurs(username);
CREATE INDEX IF NOT EXISTS idx_usr_actif    ON utilisateurs(est_actif);
CREATE INDEX IF NOT EXISTS idx_usr_role     ON utilisateurs(role);

-- ================================================================
-- TABLE 2 : emails_alertes
-- Liste emails de notification (plusieurs possibles)
-- ================================================================
CREATE TABLE IF NOT EXISTS emails_alertes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT    UNIQUE NOT NULL,
    nom           TEXT,
    est_actif     INTEGER NOT NULL DEFAULT 1,
    est_principal INTEGER NOT NULL DEFAULT 0,
    ajoute_par    INTEGER REFERENCES utilisateurs(id),
    ajoute_le     TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_email_actif ON emails_alertes(est_actif);

-- ================================================================
-- TABLE 3 : attaques
-- 380 signatures contextualisees Afrique + MITRE + actions
-- ================================================================
CREATE TABLE IF NOT EXISTS attaques (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id            INTEGER NOT NULL,
    sid_snort          INTEGER,
    nom                TEXT    NOT NULL,
    nom_en             TEXT,
    categorie          TEXT    NOT NULL
                       CHECK(categorie IN (
                           'Scan de ports','Brute Force','Deni de service',
                           'Injection SQL','XSS','Malware Ransomware',
                           'Phishing','Exploitation','Intrusion reseau',
                           'Exfiltration','Man in the Middle','Botnet C2',
                           'Fraude financiere','Cryptomining',
                           'Infrastructure','Honeypot'
                       )),
    description        TEXT    NOT NULL,
    description_en     TEXT,
    gravite            INTEGER NOT NULL CHECK(gravite BETWEEN 1 AND 4),
    gravite_label      TEXT    NOT NULL
                       CHECK(gravite_label IN ('Faible','Moyenne','Haute','Critique')),
    actions_fr         TEXT    NOT NULL DEFAULT '[]',
    actions_en         TEXT    NOT NULL DEFAULT '[]',
    contre_mesure      TEXT,
    contre_mesure_en   TEXT,
    mitre_id           TEXT,
    mitre_tactique     TEXT,
    mitre_technique    TEXT,
    frequence_afrique  TEXT    NOT NULL DEFAULT 'Commune'
                       CHECK(frequence_afrique IN ('Tres commune','Commune','Rare')),
    contexte_afrique   TEXT,
    fp_frequence       INTEGER NOT NULL DEFAULT 0,
    fp_raison          TEXT,
    source             TEXT    NOT NULL DEFAULT 'Snort'
                       CHECK(source IN ('Snort','Wazuh','Custom')),
    protocole          TEXT,
    port_cible         INTEGER,
    cve                TEXT,
    cree_le            TEXT    DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_att_rule_id   ON attaques(rule_id);
CREATE INDEX IF NOT EXISTS idx_att_sid       ON attaques(sid_snort);
CREATE INDEX IF NOT EXISTS idx_att_gravite   ON attaques(gravite);
CREATE INDEX IF NOT EXISTS idx_att_categorie ON attaques(categorie);
CREATE INDEX IF NOT EXISTS idx_att_mitre     ON attaques(mitre_id);

-- ================================================================
-- TABLE 4 : alertes
-- ================================================================
CREATE TABLE IF NOT EXISTS alertes (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_alerte        TEXT    NOT NULL DEFAULT (datetime('now')),
    rule_id                 INTEGER NOT NULL,
    sid_snort               INTEGER,
    attaque_id              INTEGER REFERENCES attaques(id),
    nom_attaque             TEXT,
    nom_attaque_en          TEXT,
    categorie               TEXT,
    gravite                 INTEGER CHECK(gravite BETWEEN 1 AND 4),
    gravite_label           TEXT,
    actions_fr              TEXT    DEFAULT '[]',
    actions_en              TEXT    DEFAULT '[]',
    contre_mesure           TEXT,
    mitre_id                TEXT,
    mitre_tactique          TEXT,
    mitre_technique         TEXT,
    ip_source               TEXT,
    ip_destination          TEXT,
    port_source             INTEGER,
    port_destination        INTEGER,
    protocole               TEXT,
    pays_source             TEXT,
    ville_source            TEXT,
    agent_id                TEXT,
    machine_nom             TEXT,
    machine_os              TEXT,
    score_confiance         INTEGER NOT NULL DEFAULT 100
                            CHECK(score_confiance BETWEEN 0 AND 100),
    est_faux_positif_predit INTEGER NOT NULL DEFAULT 0,
    raison_fp_predit        TEXT,
    statut                  TEXT    NOT NULL DEFAULT 'Nouveau'
                            CHECK(statut IN ('Nouveau','En cours','Resolu','Faux positif','Ignore')),
    resolu_par              INTEGER REFERENCES utilisateurs(id),
    resolu_le               TEXT,
    commentaire             TEXT,
    est_inconnue            INTEGER NOT NULL DEFAULT 0,
    est_honeypot            INTEGER NOT NULL DEFAULT 0,
    est_correllee           INTEGER NOT NULL DEFAULT 0,
    est_bloquee_auto        INTEGER NOT NULL DEFAULT 0,
    description_wazuh       TEXT,
    raw_alert               TEXT,
    cree_le                 TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_ale_timestamp ON alertes(timestamp_alerte);
CREATE INDEX IF NOT EXISTS idx_ale_gravite   ON alertes(gravite);
CREATE INDEX IF NOT EXISTS idx_ale_statut    ON alertes(statut);
CREATE INDEX IF NOT EXISTS idx_ale_ip_source ON alertes(ip_source);
CREATE INDEX IF NOT EXISTS idx_ale_categorie ON alertes(categorie);
CREATE INDEX IF NOT EXISTS idx_ale_fp        ON alertes(est_faux_positif_predit);

-- ================================================================
-- TABLE 5 : faux_positifs (4 niveaux)
-- ================================================================
CREATE TABLE IF NOT EXISTS faux_positifs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    fp_type      TEXT    NOT NULL
                 CHECK(fp_type IN ('signature','ip','manuel','correlation')),
    ip_source    TEXT,
    rule_id      INTEGER,
    sid_snort    INTEGER,
    categorie    TEXT,
    alerte_id    INTEGER REFERENCES alertes(id),
    raison       TEXT    NOT NULL,
    raison_en    TEXT,
    score_impact INTEGER NOT NULL DEFAULT 20,
    confirme_par INTEGER REFERENCES utilisateurs(id),
    confirme_le  TEXT    NOT NULL DEFAULT (datetime('now')),
    est_actif    INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_fp_ip    ON faux_positifs(ip_source);
CREATE INDEX IF NOT EXISTS idx_fp_rule  ON faux_positifs(rule_id);
CREATE INDEX IF NOT EXISTS idx_fp_type  ON faux_positifs(fp_type);
CREATE INDEX IF NOT EXISTS idx_fp_actif ON faux_positifs(est_actif);

-- ================================================================
-- TABLE 6 : ips_whitelist
-- ================================================================
CREATE TABLE IF NOT EXISTS ips_whitelist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT    UNIQUE NOT NULL,
    nom        TEXT    NOT NULL,
    raison     TEXT,
    ajoute_par INTEGER REFERENCES utilisateurs(id),
    ajoute_le  TEXT    NOT NULL DEFAULT (datetime('now')),
    est_actif  INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_wl_ip    ON ips_whitelist(ip);
CREATE INDEX IF NOT EXISTS idx_wl_actif ON ips_whitelist(est_actif);

-- ================================================================
-- TABLE 7 : ips_bloquees
-- ================================================================
CREATE TABLE IF NOT EXISTS ips_bloquees (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip           TEXT    UNIQUE NOT NULL,
    type_blocage TEXT    NOT NULL
                 CHECK(type_blocage IN ('Temporaire','Permanent','Auto')),
    bloque_par   INTEGER REFERENCES utilisateurs(id),
    alerte_id    INTEGER REFERENCES alertes(id),
    raison       TEXT,
    bloque_le    TEXT    NOT NULL DEFAULT (datetime('now')),
    expire_le    TEXT,
    est_actif    INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_ip_ip    ON ips_bloquees(ip);
CREATE INDEX IF NOT EXISTS idx_ip_actif ON ips_bloquees(est_actif);
CREATE INDEX IF NOT EXISTS idx_ip_type  ON ips_bloquees(type_blocage);

-- ================================================================
-- TABLE 8 : agents
-- ================================================================
CREATE TABLE IF NOT EXISTS agents (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_wazuh_id   TEXT    UNIQUE NOT NULL,
    nom              TEXT    NOT NULL,
    ip               TEXT,
    os               TEXT,
    version_wazuh    TEXT,
    statut           TEXT    NOT NULL DEFAULT 'Actif'
                     CHECK(statut IN ('Actif','Inactif','Deconnecte')),
    derniere_synchro TEXT,
    cree_le          TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_agt_statut ON agents(statut);

-- ================================================================
-- TABLE 9 : attaques_inconnues
-- ================================================================
CREATE TABLE IF NOT EXISTS attaques_inconnues (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id            INTEGER NOT NULL,
    sid_snort          INTEGER,
    description        TEXT,
    ip_source          TEXT,
    ip_destination     TEXT,
    nb_occurrences     INTEGER NOT NULL DEFAULT 1,
    derniere_fois      TEXT    NOT NULL DEFAULT (datetime('now')),
    enrichie           INTEGER NOT NULL DEFAULT 0,
    nom_propose        TEXT,
    categorie_proposee TEXT,
    gravite_proposee   INTEGER CHECK(gravite_proposee BETWEEN 1 AND 4),
    enrichie_par       INTEGER REFERENCES utilisateurs(id),
    enrichie_le        TEXT,
    cree_le            TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_inc_rule_id  ON attaques_inconnues(rule_id);
CREATE INDEX IF NOT EXISTS idx_inc_enrichie ON attaques_inconnues(enrichie);

-- ================================================================
-- TABLE 10 : actions_admin
-- ================================================================
CREATE TABLE IF NOT EXISTS actions_admin (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id  INTEGER REFERENCES utilisateurs(id),
    nom_action TEXT    NOT NULL,
    detail    TEXT,
    alerte_id INTEGER REFERENCES alertes(id),
    ip_cible  TEXT,
    resultat  TEXT    NOT NULL DEFAULT 'succes'
              CHECK(resultat IN ('succes','echec')),
    cree_le   TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_act_admin  ON actions_admin(admin_id);
CREATE INDEX IF NOT EXISTS idx_act_action ON actions_admin(nom_action);
CREATE INDEX IF NOT EXISTS idx_act_date   ON actions_admin(cree_le);

-- ================================================================
-- TABLE 11 : notifications
-- ================================================================
CREATE TABLE IF NOT EXISTS notifications (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    alerte_id INTEGER REFERENCES alertes(id),
    email_dest TEXT   NOT NULL,
    canal      TEXT   NOT NULL DEFAULT 'Email'
               CHECK(canal IN ('Email','Push','SMS')),
    statut     TEXT   NOT NULL DEFAULT 'envoye'
               CHECK(statut IN ('envoye','echec','en_attente')),
    erreur     TEXT,
    envoye_le  TEXT   NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_notif_alerte ON notifications(alerte_id);
CREATE INDEX IF NOT EXISTS idx_notif_statut ON notifications(statut);

-- ================================================================
-- TABLE 12 : rapports
-- ================================================================
CREATE TABLE IF NOT EXISTS rapports (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    rapport_type  TEXT    NOT NULL
                  CHECK(rapport_type IN ('incident','hebdomadaire','trimestriel','annuel','manuel')),
    titre         TEXT    NOT NULL,
    periode_debut TEXT,
    periode_fin   TEXT,
    chemin_pdf    TEXT,
    chemin_excel  TEXT,
    genere_par    INTEGER REFERENCES utilisateurs(id),
    alerte_id     INTEGER REFERENCES alertes(id),
    genere_le     TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_rpt_type ON rapports(rapport_type);
CREATE INDEX IF NOT EXISTS idx_rpt_date ON rapports(genere_le);

-- ================================================================
-- TABLE 13 : parametres
-- ================================================================
CREATE TABLE IF NOT EXISTS parametres (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cle         TEXT    UNIQUE NOT NULL,
    valeur      TEXT    NOT NULL,
    description TEXT,
    modifie_le  TEXT    DEFAULT (datetime('now'))
);

-- ================================================================
-- TABLE 14 : comportements (Machine Learning)
-- ================================================================
CREATE TABLE IF NOT EXISTS comportements (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_source      TEXT    NOT NULL,
    heure          INTEGER NOT NULL CHECK(heure BETWEEN 0 AND 23),
    jour_semaine   INTEGER NOT NULL CHECK(jour_semaine BETWEEN 0 AND 6),
    nb_alertes     INTEGER NOT NULL DEFAULT 0,
    nb_ports       INTEGER NOT NULL DEFAULT 0,
    nb_protocoles  INTEGER NOT NULL DEFAULT 0,
    score_anomalie REAL    DEFAULT 0.0,
    est_anomalie   INTEGER NOT NULL DEFAULT 0,
    enregistre_le  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_comp_ip   ON comportements(ip_source);
CREATE INDEX IF NOT EXISTS idx_comp_date ON comportements(enregistre_le);

-- ================================================================
-- VUES
-- ================================================================

CREATE VIEW IF NOT EXISTS v_stats_dashboard AS
SELECT
    COUNT(*)                                                    AS total_alertes,
    SUM(CASE WHEN gravite = 4 THEN 1 ELSE 0 END)              AS critique,
    SUM(CASE WHEN gravite = 3 THEN 1 ELSE 0 END)              AS haute,
    SUM(CASE WHEN gravite = 2 THEN 1 ELSE 0 END)              AS moyenne,
    SUM(CASE WHEN gravite = 1 THEN 1 ELSE 0 END)              AS faible,
    SUM(CASE WHEN statut = 'Resolu'        THEN 1 ELSE 0 END) AS resolues,
    SUM(CASE WHEN statut = 'Nouveau'       THEN 1 ELSE 0 END) AS nouvelles,
    SUM(CASE WHEN est_faux_positif_predit = 1 THEN 1 ELSE 0 END) AS fp_predits,
    SUM(CASE WHEN est_honeypot = 1         THEN 1 ELSE 0 END) AS honeypot,
    SUM(CASE WHEN date(timestamp_alerte) = date('now') THEN 1 ELSE 0 END) AS aujourd_hui
FROM alertes;

CREATE VIEW IF NOT EXISTS v_alertes_detail AS
SELECT
    a.id, a.timestamp_alerte, a.nom_attaque, a.nom_attaque_en,
    a.categorie, a.gravite, a.gravite_label,
    a.ip_source, a.ip_destination, a.port_destination,
    a.pays_source, a.mitre_id, a.mitre_tactique, a.mitre_technique,
    a.actions_fr, a.actions_en,
    a.score_confiance, a.est_faux_positif_predit, a.raison_fp_predit,
    a.statut, a.est_honeypot, a.est_correllee, a.est_bloquee_auto,
    a.machine_nom, u.username AS resolu_par_username
FROM alertes a
LEFT JOIN utilisateurs u ON a.resolu_par = u.id;

-- ================================================================
-- DONNEES INITIALES — Parametres systeme
-- ================================================================
INSERT OR IGNORE INTO parametres (cle, valeur, description) VALUES
    ('organisation_nom',       'Mon Entreprise',  'Nom de l organisation'),
    ('polling_interval',       '10',              'Intervalle polling en secondes'),
    ('correlation_window',     '60',              'Fenetre correlation en secondes'),
    ('correlation_threshold',  '3',               'Seuil de correlation'),
    ('active_response_delay',  '300',             'Delai active response en secondes'),
    ('honeypot_enabled',       '1',               'Honeypot actif'),
    ('honeypot_ssh_port',      '2222',            'Port SSH honeypot'),
    ('honeypot_http_port',     '8888',            'Port HTTP honeypot'),
    ('honeypot_mysql_port',    '3307',            'Port MySQL honeypot'),
    ('ml_apprentissage_jours', '7',               'Jours avant activation ML'),
    ('smtp_host',              'smtp.gmail.com',  'Serveur SMTP'),
    ('smtp_port',              '587',             'Port SMTP'),
    ('smtp_user',              '',                'Email SMTP'),
    ('smtp_password',          '',                'Mot de passe SMTP'),
    ('fp_seuil_score',         '40',              'Score en dessous duquel = faux positif probable'),
    ('fp_nb_occurrences_seuil','3',               'Nb fois IP marquee fp pour auto-detection'),
    ('pwd_expire_jours',       '90',              'Expiration MDP en jours'),
    ('pwd_historique',         '5',               'Nb anciens MDP conserves'),
    ('pwd_tentatives_max',     '5',               'Tentatives avant blocage'),
    ('pwd_blocage_minutes',    '30',              'Duree blocage en minutes'),
    ('langue_defaut',          'fr',              'Langue par defaut'),
