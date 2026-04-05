-- ================================================================
--  SIEM Africa — Base de données SQLite
--  Fichier  : 2-database/schema.sql
--  Version  : 1.0
--  Contenu  : 10 tables + 2 vues + index
--  Usage    : sqlite3 siem_africa.db < schema.sql
-- ================================================================

PRAGMA foreign_keys = ON;
PRAGMA journal_mode  = WAL;
PRAGMA synchronous   = NORMAL;

-- ================================================================
-- TABLE 1 : utilisateurs
-- Comptes admin_securite et dirigeant
-- ================================================================
CREATE TABLE IF NOT EXISTS utilisateurs (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    username           TEXT    UNIQUE NOT NULL,
    email              TEXT    UNIQUE NOT NULL,
    password_hash      TEXT    NOT NULL,
    role               TEXT    NOT NULL DEFAULT 'admin_securite'
                       CHECK(role IN ('admin_securite','dirigeant')),
    langue             TEXT    NOT NULL DEFAULT 'fr'
                       CHECK(langue IN ('fr','en')),
    premiere_connexion INTEGER NOT NULL DEFAULT 1,
    pwd_change_le      TEXT    DEFAULT (datetime('now')),
    pwd_expire_le      TEXT    DEFAULT (datetime('now','+90 days')),
    historique_pwd     TEXT    DEFAULT '[]',
    tentatives_echec   INTEGER NOT NULL DEFAULT 0,
    bloque_jusqua      TEXT,
    derniere_connexion TEXT,
    cree_le            TEXT    DEFAULT (datetime('now')),
    modifie_le         TEXT    DEFAULT (datetime('now'))
);

-- ================================================================
-- TABLE 2 : attaques
-- Référentiel des signatures d'attaques contextualisées Afrique
-- ================================================================
CREATE TABLE IF NOT EXISTS attaques (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id            INTEGER NOT NULL,
    sid_snort          INTEGER,
    nom                TEXT    NOT NULL,
    nom_en             TEXT,
    categorie          TEXT    NOT NULL,
    description        TEXT    NOT NULL,
    description_en     TEXT,
    gravite            INTEGER NOT NULL CHECK(gravite BETWEEN 1 AND 4),
    action_recommandee TEXT    NOT NULL,
    contre_mesure      TEXT,
    faux_positif       INTEGER NOT NULL DEFAULT 0,
    source             TEXT    NOT NULL DEFAULT 'Snort'
                       CHECK(source IN ('Snort','Wazuh','Custom')),
    protocole          TEXT,
    port_cible         INTEGER,
    cve                TEXT,
    frequence_afrique  TEXT    NOT NULL DEFAULT 'Commune'
                       CHECK(frequence_afrique IN ('Très commune','Commune','Rare')),
    cree_le            TEXT    DEFAULT (datetime('now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_att_rule_sid
    ON attaques(rule_id, COALESCE(sid_snort, 0));
CREATE INDEX IF NOT EXISTS idx_att_rule_id    ON attaques(rule_id);
CREATE INDEX IF NOT EXISTS idx_att_sid        ON attaques(sid_snort);
CREATE INDEX IF NOT EXISTS idx_att_gravite    ON attaques(gravite);
CREATE INDEX IF NOT EXISTS idx_att_categorie  ON attaques(categorie);
CREATE INDEX IF NOT EXISTS idx_att_faux_pos   ON attaques(faux_positif);

-- ================================================================
-- TABLE 3 : alertes
-- Alertes reçues de Wazuh et enrichies par l'agent
-- ================================================================
CREATE TABLE IF NOT EXISTS alertes (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_alerte   TEXT    NOT NULL DEFAULT (datetime('now')),
    rule_id            INTEGER NOT NULL,
    sid_snort          INTEGER,
    attaque_id         INTEGER REFERENCES attaques(id),
    nom_attaque        TEXT,
    nom_attaque_en     TEXT,
    categorie          TEXT,
    gravite            INTEGER CHECK(gravite BETWEEN 1 AND 4),
    gravite_label      TEXT,
    action_recommandee TEXT,
    contre_mesure      TEXT,
    ip_source          TEXT,
    ip_destination     TEXT,
    port_source        INTEGER,
    port_destination   INTEGER,
    protocole          TEXT,
    pays_source        TEXT,
    ville_source       TEXT,
    agent_id           TEXT,
    machine_nom        TEXT,
    machine_os         TEXT,
    est_inconnue       INTEGER NOT NULL DEFAULT 0,
    description_wazuh  TEXT,
    est_correllee      INTEGER NOT NULL DEFAULT 0,
    correlation_count  INTEGER NOT NULL DEFAULT 1,
    statut             TEXT    NOT NULL DEFAULT 'Nouveau'
                       CHECK(statut IN (
                           'Nouveau','En cours','Résolu',
                           'Acquitté','Faux positif'
                       )),
    resolu_par         INTEGER REFERENCES utilisateurs(id),
    resolu_le          TEXT,
    commentaire        TEXT,
    rapport_genere     INTEGER NOT NULL DEFAULT 0,
    cree_le            TEXT    DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_al_timestamp ON alertes(timestamp_alerte DESC);
CREATE INDEX IF NOT EXISTS idx_al_ip        ON alertes(ip_source);
CREATE INDEX IF NOT EXISTS idx_al_gravite   ON alertes(gravite);
CREATE INDEX IF NOT EXISTS idx_al_statut    ON alertes(statut);
CREATE INDEX IF NOT EXISTS idx_al_rule_id   ON alertes(rule_id);
CREATE INDEX IF NOT EXISTS idx_al_inconnue  ON alertes(est_inconnue);

-- ================================================================
-- TABLE 4 : actions_admin
-- Journal complet horodaté de toutes les actions
-- ================================================================
CREATE TABLE IF NOT EXISTS actions_admin (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_action TEXT    NOT NULL DEFAULT (datetime('now')),
    admin_id         INTEGER REFERENCES utilisateurs(id),
    admin_username   TEXT    NOT NULL,
    alerte_id        INTEGER REFERENCES alertes(id),
    type_action      TEXT    NOT NULL
                     CHECK(type_action IN (
                         'Bloquer IP temporaire',
                         'Bloquer IP permanent',
                         'Débloquer IP',
                         'Whitelist IP',
                         'Acquitter alerte',
                         'Marquer faux positif',
                         'Isoler machine',
                         'Redémarrer service',
                         'Générer rapport',
                         'Changement mot de passe',
                         'Ajout attaque inconnue'
                     )),
    ip_concernee     TEXT,
    duree_minutes    INTEGER,
    expire_le        TEXT,
    commande_exec    TEXT,
    resultat         TEXT    NOT NULL DEFAULT 'Succès'
                     CHECK(resultat IN ('Succès','Échec','Annulé')),
    canal            TEXT    NOT NULL DEFAULT 'Dashboard'
                     CHECK(canal IN ('Dashboard','PWA Mobile','API')),
    commentaire      TEXT
);

CREATE INDEX IF NOT EXISTS idx_act_ts    ON actions_admin(timestamp_action DESC);
CREATE INDEX IF NOT EXISTS idx_act_admin ON actions_admin(admin_id);
CREATE INDEX IF NOT EXISTS idx_act_ip    ON actions_admin(ip_concernee);

-- ================================================================
-- TABLE 5 : ips_bloquees
-- ================================================================
CREATE TABLE IF NOT EXISTS ips_bloquees (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip           TEXT    UNIQUE NOT NULL,
    type_blocage TEXT    NOT NULL
                 CHECK(type_blocage IN ('Temporaire','Permanent','Whitelist')),
    bloque_par   INTEGER REFERENCES utilisateurs(id),
    bloque_le    TEXT    DEFAULT (datetime('now')),
    expire_le    TEXT,
    raison       TEXT,
    alerte_id    INTEGER REFERENCES alertes(id),
    est_actif    INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_ip_ip    ON ips_bloquees(ip);
CREATE INDEX IF NOT EXISTS idx_ip_actif ON ips_bloquees(est_actif);
CREATE INDEX IF NOT EXISTS idx_ip_type  ON ips_bloquees(type_blocage);

-- ================================================================
-- TABLE 6 : faux_positifs
-- ================================================================
CREATE TABLE IF NOT EXISTS faux_positifs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_source    TEXT,
    rule_id      INTEGER,
    sid_snort    INTEGER,
    categorie    TEXT,
    confirme_par INTEGER REFERENCES utilisateurs(id),
    confirme_le  TEXT    DEFAULT (datetime('now')),
    commentaire  TEXT
);

-- ================================================================
-- TABLE 7 : attaques_inconnues
-- ================================================================
CREATE TABLE IF NOT EXISTS attaques_inconnues (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id            INTEGER NOT NULL UNIQUE,
    description_wazuh  TEXT,
    gravite_wazuh      INTEGER,
    nb_occurrences     INTEGER NOT NULL DEFAULT 1,
    premiere_vue       TEXT    DEFAULT (datetime('now')),
    derniere_vue       TEXT    DEFAULT (datetime('now')),
    enrichie           INTEGER NOT NULL DEFAULT 0,
    nom_manuel         TEXT,
    categorie_manuelle TEXT,
    gravite_manuelle   INTEGER CHECK(gravite_manuelle BETWEEN 1 AND 4),
    action_manuelle    TEXT,
    enrichie_par       INTEGER REFERENCES utilisateurs(id),
    enrichie_le        TEXT
);

-- ================================================================
-- TABLE 8 : agents
-- ================================================================
CREATE TABLE IF NOT EXISTS agents (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_wazuh_id TEXT    UNIQUE NOT NULL,
    nom            TEXT    NOT NULL,
    ip             TEXT,
    os             TEXT,
    statut         TEXT    NOT NULL DEFAULT 'Actif'
                   CHECK(statut IN ('Actif','Inactif','Alerte','Isolé')),
    derniere_vue   TEXT,
    version_wazuh  TEXT,
    cree_le        TEXT    DEFAULT (datetime('now'))
);

-- ================================================================
-- TABLE 9 : rapports
-- ================================================================
CREATE TABLE IF NOT EXISTS rapports (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    type_rapport  TEXT    NOT NULL
                  CHECK(type_rapport IN (
                      'Incident','Hebdomadaire',
                      'Trimestriel','Annuel','Manuel'
                  )),
    titre         TEXT,
    periode_debut TEXT,
    periode_fin   TEXT,
    alerte_id     INTEGER REFERENCES alertes(id),
    genere_par    INTEGER REFERENCES utilisateurs(id),
    genere_le     TEXT    DEFAULT (datetime('now')),
    fichier_pdf   TEXT,
    fichier_xlsx  TEXT,
    langue        TEXT    NOT NULL DEFAULT 'fr'
                  CHECK(langue IN ('fr','en')),
    nb_alertes    INTEGER NOT NULL DEFAULT 0,
    nb_critiques  INTEGER NOT NULL DEFAULT 0,
    nb_resolues   INTEGER NOT NULL DEFAULT 0,
    statut        TEXT    NOT NULL DEFAULT 'Généré'
);

-- ================================================================
-- TABLE 10 : parametres
-- ================================================================
CREATE TABLE IF NOT EXISTS parametres (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cle         TEXT    UNIQUE NOT NULL,
    valeur      TEXT    NOT NULL,
    description TEXT,
    modifie_le  TEXT    DEFAULT (datetime('now'))
);

-- Valeurs par défaut
INSERT OR IGNORE INTO parametres (cle, valeur, description) VALUES
-- Agent
('polling_interval',    '10',            'Interrogation API Wazuh toutes les X secondes'),
('correlation_window',  '60',            'Fenêtre corrélation en secondes'),
('correlation_seuil',   '3',             'Nb alertes même IP pour déclencher corrélation'),
-- Sécurité
('pwd_duree_jours',     '90',            'Durée validité mot de passe en jours'),
('pwd_alerte_jours',    '15',            'Alerter X jours avant expiration'),
('max_tentatives',      '5',             'Max tentatives login avant blocage compte'),
('blocage_minutes',     '30',            'Durée blocage compte en minutes'),
('session_timeout',     '120',           'Expiration session inactive en minutes'),
-- Rapports
('rapport_hebdo_heure', '08:00',         'Heure génération rapport hebdomadaire'),
('rapport_hebdo_jour',  '0',             '0=Lundi ... 6=Dimanche'),
-- Interface
('langue_defaut',       'fr',            'Langue par défaut fr ou en'),
-- SMTP
('smtp_host',           'smtp.gmail.com','Serveur SMTP'),
('smtp_port',           '587',           'Port SMTP 587=TLS 465=SSL'),
('smtp_user',           '',              'Adresse email expéditeur'),
('smtp_password',       '',              'Mot de passe SMTP'),
('alert_email',         '',              'Email destinataire des alertes critiques'),
-- Wazuh
('wazuh_host',          '127.0.0.1',     'IP serveur Wazuh'),
('wazuh_port',          '55000',         'Port API REST Wazuh'),
('wazuh_user',          'wazuh-api',     'Utilisateur API Wazuh'),
('wazuh_password',      '',              'Mot de passe API Wazuh'),
-- Snort
('snort_log',           '/var/log/snort/alert.json', 'Chemin fichier JSON Snort'),
-- Cloudflare
('cloudflare_token',    '',              'Token Cloudflare Tunnel'),
('cloudflare_url',      '',              'URL publique Cloudflare');

-- ================================================================
-- VUE 1 : alertes enrichies pour le dashboard
-- ================================================================
CREATE VIEW IF NOT EXISTS v_alertes_recentes AS
SELECT
    a.id,
    a.timestamp_alerte,
    a.rule_id,
    a.nom_attaque,
    a.nom_attaque_en,
    a.categorie,
    a.gravite,
    CASE a.gravite
        WHEN 4 THEN 'Critique'
        WHEN 3 THEN 'Haute'
        WHEN 2 THEN 'Moyenne'
        WHEN 1 THEN 'Faible'
        ELSE    'Inconnue'
    END AS gravite_label,
    a.ip_source,
    a.pays_source,
    a.ville_source,
    a.machine_nom,
    a.machine_os,
    a.statut,
    a.est_inconnue,
    a.est_correllee,
    a.action_recommandee,
    a.contre_mesure,
    a.resolu_le,
    a.commentaire,
    u.username AS resolu_par_username
FROM alertes a
LEFT JOIN utilisateurs u ON a.resolu_par = u.id
ORDER BY a.timestamp_alerte DESC;

-- ================================================================
-- VUE 2 : statistiques dashboard en une seule requête
-- ================================================================
CREATE VIEW IF NOT EXISTS v_stats_dashboard AS
SELECT
    COUNT(CASE WHEN gravite=4 AND statut='Nouveau'                     THEN 1 END) AS critiques_actives,
    COUNT(CASE WHEN gravite=3 AND statut='Nouveau'                     THEN 1 END) AS hautes_actives,
    COUNT(CASE WHEN gravite=2 AND statut='Nouveau'                     THEN 1 END) AS moyennes_actives,
    COUNT(CASE WHEN gravite=1 AND statut='Nouveau'                     THEN 1 END) AS faibles_actives,
    COUNT(CASE WHEN date(timestamp_alerte)=date('now')                 THEN 1 END) AS alertes_auj,
    COUNT(CASE WHEN timestamp_alerte>=datetime('now','-7 days')        THEN 1 END) AS alertes_7j,
    COUNT(CASE WHEN timestamp_alerte>=datetime('now','-30 days')       THEN 1 END) AS alertes_30j,
    COUNT(CASE WHEN statut IN ('Résolu','Acquitté')                    THEN 1 END) AS alertes_resolues,
    COUNT(CASE WHEN statut='Faux positif'                              THEN 1 END) AS faux_positifs,
    COUNT(CASE WHEN est_inconnue=1                                     THEN 1 END) AS inconnues,
    COUNT(CASE WHEN est_correllee=1                                    THEN 1 END) AS correlees,
    COUNT(*)                                                                        AS total_alertes
FROM alertes;
