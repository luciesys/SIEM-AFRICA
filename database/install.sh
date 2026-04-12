#!/bin/bash
# ================================================================
#  SIEM Africa — Module 2 : Base de donnees SQLite
#  Fichier  : database/install.sh
#  Version  : 2.2 — Refonte complete
#  Usage    : sudo bash install.sh
#
#  Corrections v2.2 :
#  - Groupe siem-africa verifie (cree par Module 1)
#  - Permissions SQLite correctes : siem-africa:siem-africa + chmod 664
#  - Sans set -e
#  - Username comme login (plus email)
#  - Table emails_alertes : plusieurs emails de notification
#  - Compte admin genere automatiquement
#  - Politiques securite username et mot de passe
# ================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

LOG_FILE="/var/log/siem-africa-install.log"
DB_PATH="/opt/siem-africa/siem_africa.db"
ENV_FILE="/opt/siem-africa/.env"
CRED_FILE="/opt/siem-africa/credentials.txt"
OPT_DIR="/opt/siem-africa"
GROUPE="siem-africa"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Infos collectees pendant l'installation
ORG_NOM=""
EMAIL_PRINCIPAL=""
ADMIN_USERNAME=""
ADMIN_PASSWORD=""

log()       { echo -e "$1" | tee -a "$LOG_FILE"; }
log_ok()    { log "${GREEN}[OK]${NC} $1"; }
log_info()  { log "${CYAN}[INFO]${NC} $1"; }
log_warn()  { log "${YELLOW}[ATTENTION]${NC} $1"; }
log_etape() { log "\n${BLUE}━━━ ETAPE $1 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

quitter() {
    echo -e "\n${RED}ARRETE : $1${NC}"
    echo "Journal : $LOG_FILE"
    exit 1
}

show_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║       SIEM Africa — Module 2 v2.2                   ║"
    echo "  ║       Base de donnees SQLite                        ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ── Desinstallation si deja installe ─────────────────────────────
desinstaller_si_present() {
    [ ! -f "$DB_PATH" ] && return 0
    echo -e "${YELLOW}  Installation precedente detectee — suppression...${NC}"
    rm -f "$DB_PATH" "${DB_PATH}-wal" "${DB_PATH}-shm"
    log_ok "Ancienne base supprimee"
    sleep 1
}

# ================================================================
# ETAPE 1 : Verifications
# ================================================================
check_all() {
    log_etape "1/5" "VERIFICATIONS"

    [ "$EUID" -ne 0 ] && quitter "sudo requis"
    log_ok "Root confirme"

    # Module 1 requis
    [ ! -f "$ENV_FILE" ] && quitter "Module 1 non installe — lancez installation/install.sh d'abord"
    log_ok "Module 1 detecte"

    # Groupe siem-africa requis
    getent group "$GROUPE" > /dev/null 2>&1 || \
        quitter "Groupe $GROUPE non trouve — Module 1 requis"
    log_ok "Groupe $GROUPE present"

    # sqlite3
    if ! command -v sqlite3 > /dev/null 2>&1; then
        log_info "Installation sqlite3..."
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sqlite3 > /dev/null 2>&1
    fi
    command -v sqlite3 > /dev/null 2>&1 || quitter "sqlite3 non installe"
    log_ok "sqlite3 : $(sqlite3 --version | awk '{print $1}')"

    # schema.sql et attacks.sql
    [ ! -f "${SCRIPT_DIR}/schema.sql" ]  && quitter "schema.sql introuvable dans $SCRIPT_DIR"
    [ ! -f "${SCRIPT_DIR}/attacks.sql" ] && quitter "attacks.sql introuvable dans $SCRIPT_DIR"
    log_ok "Fichiers SQL presents"
}

# ================================================================
# ETAPE 2 : Configuration organisation
# ================================================================
collect_config() {
    log_etape "2/5" "CONFIGURATION ORGANISATION"
    echo ""

    # Nom de l'organisation
    echo -n "  Nom de l'organisation : "
    read ORG_NOM
    [ -z "$ORG_NOM" ] && ORG_NOM="Mon Entreprise"
    log_ok "Organisation : $ORG_NOM"

    # Email principal (obligatoire)
    while true; do
        echo -n "  Email principal de l'entreprise (pour les alertes) : "
        read EMAIL_PRINCIPAL
        EMAIL_PRINCIPAL=$(echo "$EMAIL_PRINCIPAL" | tr '[:upper:]' '[:lower:]' | xargs)
        echo "$EMAIL_PRINCIPAL" | grep -qE '^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$' && break
        echo -e "  ${RED}Email invalide. Exemple : securite@entreprise.cm${NC}"
    done
    log_ok "Email principal : $EMAIL_PRINCIPAL"

    # Emails supplementaires
    echo ""
    log_info "Vous pouvez ajouter d'autres emails pour recevoir les alertes."
    EMAILS_SUPP=()
    while true; do
        echo -n "  Ajouter un autre email ? (oui/non) : "
        read REPONSE
        [ "$REPONSE" != "oui" ] && break
        echo -n "  Nouvel email : "
        read EMAIL_SUPP
        EMAIL_SUPP=$(echo "$EMAIL_SUPP" | tr '[:upper:]' '[:lower:]' | xargs)
        if echo "$EMAIL_SUPP" | grep -qE '^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'; then
            EMAILS_SUPP+=("$EMAIL_SUPP")
            log_ok "Email ajoute : $EMAIL_SUPP"
        else
            echo -e "  ${RED}Email invalide — ignore${NC}"
        fi
    done
}

# ================================================================
# ETAPE 3 : Creation base de donnees
# ================================================================
create_database() {
    log_etape "3/5" "CREATION BASE DE DONNEES"

    # Creer la base
    sqlite3 "$DB_PATH" < "${SCRIPT_DIR}/schema.sql" 2>/dev/null
    if [ ! -f "$DB_PATH" ]; then
        quitter "Impossible de creer la base SQLite"
    fi
    log_ok "Schema SQLite cree (14 tables + 2 vues)"

    # Charger les signatures
    log_info "Chargement des signatures d'attaques..."
    sqlite3 "$DB_PATH" < "${SCRIPT_DIR}/attacks.sql" 2>/dev/null
    NB_SIG=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM attaques;" 2>/dev/null || echo "0")
    log_ok "Signatures chargees : $NB_SIG"

    # Mettre a jour le parametre organisation
    sqlite3 "$DB_PATH" \
        "UPDATE parametres SET valeur='${ORG_NOM}' WHERE cle='organisation_nom';" 2>/dev/null || true

    # Inserer l'email principal
    sqlite3 "$DB_PATH" "
        INSERT OR IGNORE INTO emails_alertes (email, nom, est_actif, est_principal)
        VALUES ('${EMAIL_PRINCIPAL}', 'Email principal', 1, 1);
    " 2>/dev/null
    log_ok "Email principal enregistre : $EMAIL_PRINCIPAL"

    # Inserer les emails supplementaires
    for email in "${EMAILS_SUPP[@]}"; do
        sqlite3 "$DB_PATH" "
            INSERT OR IGNORE INTO emails_alertes (email, nom, est_actif, est_principal)
            VALUES ('${email}', 'Email supplementaire', 1, 0);
        " 2>/dev/null
        log_ok "Email supplementaire enregistre : $email"
    done
}

# ================================================================
# ETAPE 4 : Creation compte administrateur
# ================================================================
create_admin() {
    log_etape "4/5" "CREATION COMPTE ADMINISTRATEUR"
    echo ""

    # Generer username et mot de passe automatiquement
    ADMIN_USERNAME="siem-$(cat /dev/urandom | tr -dc 'a-z0-9' | head -c 6)"
    ADMIN_PASSWORD=$(python3 -c "
import secrets, string
chars = string.ascii_uppercase + string.ascii_lowercase + string.digits + '@#\$%&*'
pwd = [
    secrets.choice(string.ascii_uppercase),
    secrets.choice(string.ascii_lowercase),
    secrets.choice(string.digits),
    secrets.choice('@#\$%&*'),
]
pwd += [secrets.choice(chars) for _ in range(8)]
import random; random.shuffle(pwd)
print(''.join(pwd))
")

    # Hasher le mot de passe
    HASH=$(python3 -c "
import sys
try:
    import bcrypt
    h = bcrypt.hashpw(sys.argv[1].encode(), bcrypt.gensalt(rounds=12)).decode()
    print(h)
except ImportError:
    import hashlib
    print(hashlib.sha256(sys.argv[1].encode()).hexdigest())
" "$ADMIN_PASSWORD" 2>/dev/null)

    if [ -z "$HASH" ]; then
        quitter "Impossible de hasher le mot de passe"
    fi

    # Inserer l'admin dans la base
    sqlite3 "$DB_PATH" "
        INSERT INTO utilisateurs
            (username, password_hash, role, email_alertes, langue,
             est_actif, premiere_connexion,
             pwd_expire_le, pwd_change_le, historique_pwd,
             tentatives_echec, organisation, cree_le)
        VALUES
            ('${ADMIN_USERNAME}', '${HASH}', 'admin_securite',
             '${EMAIL_PRINCIPAL}', 'fr',
             1, 1,
             datetime('now', '+90 days'), datetime('now'), '[]',
             0, '${ORG_NOM}', datetime('now'));
    " 2>/dev/null

    NB=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM utilisateurs;" 2>/dev/null || echo "0")
    [ "${NB:-0}" -gt 0 ] && log_ok "Compte admin cree" || quitter "Echec creation compte admin"

    # Afficher les identifiants UNE SEULE FOIS
    echo ""
    echo -e "${YELLOW}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║   IDENTIFIANTS DE PREMIERE CONNEXION               ║"
    echo "  ║   Notez-les maintenant — affiches UNE SEULE FOIS   ║"
    echo "  ╠══════════════════════════════════════════════════════╣"
    echo -e "  ║   Username : ${GREEN}${ADMIN_USERNAME}${YELLOW}$(printf '%*s' $((40-${#ADMIN_USERNAME})) '')║"
    echo -e "  ║   Password : ${GREEN}${ADMIN_PASSWORD}${YELLOW}$(printf '%*s' $((40-${#ADMIN_PASSWORD})) '')║"
    echo "  ╠══════════════════════════════════════════════════════╣"
    echo "  ║   VOUS DEVREZ LES CHANGER A LA PREMIERE CONNEXION  ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ================================================================
# ETAPE 5 : Permissions et finalisation
# ================================================================
set_permissions() {
    log_etape "5/5" "PERMISSIONS ET FINALISATION"

    # Permissions SQLite — CORRECTION CLES
    # Proprietaire : siem-africa:siem-africa
    # chmod 664 = groupe peut lire ET ecrire
    # C'est ce qui resout le probleme "readonly database"
    chown "${GROUPE}:${GROUPE}" "$DB_PATH"
    chmod 664 "$DB_PATH"

    # Fichiers WAL aussi
    [ -f "${DB_PATH}-wal" ] && chown "${GROUPE}:${GROUPE}" "${DB_PATH}-wal" && chmod 664 "${DB_PATH}-wal"
    [ -f "${DB_PATH}-shm" ] && chown "${GROUPE}:${GROUPE}" "${DB_PATH}-shm" && chmod 664 "${DB_PATH}-shm"

    # Dossier parent
    chown "${GROUPE}:${GROUPE}" "$OPT_DIR"
    chmod 775 "$OPT_DIR"

    log_ok "Permissions SQLite : ${GROUPE}:${GROUPE} chmod 664"
    log_ok "Permissions dossier : ${GROUPE}:${GROUPE} chmod 775"

    # Mettre a jour .env
    grep -q "^DB_PATH=" "$ENV_FILE" && \
        sed -i "s|^DB_PATH=.*|DB_PATH=${DB_PATH}|" "$ENV_FILE" || \
        echo "DB_PATH=${DB_PATH}" >> "$ENV_FILE"
    grep -q "^ORG_NOM=" "$ENV_FILE" && \
        sed -i "s|^ORG_NOM=.*|ORG_NOM=${ORG_NOM}|" "$ENV_FILE" || \
        echo "ORG_NOM=${ORG_NOM}" >> "$ENV_FILE"
    grep -q "^ALERT_EMAIL=" "$ENV_FILE" && \
        sed -i "s|^ALERT_EMAIL=.*|ALERT_EMAIL=${EMAIL_PRINCIPAL}|" "$ENV_FILE" || \
        echo "ALERT_EMAIL=${EMAIL_PRINCIPAL}" >> "$ENV_FILE"
    log_ok ".env mis a jour"

    # Mettre a jour credentials.txt
    NB_EMAILS=$((1 + ${#EMAILS_SUPP[@]}))
    cat >> "$CRED_FILE" << CREDS

── MODULE 2 — BASE DE DONNEES SQLite (v2.2) ──────────────────
  Installe le   : $(date '+%d/%m/%Y a %H:%M')

── BASE DE DONNEES ────────────────────────────────────────────
  Chemin        : ${DB_PATH}
  Tables        : 14 + 2 vues
  Signatures    : $(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM attaques;" 2>/dev/null) attaques
  Permissions   : ${GROUPE}:${GROUPE} chmod 664

── ORGANISATION ───────────────────────────────────────────────
  Nom           : ${ORG_NOM}
  Emails alertes: ${NB_EMAILS} email(s) configure(s)
  Email principal: ${EMAIL_PRINCIPAL}

── COMPTE ADMINISTRATEUR ─────────────────────────────────────
  Username      : ${ADMIN_USERNAME}
  Password      : ${ADMIN_PASSWORD}
  Role          : admin_securite
  IMPORTANT     : Changer username et password a la 1ere connexion

── POLITIQUES DE SECURITE ────────────────────────────────────
  Username      : 6-20 chars, lettres/chiffres/-/_  uniquement
  Mot de passe  : 12+ chars, maj+min+chiffre+special
  Expiration    : 90 jours
  Blocage       : 5 echecs = 30 min de blocage
  Historique    : 5 derniers MDP conserves

── PROCHAINE ETAPE ───────────────────────────────────────────
  Module 3 — Agent intelligent
  curl -sL https://raw.githubusercontent.com/luciesys/SIEM-AFRICA/main/agent/agent.py \\
    -o /tmp/agent.py
  curl -sL https://raw.githubusercontent.com/luciesys/SIEM-AFRICA/main/agent/install.sh \\
    -o /tmp/install_agent.sh
  cd /tmp && sudo bash install_agent.sh

CREDS

    chmod 640 "$CRED_FILE"
    log_ok "credentials.txt mis a jour"

    # Resume
    _show_summary
}

_show_summary() {
    SERVER_IP=$(grep "^SERVER_IP=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || hostname -I | awk '{print $1}')
    NB_SIG=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM attaques;" 2>/dev/null || echo "0")

    echo ""
    echo -e "${GREEN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║     MODULE 2 — INSTALLATION TERMINEE                ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${CYAN}── BASE DE DONNEES ──────────────────────────────────${NC}"
    echo -e "  ${GREEN}[OK]${NC} $DB_PATH"
    echo -e "  ${GREEN}[OK]${NC} $NB_SIG signatures chargees"
    echo -e "  ${GREEN}[OK]${NC} Permissions : ${GROUPE}:${GROUPE} 664"
    echo ""
    echo -e "${CYAN}── COMPTE ADMIN ─────────────────────────────────────${NC}"
    echo -e "  Username : ${GREEN}${ADMIN_USERNAME}${NC}"
    echo -e "  ${YELLOW}Changer a la premiere connexion !${NC}"
    echo ""
    echo -e "${CYAN}── EMAILS ALERTES ───────────────────────────────────${NC}"
    sqlite3 "$DB_PATH" "SELECT '  [OK] ' || email FROM emails_alertes;" 2>/dev/null
    echo ""
}

# ================================================================
# MAIN
# ================================================================
main() {
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    echo "=== SIEM Africa Module 2 v2.2 - $(date) ===" >> "$LOG_FILE"

    show_banner
    desinstaller_si_present
    check_all
    collect_config
    create_database
    create_admin
    set_permissions

    log_info "Module 2 termine — $(date)"
}

main "$@"
