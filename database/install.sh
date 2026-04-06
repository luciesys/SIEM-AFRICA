#!/bin/bash
# ================================================================
#  SIEM Africa — Module 2 : Base de données SQLite
#  Fichier  : 2-database/install.sh
#  Usage    : sudo bash install.sh
#  Version  : 1.0
# ================================================================

set -e

# ================================================================
# COULEURS
# ================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ================================================================
# VARIABLES
# ================================================================
LOG_FILE="/var/log/siem-africa-install.log"
DB_PATH="/opt/siem-africa/siem_africa.db"
CRED_FILE="/opt/siem-africa/credentials.txt"
ENV_FILE="/opt/siem-africa/.env"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_DB="siem-db"

# ================================================================
# FONCTIONS
# ================================================================
log()        { echo -e "$1" | tee -a "$LOG_FILE"; }
log_ok()     { log "${GREEN}[OK]${NC} $1"; }
log_info()   { log "${CYAN}[INFO]${NC} $1"; }
log_warn()   { log "${YELLOW}[ATTENTION]${NC} $1"; }
log_etape()  { log "${BLUE}[ETAPE $1]${NC} $2"; }

quitter() {
    echo ""
    echo -e "${RED}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║     INSTALLATION ARRETEE                             ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════╝${NC}"
    echo -e "  Raison  : $1"
    echo -e "  Journal : $LOG_FILE"
    echo ""
    exit 1
}

show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║       SIEM Africa — Module 2                        ║"
    echo "║       Base de données SQLite                        ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
}

# ================================================================
# VERIFICATIONS
# ================================================================
check_root() {
    if [ "$EUID" -ne 0 ]; then
        quitter "Lancez avec : sudo bash install.sh"
    fi
    log_ok "Execution en tant que root"
}

check_module1() {
    log_info "Verification que le module 1 est installe..."

    if [ ! -d "/var/ossec" ]; then
        quitter "Wazuh non detecte. Lancez d abord le module 1."
    fi

    if ! command -v snort > /dev/null 2>&1; then
        quitter "Snort non detecte. Lancez d abord le module 1."
    fi

    log_ok "Module 1 detecte (Snort + Wazuh)"
}

check_files() {
    log_info "Verification des fichiers SQL..."

    if [ ! -f "${SCRIPT_DIR}/schema.sql" ]; then
        quitter "schema.sql introuvable dans ${SCRIPT_DIR}"
    fi

    if [ ! -f "${SCRIPT_DIR}/attacks.sql" ]; then
        quitter "attacks.sql introuvable dans ${SCRIPT_DIR}"
    fi

    log_ok "Fichiers SQL trouves : schema.sql + attacks.sql"
}

# ================================================================
# ETAPE 1 — UTILISATEUR SYSTEME
# ================================================================
create_user() {
    log_etape "1/5" "CREATION UTILISATEUR SYSTEME"

    if id "$USER_DB" > /dev/null 2>&1; then
        log_info "Utilisateur ${USER_DB} existe deja"
    else
        useradd --system \
                --no-create-home \
                --shell /sbin/nologin \
                --comment "SIEM Africa - Base de donnees" \
                "$USER_DB"
        log_ok "Utilisateur ${USER_DB} cree"
    fi

    echo ""
    echo -e "  ${GREEN}[OK]${NC} ${USER_DB}"
    echo -e "       Role  : Base de donnees SQLite"
    echo -e "       Shell : /sbin/nologin (pas de connexion directe)"
    echo ""
}

# ================================================================
# ETAPE 2 — DEPENDANCES
# ================================================================
install_deps() {
    log_etape "2/5" "INSTALLATION DES DEPENDANCES"

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq

    # SQLite3
    if command -v sqlite3 > /dev/null 2>&1; then
        log_ok "SQLite3 deja installe : $(sqlite3 --version | awk '{print $1}')"
    else
        apt-get install -y -qq sqlite3
        log_ok "SQLite3 installe : $(sqlite3 --version | awk '{print $1}')"
    fi

    # Python3
    apt-get install -y -qq python3 python3-pip > /dev/null 2>&1
    log_ok "Python3 pret"

    # bcrypt
    if python3 -c "import bcrypt" > /dev/null 2>&1; then
        log_ok "bcrypt deja installe"
    else
        pip3 install bcrypt --quiet --break-system-packages 2>/dev/null || \
        pip3 install bcrypt --quiet
        log_ok "bcrypt installe"
    fi
}

# ================================================================
# ETAPE 3 — CREATION DE LA BASE
# ================================================================
create_database() {
    log_etape "3/5" "CREATION DE LA BASE DE DONNEES"

    # Creer les dossiers
    mkdir -p "$(dirname "$DB_PATH")"
    mkdir -p /opt/siem-africa/rapports/installation

    # Sauvegarder si base existante
    if [ -f "$DB_PATH" ]; then
        BACKUP="${DB_PATH}.backup_$(date +%Y%m%d_%H%M%S)"
        cp "$DB_PATH" "$BACKUP"
        log_warn "Base existante sauvegardee : $BACKUP"
        rm -f "$DB_PATH"
    fi

    # Creer la base avec le schema
    log_info "Creation de la base : $DB_PATH"
    sqlite3 "$DB_PATH" < "${SCRIPT_DIR}/schema.sql"

    # Compter
    TABLE_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='table';")
    VIEW_COUNT=$(sqlite3  "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='view';")
    INDEX_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='index';")

    log_ok "Tables  : ${TABLE_COUNT}"
    log_ok "Vues    : ${VIEW_COUNT}"
    log_ok "Index   : ${INDEX_COUNT}"
}

# ================================================================
# ETAPE 4 — IMPORT DES SIGNATURES
# ================================================================
import_attacks() {
    log_etape "4/5" "IMPORT DES SIGNATURES D ATTAQUES"

    log_info "Import des signatures contextualisees Afrique..."
    sqlite3 "$DB_PATH" < "${SCRIPT_DIR}/attacks.sql"

    ATTACK_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM attaques;")
    log_ok "Signatures importees : ${ATTACK_COUNT}"

    echo ""
    echo -e "  ${BOLD}Par categorie :${NC}"
    sqlite3 "$DB_PATH" \
        "SELECT '  ' || categorie || ' : ' || COUNT(*) || ' signatures'
         FROM attaques
         GROUP BY categorie
         ORDER BY COUNT(*) DESC;"

    echo ""
    echo -e "  ${BOLD}Par gravite :${NC}"
    while IFS='|' read -r GRAV NB; do
        case "$GRAV" in
            4) LABEL="Critique" ; COLOR="$RED"    ;;
            3) LABEL="Haute"    ; COLOR="$YELLOW" ;;
            2) LABEL="Moyenne"  ; COLOR="$CYAN"   ;;
            1) LABEL="Faible"   ; COLOR="$GREEN"  ;;
            *) LABEL="Inconnu"  ; COLOR="$NC"     ;;
        esac
        echo -e "  ${COLOR}●${NC} ${LABEL} : ${NB}"
    done < <(sqlite3 "$DB_PATH" \
        "SELECT gravite, COUNT(*) FROM attaques GROUP BY gravite ORDER BY gravite DESC;")
    echo ""
}

# ================================================================
# ETAPE 5 — FINALISATION
# ================================================================
finalize() {
    log_etape "5/5" "FINALISATION"

    # Permissions sur la base
    chown "$USER_DB":"$USER_DB" "$DB_PATH" 2>/dev/null || true
    chmod 640 "$DB_PATH"
    log_ok "Permissions : 640 (proprietaire: ${USER_DB})"

    # Mettre a jour .env
    if [ -f "$ENV_FILE" ]; then
        if grep -q "^DB_PATH=" "$ENV_FILE" 2>/dev/null; then
            sed -i "s|^DB_PATH=.*|DB_PATH=${DB_PATH}|" "$ENV_FILE"
        else
            echo "DB_PATH=${DB_PATH}" >> "$ENV_FILE"
        fi
        log_ok ".env mis a jour"
    fi

    # Mettre a jour credentials.txt
    if [ -f "$CRED_FILE" ]; then
        cat >> "$CRED_FILE" << CREDS

── BASE DE DONNEES (module 2) ────────────────────────────────

  Utilisateur systeme  : ${USER_DB}
  Shell                : /sbin/nologin (pas de connexion directe)
  Type                 : SQLite
  Chemin               : ${DB_PATH}
  Tables               : ${TABLE_COUNT}
  Vues                 : ${VIEW_COUNT}
  Signatures attaques  : ${ATTACK_COUNT}
  Permissions          : 640

  Commandes utiles :
  Ouvrir la base  : sqlite3 ${DB_PATH}
  Voir stats      : sqlite3 ${DB_PATH} "SELECT * FROM v_stats_dashboard;"
  Voir alertes    : sqlite3 ${DB_PATH} "SELECT * FROM v_alertes_recentes LIMIT 10;"
  Compter alertes : sqlite3 ${DB_PATH} "SELECT COUNT(*) FROM alertes;"

── PROCHAINE ETAPE ───────────────────────────────────────────
  Module 3 — Agent intelligent
  Commande : cd ../3-agent && sudo bash install.sh

CREDS
        log_ok "credentials.txt mis a jour"
    fi

    # Rapport
    RAPPORT="/opt/siem-africa/rapports/installation/rapport_module2_$(date +%Y%m%d_%H%M%S).txt"
    cat > "$RAPPORT" << RAPPORT_CONTENT
================================================================
  SIEM Africa — Rapport Module 2 : Base de donnees
  Date : $(date '+%d/%m/%Y a %H:%M:%S')
================================================================
STATUT : INSTALLATION REUSSIE

Utilisateur systeme : ${USER_DB}
Base de donnees     : ${DB_PATH}
Version SQLite      : $(sqlite3 --version | awk '{print $1}')
Tables              : ${TABLE_COUNT}
Vues                : ${VIEW_COUNT}
Index               : ${INDEX_COUNT}
Signatures          : ${ATTACK_COUNT} attaques contextualisees Afrique

Repartition par categorie :
$(sqlite3 "$DB_PATH" "SELECT '  ' || categorie || ' : ' || COUNT(*) FROM attaques GROUP BY categorie ORDER BY COUNT(*) DESC;")

Prochaine etape :
  cd ../3-agent && sudo bash install.sh
================================================================
RAPPORT_CONTENT

    log_ok "Rapport genere : $RAPPORT"
}

# ================================================================
# RESUME FINAL
# ================================================================
show_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     MODULE 2 — INSTALLATION TERMINEE AVEC SUCCES    ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}── UTILISATEUR SYSTEME ───────────────────────────────${NC}"
    echo -e "  ${GREEN}[OK]${NC} ${USER_DB} — Base de donnees SQLite"
    echo ""
    echo -e "${CYAN}── BASE DE DONNEES ───────────────────────────────────${NC}"
    echo -e "  Chemin      : ${YELLOW}${DB_PATH}${NC}"
    echo -e "  Tables      : ${TABLE_COUNT}"
    echo -e "  Vues        : ${VIEW_COUNT}"
    echo -e "  Signatures  : ${ATTACK_COUNT} attaques"
    echo ""
    echo -e "${CYAN}── COMMANDES UTILES ──────────────────────────────────${NC}"
    echo -e "  sqlite3 ${DB_PATH}"
    echo -e "  sqlite3 ${DB_PATH} \"SELECT * FROM v_stats_dashboard;\""
    echo ""
    echo -e "${CYAN}── PROCHAINE ETAPE ───────────────────────────────────${NC}"
    echo -e "  ${YELLOW}cd ../3-agent && sudo bash install.sh${NC}"
    echo ""
}

# ================================================================
# MAIN
# ================================================================
main() {
    echo "=== SIEM Africa Module 2 - $(date) ===" >> "$LOG_FILE"

    show_banner

    echo -e "${CYAN}[VERIFICATIONS]${NC}"
    echo "────────────────────────────────────────────────────"
    check_root
    check_module1
    check_files
    echo ""

    echo -e "${CYAN}[INSTALLATION]${NC}"
    echo "────────────────────────────────────────────────────"
    create_user
    install_deps
    echo ""
    create_database
    echo ""
    import_attacks
    finalize
    echo ""

    show_summary

    log_info "Module 2 termine - $(date)"
}

main "$@"
