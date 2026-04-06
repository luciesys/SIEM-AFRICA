#!/bin/bash
# ================================================================
#  SIEM Africa — Module 3 : Agent intelligent
#  Fichier  : agent/install.sh
#  Usage    : sudo bash install.sh
#  Version  : 1.0
# ================================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

LOG_FILE="/var/log/siem-africa-install.log"
AGENT_DIR="/opt/siem-africa/agent"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_AGENT="siem-agent"

log()       { echo -e "$1" | tee -a "$LOG_FILE"; }
log_ok()    { log "${GREEN}[OK]${NC} $1"; }
log_info()  { log "${CYAN}[INFO]${NC} $1"; }
log_warn()  { log "${YELLOW}[ATTENTION]${NC} $1"; }
log_etape() { log "${BLUE}[ETAPE $1]${NC} $2"; }

quitter() {
    echo -e "${RED}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║     INSTALLATION ARRETEE — $1${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════╝${NC}"
    exit 1
}

show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║       SIEM Africa — Module 3                        ║"
    echo "║       Agent intelligent                             ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
}

# ================================================================
# VERIFICATIONS
# ================================================================
check_root() {
    [ "$EUID" -ne 0 ] && quitter "Lancez avec : sudo bash install.sh"
    log_ok "Droits root confirmes"
}

check_modules() {
    log_info "Verification des modules precedents..."

    [ ! -d "/var/ossec" ]                    && quitter "Wazuh non installe. Lancez le module 1."
    [ ! -f "/opt/siem-africa/.env" ]         && quitter "Module 1 non installe."
    [ ! -f "/opt/siem-africa/siem_africa.db" ] && quitter "Base de donnees non trouvee. Lancez le module 2."

    log_ok "Modules 1 et 2 detectes"
}

check_agent_file() {
    log_info "Verification du fichier agent.py..."
    [ ! -f "${SCRIPT_DIR}/agent.py" ] && quitter "agent.py introuvable dans ${SCRIPT_DIR}"
    log_ok "agent.py present"
}

# ================================================================
# ETAPE 1 — UTILISATEUR SYSTEME
# ================================================================
create_user() {
    log_etape "1/5" "CREATION UTILISATEUR SYSTEME"

    if id "$USER_AGENT" > /dev/null 2>&1; then
        log_info "Utilisateur ${USER_AGENT} existe deja"
    else
        useradd --system \
                --no-create-home \
                --shell /sbin/nologin \
                --comment "SIEM Africa - Agent intelligent" \
                "$USER_AGENT"
        log_ok "Utilisateur ${USER_AGENT} cree"
    fi

    echo ""
    echo -e "  ${GREEN}[OK]${NC} ${USER_AGENT}"
    echo -e "       Role  : Agent intelligent (polling Wazuh API)"
    echo -e "       Shell : /sbin/nologin (pas de connexion directe)"
    echo ""
}

# ================================================================
# ETAPE 2 — DEPENDANCES PYTHON
# ================================================================
install_deps() {
    log_etape "2/5" "INSTALLATION DES DEPENDANCES"

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq

    apt-get install -y -qq python3 python3-pip > /dev/null 2>&1
    log_ok "Python3 pret"

    # L'agent utilise uniquement la bibliothèque standard Python
    # (urllib, smtplib, sqlite3, logging — tout est inclus dans Python3)
    log_ok "Dependances OK — bibliotheques standard Python3 uniquement"
}

# ================================================================
# ETAPE 3 — INSTALLATION DE L'AGENT
# ================================================================
install_agent() {
    log_etape "3/5" "INSTALLATION DE L AGENT"

    # Créer le dossier
    mkdir -p "$AGENT_DIR"

    # Copier l'agent
    cp "${SCRIPT_DIR}/agent.py" "${AGENT_DIR}/agent.py"
    chmod 750 "${AGENT_DIR}/agent.py"

    # Créer les dossiers nécessaires
    mkdir -p /var/log/siem-africa
    mkdir -p /opt/siem-africa/rapports/installation

    # Droits
    chown -R "$USER_AGENT":"$USER_AGENT" "$AGENT_DIR" 2>/dev/null || true
    chown -R "$USER_AGENT":"$USER_AGENT" /var/log/siem-africa 2>/dev/null || true

    # Donner accès à la base SQLite
    DB_PATH=$(grep "^DB_PATH=" /opt/siem-africa/.env | cut -d'=' -f2 | tr -d '"' 2>/dev/null || echo "/opt/siem-africa/siem_africa.db")
    if [ -f "$DB_PATH" ]; then
        chown siem-africa:"$USER_AGENT" "$DB_PATH" 2>/dev/null || true
        chmod 660 "$DB_PATH"
        log_ok "Acces base de donnees configure"
    fi

    # Donner accès au .env en lecture
    chmod 640 /opt/siem-africa/.env
    chown root:"$USER_AGENT" /opt/siem-africa/.env 2>/dev/null || true

    log_ok "Agent installe dans ${AGENT_DIR}"
}

# ================================================================
# ETAPE 4 — SERVICE SYSTEMD
# ================================================================
install_service() {
    log_etape "4/5" "CREATION DU SERVICE SYSTEMD"

    # Lire les variables depuis .env
    WAZUH_PASSWORD=""
    WAZUH_HOST="127.0.0.1"
    WAZUH_PORT="55000"

    if [ -f "/opt/siem-africa/.env" ]; then
        WAZUH_PASSWORD=$(grep "^WAZUH_PASSWORD=" /opt/siem-africa/.env | cut -d'=' -f2 | tr -d '"')
        WAZUH_HOST=$(grep "^WAZUH_HOST=" /opt/siem-africa/.env | cut -d'=' -f2 | tr -d '"')
        WAZUH_PORT=$(grep "^WAZUH_PORT=" /opt/siem-africa/.env | cut -d'=' -f2 | tr -d '"')
    fi

    cat > /etc/systemd/system/siem-agent.service << SERVICE
[Unit]
Description=SIEM Africa - Agent intelligent
Documentation=https://github.com/luciesys/SIEM-AFRICA
After=network.target wazuh-manager.service

[Service]
Type=simple
User=${USER_AGENT}
Group=${USER_AGENT}
WorkingDirectory=${AGENT_DIR}
ExecStart=/usr/bin/python3 ${AGENT_DIR}/agent.py
Restart=always
RestartSec=10
StandardOutput=append:/var/log/siem-africa/agent.log
StandardError=append:/var/log/siem-africa/agent.log

# Securite
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/log/siem-africa /opt/siem-africa
ReadOnlyPaths=/opt/siem-africa/.env

[Install]
WantedBy=multi-user.target
SERVICE

    systemctl daemon-reload
    systemctl enable siem-agent
    systemctl start siem-agent
    sleep 3

    if systemctl is-active --quiet siem-agent; then
        log_ok "Service siem-agent demarre"
    else
        log_warn "Service siem-agent non demarre — vérifiez : journalctl -u siem-agent"
    fi
}

# ================================================================
# ETAPE 5 — FINALISATION
# ================================================================
finalize() {
    log_etape "5/5" "FINALISATION"

    CRED_FILE="/opt/siem-africa/credentials.txt"
    if [ -f "$CRED_FILE" ]; then
        cat >> "$CRED_FILE" << CREDS

── AGENT INTELLIGENT (module 3) ──────────────────────────────

  Utilisateur systeme  : ${USER_AGENT}
  Shell                : /sbin/nologin (pas de connexion directe)
  Script               : ${AGENT_DIR}/agent.py
  Service              : siem-agent.service

  Fonctionnalites :
  - Interroge l API Wazuh :55000 toutes les 10 secondes
  - Enrichit les alertes avec la base SQLite (380 signatures)
  - Correlation : 3+ alertes meme IP en 60s -> CRITIQUE
  - Stocke les attaques inconnues pour enrichissement manuel
  - Envoie email pour alertes Critique et Haute

  Logs                 : /var/log/siem-africa/agent.log
  Verifier             : systemctl status siem-agent
  Voir logs            : tail -f /var/log/siem-africa/agent.log
  Redemarrer           : systemctl restart siem-agent

── PROCHAINE ETAPE ───────────────────────────────────────────
  Module 4 — Dashboard Flask
  Commande : cd ../4-dashboard && sudo bash install.sh

CREDS
        log_ok "credentials.txt mis a jour"
    fi

    # Rapport
    RAPPORT="/opt/siem-africa/rapports/installation/rapport_module3_$(date +%Y%m%d_%H%M%S).txt"
    cat > "$RAPPORT" << RAPPORT_CONTENT
================================================================
  SIEM Africa — Rapport Module 3 : Agent intelligent
  Date : $(date '+%d/%m/%Y a %H:%M:%S')
================================================================
STATUT : INSTALLATION REUSSIE

Utilisateur systeme : ${USER_AGENT}
Script agent        : ${AGENT_DIR}/agent.py
Service systemd     : siem-agent.service
Logs                : /var/log/siem-africa/agent.log

Fonctionnalites :
  - Polling Wazuh API :55000 toutes les 10s
  - Matching 380 signatures SQLite
  - Correlation 3+ alertes meme IP en 60s
  - Geolocalisation IP (ip-api.com)
  - Notification email SMTP

Prochaine etape :
  cd ../4-dashboard && sudo bash install.sh
================================================================
RAPPORT_CONTENT

    log_ok "Rapport : $RAPPORT"
}

# ================================================================
# RESUME FINAL
# ================================================================
show_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     MODULE 3 — AGENT INSTALLE AVEC SUCCES           ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}── UTILISATEUR SYSTEME ───────────────────────────────${NC}"
    echo -e "  ${GREEN}[OK]${NC} ${USER_AGENT} — Agent intelligent"
    echo ""
    echo -e "${CYAN}── SERVICE ───────────────────────────────────────────${NC}"
    if systemctl is-active --quiet siem-agent; then
        echo -e "  ${GREEN}[ACTIF]${NC} siem-agent.service"
    else
        echo -e "  ${RED}[INACTIF]${NC} siem-agent.service"
    fi
    echo ""
    echo -e "${CYAN}── COMMANDES UTILES ──────────────────────────────────${NC}"
    echo -e "  systemctl status siem-agent"
    echo -e "  tail -f /var/log/siem-africa/agent.log"
    echo -e "  systemctl restart siem-agent"
    echo ""
    echo -e "${CYAN}── PROCHAINE ETAPE ───────────────────────────────────${NC}"
    echo -e "  ${YELLOW}cd ../4-dashboard && sudo bash install.sh${NC}"
    echo ""
}

# ================================================================
# MAIN
# ================================================================
main() {
    echo "=== SIEM Africa Module 3 - $(date) ===" >> "$LOG_FILE"
    show_banner

    echo -e "${CYAN}[VERIFICATIONS]${NC}"
    echo "────────────────────────────────────────────────────"
    check_root
    check_modules
    check_agent_file
    echo ""

    echo -e "${CYAN}[INSTALLATION]${NC}"
    echo "────────────────────────────────────────────────────"
    create_user
    install_deps
    echo ""
    install_agent
    echo ""
    install_service
    echo ""
    finalize
    echo ""

    show_summary
    log_info "Module 3 termine - $(date)"
}

main "$@"
