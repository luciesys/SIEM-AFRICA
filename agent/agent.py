#!/bin/bash
# SIEM Africa — Module 3 : Agent intelligent v2.0
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

LOG_FILE="/var/log/siem-africa-install.log"
AGENT_DIR="/opt/siem-africa/agent"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_AGENT="siem-agent"
ENV_FILE="/opt/siem-africa/.env"
CRED_FILE="/opt/siem-africa/credentials.txt"

log()       { echo -e "$1" | tee -a "$LOG_FILE"; }
log_ok()    { log "${GREEN}[OK]${NC} $1"; }
log_info()  { log "${CYAN}[INFO]${NC} $1"; }
log_warn()  { log "${YELLOW}[ATTENTION]${NC} $1"; }
log_etape() { log "${BLUE}[ETAPE $1]${NC} $2"; }

quitter() {
    echo -e "${RED}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║     INSTALLATION ARRETEE                             ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════╝${NC}"
    echo -e "  Raison : $1"
    exit 1
}

show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║       SIEM Africa — Module 3                        ║"
    echo "║       Agent intelligent v2.0                        ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ── Etape 1 : Verifications ───────────────────────────────────────
check_all() {
    log_etape "1/6" "VERIFICATIONS"

    [ "$EUID" -ne 0 ] && quitter "Lancez avec : sudo bash install.sh"
    log_ok "Droits root confirmes"

    command -v snort > /dev/null 2>&1 || quitter "Snort non installe. Lancez le module 1."
    log_ok "Snort installe"

    [ ! -d "/var/ossec" ] && quitter "Wazuh non installe. Lancez le module 1."
    log_ok "Wazuh installe"

    systemctl is-active --quiet snort 2>/dev/null || {
        log_warn "Snort non actif — demarrage..."
        systemctl start snort 2>/dev/null || true
    }
    log_ok "Service Snort actif"

    systemctl is-active --quiet wazuh-manager 2>/dev/null || {
        log_warn "Wazuh Manager non actif — demarrage..."
        systemctl start wazuh-manager 2>/dev/null || true
        sleep 5
    }
    log_ok "Service Wazuh Manager actif"

    [ ! -f "$ENV_FILE" ] && quitter "Fichier .env non trouve. Lancez le module 1."
    log_ok "Fichier .env present"

    DB_PATH=$(grep "^DB_PATH=" "$ENV_FILE" | cut -d'=' -f2 | tr -d '"' 2>/dev/null || echo "/opt/siem-africa/siem_africa.db")
    [ ! -f "$DB_PATH" ] && quitter "Base de donnees non trouvee. Lancez le module 2."

    ATTACK_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM attaques;" 2>/dev/null || echo "0")
    [ "$ATTACK_COUNT" -eq 0 ] && quitter "Table attaques vide. Verifiez le module 2."
    log_ok "Base SQLite : $ATTACK_COUNT signatures"
}

# ── Etape 2 : Detection automatique MDP Wazuh ─────────────────────
detect_wazuh_password() {
    log_etape "2/6" "DETECTION AUTOMATIQUE MOT DE PASSE WAZUH API"

    WAZUH_API_PASS=""
    WAZUH_API_USER="wazuh"

    # Chercher le fichier tar dans plusieurs emplacements
    WAZUH_TAR=""
    for TAR_PATH in /root/wazuh-install-files.tar /tmp/wazuh-install-files.tar; do
        if [ -f "$TAR_PATH" ]; then
            WAZUH_TAR="$TAR_PATH"
            log_info "Fichier Wazuh trouve : $TAR_PATH"
            break
        fi
    done

    if [ -n "$WAZUH_TAR" ]; then
        # Trouver le nom du fichier passwords dans le tar
        PASS_FILENAME=$(tar -tf "$WAZUH_TAR" 2>/dev/null | grep "wazuh-passwords.txt" | head -1)

        if [ -n "$PASS_FILENAME" ]; then
            log_info "Extraction du fichier de mots de passe..."
            PASS_CONTENT=$(tar -xOf "$WAZUH_TAR" "$PASS_FILENAME" 2>/dev/null || echo "")

            # Parser le mot de passe pour l'utilisateur wazuh
            IN_WAZUH_BLOCK=0
            while IFS= read -r line; do
                if echo "$line" | grep -q "api_username:.*'wazuh'"; then
                    IN_WAZUH_BLOCK=1
                fi
                if [ "$IN_WAZUH_BLOCK" -eq 1 ] && echo "$line" | grep -q "api_password:"; then
                    WAZUH_API_PASS=$(echo "$line" | sed "s/.*'\(.*\)'.*/\1/")
                    IN_WAZUH_BLOCK=0
                    break
                fi
            done <<< "$PASS_CONTENT"

            if [ -n "$WAZUH_API_PASS" ]; then
                log_ok "Mot de passe API Wazuh detecte automatiquement"
            fi
        fi
    fi

    # Fallback : depuis le .env existant
    if [ -z "$WAZUH_API_PASS" ]; then
        EXISTING=$(grep "^WAZUH_PASSWORD=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 | tr -d '"')
        if [ -n "$EXISTING" ]; then
            WAZUH_API_PASS="$EXISTING"
            log_info "Mot de passe existant trouve dans .env"
        fi
    fi

    # Fallback : saisie manuelle
    if [ -z "$WAZUH_API_PASS" ]; then
        log_warn "Mot de passe non detecte automatiquement"
        if [ -n "$WAZUH_TAR" ] && [ -n "$PASS_FILENAME" ]; then
            echo ""
            echo -e "  ${CYAN}Mots de passe disponibles :${NC}"
            tar -xOf "$WAZUH_TAR" "$PASS_FILENAME" 2>/dev/null | grep -A2 "api_username" || true
            echo ""
        fi
        echo -n "  Entrez le mot de passe API Wazuh (api_username: wazuh) : "
        read -r WAZUH_API_PASS
        [ -z "$WAZUH_API_PASS" ] && quitter "Mot de passe Wazuh obligatoire"
    fi

    # Mettre à jour le .env
    if grep -q "^WAZUH_USER=" "$ENV_FILE" 2>/dev/null; then
        sed -i "s|^WAZUH_USER=.*|WAZUH_USER=${WAZUH_API_USER}|" "$ENV_FILE"
    else
        echo "WAZUH_USER=${WAZUH_API_USER}" >> "$ENV_FILE"
    fi

    if grep -q "^WAZUH_PASSWORD=" "$ENV_FILE" 2>/dev/null; then
        sed -i "s|^WAZUH_PASSWORD=.*|WAZUH_PASSWORD=${WAZUH_API_PASS}|" "$ENV_FILE"
    else
        echo "WAZUH_PASSWORD=${WAZUH_API_PASS}" >> "$ENV_FILE"
    fi

    log_ok "Identifiants Wazuh mis a jour dans .env"
    log_ok "Utilisateur : $WAZUH_API_USER"
    log_ok "Mot de passe : ${WAZUH_API_PASS:0:3}****${WAZUH_API_PASS: -3}"

    export WAZUH_API_USER WAZUH_API_PASS
}

# ── Etape 3 : Utilisateur systeme ─────────────────────────────────
create_user() {
    log_etape "3/6" "CREATION UTILISATEUR SYSTEME"

    if id "$USER_AGENT" > /dev/null 2>&1; then
        log_info "Utilisateur ${USER_AGENT} existe deja"
    else
        useradd --system --no-create-home --shell /sbin/nologin \
                --comment "SIEM Africa - Agent intelligent" "$USER_AGENT"
        log_ok "Utilisateur ${USER_AGENT} cree"
    fi

    echo -e "  ${GREEN}[OK]${NC} ${USER_AGENT} — Agent intelligent (shell: /sbin/nologin)"
}

# ── Etape 4 : Dependances ──────────────────────────────────────────
install_deps() {
    log_etape "4/6" "DEPENDANCES"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip sqlite3 > /dev/null 2>&1
    log_ok "Python3 et SQLite3 prets"
}

# ── Etape 5 : Installation et service ─────────────────────────────
install_agent() {
    log_etape "5/6" "INSTALLATION AGENT + SERVICE"

    # Dossiers
    mkdir -p "$AGENT_DIR"
    mkdir -p /var/log/siem-africa
    mkdir -p /opt/siem-africa/rapports/installation

    # Copier l'agent
    cp "${SCRIPT_DIR}/agent.py" "${AGENT_DIR}/agent.py"
    chmod 750 "${AGENT_DIR}/agent.py"

    # Permissions
    chown -R "$USER_AGENT":"$USER_AGENT" /var/log/siem-africa
    chown -R "$USER_AGENT":"$USER_AGENT" "$AGENT_DIR"
    chmod 755 /var/log/siem-africa

    DB_PATH=$(grep "^DB_PATH=" "$ENV_FILE" | cut -d'=' -f2 | tr -d '"' 2>/dev/null || echo "/opt/siem-africa/siem_africa.db")
    if [ -f "$DB_PATH" ]; then
        chown "$USER_AGENT":"$USER_AGENT" "$DB_PATH"
        chmod 660 "$DB_PATH"
        log_ok "Droits base de donnees configures"
    fi

    chown root:"$USER_AGENT" "$ENV_FILE" 2>/dev/null || true
    chmod 640 "$ENV_FILE"

    log_ok "Agent installe dans $AGENT_DIR"

    # Service systemd
    cat > /etc/systemd/system/siem-agent.service << SERVICE
[Unit]
Description=SIEM Africa - Agent intelligent
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

[Install]
WantedBy=multi-user.target
SERVICE

    systemctl daemon-reload
    systemctl enable siem-agent
    systemctl stop siem-agent 2>/dev/null || true
    sleep 2
    systemctl start siem-agent
    sleep 4

    if systemctl is-active --quiet siem-agent; then
        log_ok "Service siem-agent demarre"
    else
        log_warn "Service non demarre — vérifiez : tail -f /var/log/siem-africa/agent.log"
    fi
}

# ── Etape 6 : Finalisation ─────────────────────────────────────────
finalize() {
    log_etape "6/6" "FINALISATION — MISE A JOUR CREDENTIALS"

    if [ -f "$CRED_FILE" ]; then
        cat >> "$CRED_FILE" << CREDS

── AGENT INTELLIGENT (module 3) ──────────────────────────────

  Utilisateur systeme  : ${USER_AGENT}
  Shell                : /sbin/nologin
  Script               : ${AGENT_DIR}/agent.py
  Service              : siem-agent.service
  Logs                 : /var/log/siem-africa/agent.log

  Wazuh API user       : ${WAZUH_API_USER}
  Wazuh API MDP        : configure automatiquement dans .env

  Fonctionnalites :
  - Polling API Wazuh :55000 toutes les 10 secondes
  - Matching 380 signatures SQLite
  - Correlation : 3+ alertes meme IP en 60s -> CRITIQUE
  - Geolocalisation IP (ip-api.com)
  - Notification email SMTP

  Commandes :
  Verifier  : systemctl status siem-agent
  Logs      : tail -f /var/log/siem-africa/agent.log
  Restart   : systemctl restart siem-agent

── PROCHAINE ETAPE ───────────────────────────────────────────
  Module 4 — Dashboard Flask
  Commande : cd ../dashboard && sudo bash install.sh

CREDS
        log_ok "credentials.txt mis a jour"
    fi
}

show_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     MODULE 3 — AGENT INSTALLE AVEC SUCCES           ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}── UTILISATEUR SYSTEME ───────────────────────────────${NC}"
    echo -e "  ${GREEN}[OK]${NC} ${USER_AGENT}"
    echo ""
    echo -e "${CYAN}── SERVICE ───────────────────────────────────────────${NC}"
    if systemctl is-active --quiet siem-agent; then
        echo -e "  ${GREEN}[ACTIF]${NC} siem-agent.service"
    else
        echo -e "  ${RED}[INACTIF]${NC} siem-agent.service"
    fi
    echo ""
    echo -e "${CYAN}── WAZUH API ─────────────────────────────────────────${NC}"
    echo -e "  Utilisateur  : ${WAZUH_API_USER}"
    echo -e "  Mot de passe : detecte et configure automatiquement"
    echo ""
    echo -e "${CYAN}── COMMANDES ─────────────────────────────────────────${NC}"
    echo -e "  systemctl status siem-agent"
    echo -e "  tail -f /var/log/siem-africa/agent.log"
    echo ""
    echo -e "${CYAN}── PROCHAINE ETAPE ───────────────────────────────────${NC}"
    echo -e "  ${YELLOW}cd ../dashboard && sudo bash install.sh${NC}"
    echo ""
}

main() {
    echo "=== SIEM Africa Module 3 v2.0 - $(date) ===" >> "$LOG_FILE"
    show_banner

    echo -e "${CYAN}[VERIFICATIONS]${NC}"
    echo "────────────────────────────────────────────────────"
    check_all
    echo ""

    echo -e "${CYAN}[INSTALLATION]${NC}"
    echo "────────────────────────────────────────────────────"
    detect_wazuh_password
    echo ""
    create_user
    echo ""
    install_deps
    echo ""
    install_agent
    echo ""
    finalize
    echo ""

    show_summary
    log_info "Module 3 termine - $(date)"
}

main "$@"
