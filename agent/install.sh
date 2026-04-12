#!/bin/bash
# ================================================================
#  SIEM Africa — Module 3 : Agent intelligent
#  Fichier  : agent/install.sh
#  Usage    : sudo bash install.sh
# ================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

LOG_FILE="/var/log/siem-africa-install.log"
OPT_DIR="/opt/siem-africa"
AGENT_DIR="/opt/siem-africa/agent"
ENV_FILE="/opt/siem-africa/.env"
CRED_FILE="/opt/siem-africa/credentials.txt"
GROUPE="siem-africa"
USER_AGENT="siem-agent"
SERVICE="siem-agent"
GITHUB_BASE="https://raw.githubusercontent.com/luciesys/SIEM-AFRICA/main"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()       { echo -e "$1" | tee -a "$LOG_FILE"; }
log_ok()    { log "${GREEN}[OK]${NC} $1"; }
log_info()  { log "${CYAN}[INFO]${NC} $1"; }
log_warn()  { log "${YELLOW}[ATTENTION]${NC} $1"; }
log_err()   { log "${RED}[ERREUR]${NC} $1"; }
log_etape() {
    log ""
    log "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log "${BLUE}${BOLD}  ETAPE $1${NC}"
    log "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

quitter() {
    log_err "$1"
    echo -e "\n${RED}Installation arretee. Journal : $LOG_FILE${NC}"
    exit 1
}

show_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║       SIEM Africa — Module 3 v3.0                   ║"
    echo "  ║       Agent intelligent                             ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ================================================================
# ETAPE 1 : Verifications
# ================================================================
check_all() {
    log_etape "1/5 — VERIFICATIONS"

    [ "$EUID" -ne 0 ] && quitter "sudo requis — lancez : sudo bash install.sh"
    log_ok "Root confirme"

    [ ! -f "$ENV_FILE" ] && quitter "Module 1 non installe — lancez installation/install.sh d'abord"
    log_ok "Module 1 detecte"

    [ ! -f "$OPT_DIR/siem_africa.db" ] && quitter "Module 2 non installe — lancez database/install.sh d'abord"
    log_ok "Module 2 detecte (base SQLite)"

    # Python3
    command -v python3 > /dev/null 2>&1 || quitter "Python3 non installe"
    PY_VER=$(python3 --version 2>&1 | cut -d' ' -f2)
    log_ok "Python3 : $PY_VER"
}

# ================================================================
# ETAPE 2 : Trouver ou telecharger agent.py
# ================================================================
trouver_agent_py() {
    log_etape "2/5 — AGENT.PY"

    # Ordre de recherche :
    # 1. Meme dossier que install.sh (SCRIPT_DIR)
    # 2. /tmp/agent.py
    # 3. Telecharger depuis GitHub

    AGENT_PY_SRC=""

    if [ -f "${SCRIPT_DIR}/agent.py" ]; then
        AGENT_PY_SRC="${SCRIPT_DIR}/agent.py"
        log_ok "agent.py trouve dans $SCRIPT_DIR"

    elif [ -f "/tmp/agent.py" ]; then
        AGENT_PY_SRC="/tmp/agent.py"
        log_ok "agent.py trouve dans /tmp"

    else
        log_info "agent.py absent — telechargement depuis GitHub..."
        curl -sL "${GITHUB_BASE}/agent/agent.py" -o /tmp/agent.py 2>/dev/null || \
        wget -q   "${GITHUB_BASE}/agent/agent.py" -O /tmp/agent.py 2>/dev/null || true

        if [ -f "/tmp/agent.py" ] && grep -q "AgentSIEM\|def demarrer" /tmp/agent.py 2>/dev/null; then
            AGENT_PY_SRC="/tmp/agent.py"
            log_ok "agent.py telecharge depuis GitHub"
        else
            quitter "Impossible de trouver agent.py — placez-le dans le meme dossier que install.sh"
        fi
    fi
}

# ================================================================
# ETAPE 3 : Installation des dependances Python
# ================================================================
install_deps() {
    log_etape "3/5 — DEPENDANCES PYTHON"

    log_info "Mise a jour pip..."
    python3 -m pip install --upgrade pip --quiet 2>/dev/null || true

    # Pas de dependances externes requises — on utilise uniquement la stdlib Python3
    # sqlite3, smtplib, email, socket, threading, logging = inclus dans Python3
    log_ok "Toutes les dependances sont dans la bibliotheque standard Python3"
    log_ok "Aucune installation pip requise"
}

# ================================================================
# ETAPE 4 : Creation utilisateur et installation fichiers
# ================================================================
installer_agent() {
    log_etape "4/5 — INSTALLATION AGENT"

    # Creer l'utilisateur siem-agent
    if id "$USER_AGENT" > /dev/null 2>&1; then
        log_info "Utilisateur $USER_AGENT existe deja"
    else
        useradd --system --no-create-home \
                --shell /sbin/nologin \
                --gid "$GROUPE" \
                --comment "SIEM Africa Agent" \
                "$USER_AGENT"
        log_ok "Utilisateur $USER_AGENT cree"
    fi
    usermod -aG "$GROUPE" "$USER_AGENT" 2>/dev/null || true

    # CORRECTION PROBLEME v2 : Creer AGENT_DIR avec droits corrects DES LE DEBUT
    # L'erreur "CHDIR status=200" venait de droits insuffisants sur ce dossier
    mkdir -p "$AGENT_DIR"
    chown "${USER_AGENT}:${GROUPE}" "$AGENT_DIR"
    chmod 750 "$AGENT_DIR"
    log_ok "Dossier $AGENT_DIR cree (chmod 750, proprio $USER_AGENT)"

    # Copier agent.py
    cp "$AGENT_PY_SRC" "${AGENT_DIR}/agent.py"
    chown "${USER_AGENT}:${GROUPE}" "${AGENT_DIR}/agent.py"
    chmod 640 "${AGENT_DIR}/agent.py"
    log_ok "agent.py installe dans $AGENT_DIR"

    # Verifier que agent.py est lisible par siem-agent
    if sudo -u "$USER_AGENT" test -r "${AGENT_DIR}/agent.py" 2>/dev/null; then
        log_ok "agent.py lisible par $USER_AGENT"
    else
        # Corriger les droits du dossier parent
        chmod 755 "$OPT_DIR"
        chmod 750 "$AGENT_DIR"
        log_warn "Droits corriges sur $OPT_DIR et $AGENT_DIR"
    fi

    # Verifier les droits sur les fichiers necessaires
    # alerts.json
    chmod o+r /var/ossec/logs/alerts/alerts.json 2>/dev/null || true
    setfacl -m u:"${USER_AGENT}":r /var/ossec/logs/alerts/alerts.json 2>/dev/null || true
    log_ok "Acces alerts.json configure pour $USER_AGENT"

    # Base SQLite — siem-agent doit pouvoir ecrire
    chown "${GROUPE}:${GROUPE}" "${OPT_DIR}/siem_africa.db" 2>/dev/null || true
    chmod 664 "${OPT_DIR}/siem_africa.db" 2>/dev/null || true
    log_ok "Acces base SQLite configure pour $USER_AGENT"

    # .env — lecture seulement
    chmod 640 "$ENV_FILE" 2>/dev/null || true
    setfacl -m u:"${USER_AGENT}":r "$ENV_FILE" 2>/dev/null || \
        chmod o+r "$ENV_FILE" 2>/dev/null || true
    log_ok "Acces .env configure pour $USER_AGENT"

    # Logs
    mkdir -p /var/log/siem-africa
    chown "${USER_AGENT}:${GROUPE}" /var/log/siem-africa
    chmod 775 /var/log/siem-africa
    log_ok "Dossier logs configure"

    # Creer le service systemd
    # CORRECTION PROBLEME v2 : WorkingDirectory = AGENT_DIR (pas le dossier du script)
    cat > /etc/systemd/system/${SERVICE}.service << SRVSVC
[Unit]
Description=SIEM Africa Agent Intelligent v3.0
Documentation=https://github.com/luciesys/SIEM-AFRICA
After=network.target wazuh-manager.service
Wants=wazuh-manager.service

[Service]
Type=simple
User=${USER_AGENT}
Group=${GROUPE}
WorkingDirectory=${AGENT_DIR}
ExecStart=/usr/bin/python3 ${AGENT_DIR}/agent.py
Restart=always
RestartSec=10
StandardOutput=append:/var/log/siem-africa/agent.log
StandardError=append:/var/log/siem-africa/agent.log

[Install]
WantedBy=multi-user.target
SRVSVC

    systemctl daemon-reload
    systemctl enable "$SERVICE" 2>/dev/null || true
    log_ok "Service $SERVICE configure"
}

# ================================================================
# ETAPE 5 : Demarrage et finalisation
# ================================================================
demarrer_agent() {
    log_etape "5/5 — DEMARRAGE ET FINALISATION"

    # Demarrer le service
    systemctl start "$SERVICE" 2>/dev/null || true
    sleep 3

    if systemctl is-active --quiet "$SERVICE"; then
        log_ok "Service $SERVICE : ACTIF"
    else
        log_warn "Agent non actif — diagnostic :"
        # Afficher l'erreur precise
        journalctl -u "$SERVICE" -n 5 --no-pager 2>/dev/null | \
            grep -v "^--" | tail -5 | while read line; do
                log_warn "  $line"
            done
        log_warn "Verifier les logs : journalctl -u $SERVICE -n 20"
    fi

    # Mettre a jour credentials.txt
    cat >> "$CRED_FILE" << CREDS

── MODULE 3 — AGENT INTELLIGENT ─────────────────────────────
  Installe le : $(date '+%d/%m/%Y a %H:%M')
  Utilisateur : $USER_AGENT
  Dossier     : $AGENT_DIR
  Service     : $SERVICE.service

── CONFIGURATION AGENT ───────────────────────────────────────
  Polling     : $(grep "^POLLING_INTERVAL=" "$ENV_FILE" | cut -d= -f2)s
  Correlation : $(grep "^CORRELATION_THRESHOLD=" "$ENV_FILE" | cut -d= -f2) alertes / $(grep "^CORRELATION_WINDOW=" "$ENV_FILE" | cut -d= -f2)s
  Active Resp : Blocage auto apres $(grep "^ACTIVE_RESPONSE_DELAY=" "$ENV_FILE" | cut -d= -f2)s (gravite 4)
  Honeypot    : SSH:$(grep "^HONEYPOT_SSH_PORT=" "$ENV_FILE" | cut -d= -f2) HTTP:$(grep "^HONEYPOT_HTTP_PORT=" "$ENV_FILE" | cut -d= -f2) MySQL:$(grep "^HONEYPOT_MYSQL_PORT=" "$ENV_FILE" | cut -d= -f2)

── SMTP (A CONFIGURER) ───────────────────────────────────────
  sudo nano /opt/siem-africa/.env
  → SMTP_HOST=smtp.gmail.com
  → SMTP_PORT=587
  → SMTP_USER=votre@email.com
  → SMTP_PASSWORD=votre_mot_de_passe_app
  → ALERT_EMAIL=email_alertes@entreprise.cm
  sudo systemctl restart siem-agent

── COMMANDES UTILES ──────────────────────────────────────────
  Status   : systemctl status siem-agent
  Logs     : tail -f /var/log/siem-africa/agent.log
  Restart  : sudo systemctl restart siem-agent

CREDS

    chmod 640 "$CRED_FILE"

    # Resume
    echo ""
    echo -e "${GREEN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║     MODULE 3 — INSTALLATION TERMINEE                ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "${CYAN}── SERVICES ─────────────────────────────────────────${NC}"
    for svc in snort wazuh-manager siem-agent; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            echo -e "  ${GREEN}[ACTIF]${NC}    $svc"
        else
            echo -e "  ${YELLOW}[INACTIF]${NC}  $svc"
        fi
    done

    echo ""
    echo -e "${CYAN}── SMTP A CONFIGURER ────────────────────────────────${NC}"
    echo -e "  ${YELLOW}sudo nano /opt/siem-africa/.env${NC}"
    echo -e "  Remplir SMTP_USER, SMTP_PASSWORD et ALERT_EMAIL"
    echo -e "  Puis : ${YELLOW}sudo systemctl restart siem-agent${NC}"

    echo ""
    echo -e "${CYAN}── LOGS EN DIRECT ───────────────────────────────────${NC}"
    echo -e "  ${YELLOW}tail -f /var/log/siem-africa/agent.log${NC}"

    echo ""
    echo -e "${CYAN}── PROCHAINE ETAPE ──────────────────────────────────${NC}"
    echo -e "  ${YELLOW}Module 4 — Dashboard Django${NC}"
    echo ""
}

# ================================================================
# MAIN
# ================================================================
main() {
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    echo "" >> "$LOG_FILE"
    echo "=== SIEM Africa Module 3 v3.0 - $(date) ===" >> "$LOG_FILE"

    show_banner
    check_all
    trouver_agent_py
    install_deps
    installer_agent
    demarrer_agent

    log_info "Module 3 termine — $(date)"
}

main "$@"
