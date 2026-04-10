#!/bin/bash
# ================================================================
#  SIEM Africa — Module 3 : Agent intelligent
#  Fichier  : agent/install.sh
#  Usage    : sudo bash install.sh
#  Version  : 2.0
# ================================================================
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

LOG_FILE="/var/log/siem-africa-install.log"
AGENT_DIR="/opt/siem-africa/agent"
ENV_FILE="/opt/siem-africa/.env"
CRED_FILE="/opt/siem-africa/credentials.txt"
DB_PATH=""
USER_AGENT="siem-agent"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()       { echo -e "$1" | tee -a "$LOG_FILE"; }
log_ok()    { log "${GREEN}[OK]${NC} $1"; }
log_info()  { log "${CYAN}[INFO]${NC} $1"; }
log_warn()  { log "${YELLOW}[ATTENTION]${NC} $1"; }
log_etape() { log "${BLUE}[ETAPE $1]${NC} $2"; }

quitter() {
    echo -e "\n${RED}INSTALLATION ARRETEE : $1${NC}"
    echo "Journal : $LOG_FILE"
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
    [ "$EUID" -ne 0 ] && quitter "sudo requis"
    log_ok "Root confirme"

    [ ! -f "$ENV_FILE" ] && quitter "Module 1 non installe — lancez installation/install.sh"
    log_ok "Module 1 detecte"

    DB_PATH=$(grep "^DB_PATH=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 | tr -d '"' || echo "/opt/siem-africa/siem_africa.db")
    [ -z "$DB_PATH" ] && DB_PATH="/opt/siem-africa/siem_africa.db"

    [ ! -f "$DB_PATH" ] && quitter "Base de donnees non trouvee : $DB_PATH — lancez database/install.sh"
    log_ok "Base SQLite detectee : $DB_PATH"

    NB_SIG=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM attaques;" 2>/dev/null || echo "0")
    [ "$NB_SIG" -lt 1 ] && quitter "Table attaques vide — lancez database/install.sh"
    log_ok "Signatures : $NB_SIG"

    [ ! -f "${SCRIPT_DIR}/agent.py" ] && quitter "agent.py introuvable dans $SCRIPT_DIR"
    log_ok "agent.py detecte"

    python3 --version > /dev/null 2>&1 || quitter "Python3 non installe"
    log_ok "Python3 disponible"
}

# ── Etape 2 : Detection MDP Wazuh ────────────────────────────────
detect_wazuh_password() {
    log_etape "2/6" "DETECTION MOT DE PASSE WAZUH"

    WAZUH_PASS=""
    WAZUH_USER_API="wazuh"

    # Chercher dans wazuh-install-files.tar
    for TAR_PATH in /root/wazuh-install-files.tar /tmp/wazuh-install-files.tar; do
        if [ -f "$TAR_PATH" ]; then
            log_info "Lecture de $TAR_PATH ..."
            WAZUH_PASS=$(tar -xf "$TAR_PATH" -O \
                wazuh-install-files/wazuh-passwords.txt 2>/dev/null | \
                grep -A1 "api_username.*'wazuh'" | \
                grep "api_password" | \
                grep -oP "(?<=')[^']+(?=')" | tail -1)

            if [ -n "$WAZUH_PASS" ]; then
                log_ok "Mot de passe Wazuh detecte automatiquement"
                # Mettre a jour .env
                if grep -q "^WAZUH_PASSWORD=" "$ENV_FILE"; then
                    sed -i "s|^WAZUH_PASSWORD=.*|WAZUH_PASSWORD=${WAZUH_PASS}|" "$ENV_FILE"
                else
                    echo "WAZUH_PASSWORD=${WAZUH_PASS}" >> "$ENV_FILE"
                fi
                if grep -q "^WAZUH_USER=" "$ENV_FILE"; then
                    sed -i "s|^WAZUH_USER=.*|WAZUH_USER=wazuh|" "$ENV_FILE"
                else
                    echo "WAZUH_USER=wazuh" >> "$ENV_FILE"
                fi
                break
            fi
        fi
    done

    # Fallback : verifier si deja dans .env
    if [ -z "$WAZUH_PASS" ]; then
        WAZUH_PASS=$(grep "^WAZUH_PASSWORD=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2)
        if [ -n "$WAZUH_PASS" ]; then
            log_ok "Mot de passe Wazuh lu depuis .env"
        else
            log_warn "Mot de passe Wazuh non detecte automatiquement"
            log_warn "Vous pouvez le configurer manuellement apres installation :"
            log_warn "  sudo sed -i 's|^WAZUH_PASSWORD=.*|WAZUH_PASSWORD=VOTRE_MDP|' $ENV_FILE"
            log_warn "  sudo systemctl restart siem-agent"
        fi
    fi
}

# ── Etape 3 : Utilisateur systeme ────────────────────────────────
create_user() {
    log_etape "3/6" "CREATION UTILISATEUR SYSTEME"

    if id "$USER_AGENT" > /dev/null 2>&1; then
        log_info "Utilisateur $USER_AGENT existe deja"
    else
        useradd --system --no-create-home --shell /sbin/nologin \
                --comment "SIEM Africa - Agent Python" "$USER_AGENT"
        log_ok "Utilisateur $USER_AGENT cree (shell: /sbin/nologin)"
    fi
}

# ── Etape 4 : Installation dependances Python ────────────────────
install_deps() {
    log_etape "4/6" "INSTALLATION DEPENDANCES PYTHON"

    log_info "Installation des dependances systeme..."
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        python3-pip python3-dev build-essential libssl-dev \
        libffi-dev python3-setuptools > /dev/null 2>&1
    log_ok "Dependances systeme installees"

    log_info "Installation scikit-learn (Machine Learning)..."
    pip3 install --quiet scikit-learn numpy --break-system-packages 2>/dev/null || \
    pip3 install --quiet scikit-learn numpy 2>/dev/null || \
        log_warn "scikit-learn non installe — ML sera desactive"

    # Verifier que scikit-learn est disponible
    if python3 -c "from sklearn.ensemble import IsolationForest" > /dev/null 2>&1; then
        log_ok "scikit-learn installe — Machine Learning actif"
    else
        log_warn "scikit-learn non disponible — installez avec : pip3 install scikit-learn numpy"
    fi
}

# ── Etape 5 : Installation de l'agent ────────────────────────────
install_agent() {
    log_etape "5/6" "INSTALLATION DE L'AGENT"

    # Creer les dossiers
    mkdir -p "$AGENT_DIR"
    mkdir -p /var/log/siem-africa
    mkdir -p /opt/siem-africa/models

    # Copier l'agent
    cp "${SCRIPT_DIR}/agent.py" "${AGENT_DIR}/agent.py"
    log_ok "agent.py installe dans $AGENT_DIR"

    # Droits
    chown -R "${USER_AGENT}:${USER_AGENT}" "$AGENT_DIR"
    chown -R "${USER_AGENT}:${USER_AGENT}" /var/log/siem-africa
    chown -R "${USER_AGENT}:${USER_AGENT}" /opt/siem-africa/models
    chmod 750 "$AGENT_DIR"
    chmod 640 "${AGENT_DIR}/agent.py"
    chmod 755 /var/log/siem-africa

    # Donner acces a la base SQLite
    DB_PATH=$(grep "^DB_PATH=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 | tr -d '"' || echo "/opt/siem-africa/siem_africa.db")
    if [ -f "$DB_PATH" ]; then
        chmod 660 "$DB_PATH"
        OWNER=$(stat -c '%U' "$DB_PATH")
        chown "${OWNER}:${USER_AGENT}" "$DB_PATH"
        log_ok "Droits base SQLite configures"
    fi

    # Donner acces au .env
    chmod 640 "$ENV_FILE"
    ENV_OWNER=$(stat -c '%U' "$ENV_FILE")
    chown "${ENV_OWNER}:${USER_AGENT}" "$ENV_FILE"
    log_ok "Droits .env configures"

    # Donner acces aux logs Snort (lecture)
    if [ -d "/var/log/snort" ]; then
        setfacl -R -m u:"${USER_AGENT}":rX /var/log/snort 2>/dev/null || \
            chmod o+rX /var/log/snort
        log_ok "Acces logs Snort configure"
    fi

    # Creer le service systemd
    cat > /etc/systemd/system/siem-agent.service << SYSTEMD
[Unit]
Description=SIEM Africa Agent intelligent v2.0
Documentation=https://github.com/luciesys/SIEM-AFRICA
After=network.target wazuh-manager.service snort.service
Wants=wazuh-manager.service

[Service]
Type=simple
User=${USER_AGENT}
Group=${USER_AGENT}
WorkingDirectory=${AGENT_DIR}
ExecStart=/usr/bin/python3 ${AGENT_DIR}/agent.py
Restart=on-failure
RestartSec=10
StandardOutput=append:/var/log/siem-africa/agent.log
StandardError=append:/var/log/siem-africa/agent.log
Environment=PYTHONUNBUFFERED=1

# Securite
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/log/siem-africa /opt/siem-africa

[Install]
WantedBy=multi-user.target
SYSTEMD

    systemctl daemon-reload
    systemctl enable siem-agent
    log_ok "Service siem-agent configure et active"

    # Demarrer l'agent
    systemctl restart siem-agent 2>/dev/null || true
    sleep 3

    if systemctl is-active --quiet siem-agent; then
        log_ok "Service siem-agent ACTIF"
    else
        log_warn "Service non actif — verifier les logs : journalctl -u siem-agent -n 30"
    fi
}

# ── Etape 6 : Mise a jour credentials.txt ────────────────────────
update_credentials() {
    log_etape "6/6" "MISE A JOUR CREDENTIALS"

    WAZUH_PASS_CRED=$(grep "^WAZUH_PASSWORD=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || echo "voir .env")
    SERVER_IP=$(grep "^SERVER_IP=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || hostname -I | awk '{print $1}')

    cat >> "$CRED_FILE" << CREDS

── MODULE 3 — AGENT INTELLIGENT ─────────────────────────────
  Installe le : $(date '+%d/%m/%Y a %H:%M')

  Utilisateur systeme : ${USER_AGENT} (shell: /sbin/nologin)
  Dossier            : ${AGENT_DIR}
  Script             : ${AGENT_DIR}/agent.py
  Logs               : /var/log/siem-africa/agent.log
  Service            : siem-agent.service

  Wazuh API          : https://${SERVER_IP}:55000
  Wazuh user         : wazuh
  Wazuh password     : ${WAZUH_PASS_CRED}

── FONCTIONNALITES ACTIVES ───────────────────────────────────
  [OK] Polling Wazuh API (toutes les 10s)
  [OK] Enrichissement SQLite + MITRE ATT&CK
  [OK] Detection comportementale (5 regles)
  [OK] Correlation (simple + multi-etapes APT)
  [OK] Active Response (timer 5 min)
  [OK] Honeypot (SSH:2222 HTTP:8888 MySQL:3307)
  [OK] Notifications email SMTP
  [OK] Machine Learning Isolation Forest (apres 7 jours)

── COMMANDES UTILES ──────────────────────────────────────────
  Etat service   : systemctl status siem-agent
  Logs temps reel: tail -f /var/log/siem-africa/agent.log
  Redemarrer     : systemctl restart siem-agent
  Arreter        : systemctl stop siem-agent
  Changer MDP    : sed -i "s|^WAZUH_PASSWORD=.*|WAZUH_PASSWORD=NouveauMDP|" ${ENV_FILE}
                   systemctl restart siem-agent

── PROCHAINE ETAPE ───────────────────────────────────────────
  Module 4 — Dashboard Django
  Commande : cd ../dashboard && sudo bash install.sh

CREDS

    chmod 600 "$CRED_FILE"
    log_ok "credentials.txt mis a jour"
}

# ── Resume final ─────────────────────────────────────────────────
show_summary() {
    SERVER_IP=$(grep "^SERVER_IP=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || hostname -I | awk '{print $1}')

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     MODULE 3 — INSTALLATION TERMINEE AVEC SUCCES   ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}── ETAT DE L'AGENT ──────────────────────────────────${NC}"
    if systemctl is-active --quiet siem-agent; then
        echo -e "  ${GREEN}[ACTIF]${NC}  siem-agent"
    else
        echo -e "  ${RED}[INACTIF]${NC} siem-agent"
    fi
    echo ""
    echo -e "${CYAN}── FONCTIONNALITES ──────────────────────────────────${NC}"
    echo -e "  ${GREEN}[OK]${NC} Polling Wazuh toutes les 10 secondes"
    echo -e "  ${GREEN}[OK]${NC} Enrichissement 380 signatures + MITRE ATT&CK"
    echo -e "  ${GREEN}[OK]${NC} Detection comportementale (5 regles)"
    echo -e "  ${GREEN}[OK]${NC} Correlation simple + multi-etapes APT"
    echo -e "  ${GREEN}[OK]${NC} Active Response timer 5 minutes"
    echo -e "  ${GREEN}[OK]${NC} Honeypot SSH:2222 HTTP:8888 MySQL:3307"
    echo -e "  ${GREEN}[OK]${NC} Notifications email SMTP"
    if python3 -c "import sklearn" 2>/dev/null; then
        echo -e "  ${GREEN}[OK]${NC} Machine Learning Isolation Forest"
    else
        echo -e "  ${YELLOW}[--]${NC} Machine Learning (installer scikit-learn)"
    fi
    echo ""
    echo -e "${CYAN}── LOGS ET SUPERVISION ──────────────────────────────${NC}"
    echo -e "  tail -f /var/log/siem-africa/agent.log"
    echo -e "  journalctl -u siem-agent -f"
    echo ""
    echo -e "${CYAN}── PROCHAINE ETAPE ──────────────────────────────────${NC}"
    echo -e "  ${YELLOW}cd ../dashboard && sudo bash install.sh${NC}"
    echo ""
}

# ── MAIN ─────────────────────────────────────────────────────────
main() {
    echo "=== SIEM Africa Module 3 - $(date) ===" >> "$LOG_FILE"
    show_banner
    check_all
    detect_wazuh_password
    create_user
    install_deps
    install_agent
    update_credentials
    show_summary
    log_info "Module 3 installe — $(date)"
}

main "$@"
