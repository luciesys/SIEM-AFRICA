#!/bin/bash
# ================================================================
#  SIEM Africa — Module 3 : Agent intelligent
#  Fichier  : agent/install.sh
#
# ================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

LOG_FILE="/var/log/siem-africa-install.log"
AGENT_DIR="/opt/siem-africa/agent"
ENV_FILE="/opt/siem-africa/.env"
CRED_FILE="/opt/siem-africa/credentials.txt"
DB_PATH=""
USER_AGENT="siem-agent"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAZUH_PASS=""

log()       { echo -e "$1" | tee -a "$LOG_FILE"; }
log_ok()    { log "${GREEN}[OK]${NC} $1"; }
log_info()  { log "${CYAN}[INFO]${NC} $1"; }
log_warn()  { log "${YELLOW}[ATTENTION]${NC} $1"; }
log_etape() { log "${BLUE}[ETAPE $1]${NC} $2"; }
log_err()   { log "${RED}[ERREUR]${NC} $1"; }

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
    echo "║       Agent intelligent v2.1                        ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}


# ── Desinstallation propre si deja installe ────────────────────────
desinstaller_si_present() {
    local deja_installe=0

    # Verifier si le service existe
    if systemctl list-unit-files siem-agent.service &>/dev/null 2>&1; then
        deja_installe=1
    fi
    # Verifier si le dossier existe
    if [ -d "/opt/siem-africa/agent" ]; then
        deja_installe=1
    fi

    if [ "$deja_installe" -eq 0 ]; then
        log_info "Aucune installation precedente detectee — installation normale"
        return 0
    fi

    echo ""
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  Installation precedente du Module 3 detectee !     ║${NC}"
    echo -e "${YELLOW}║  Elle va etre supprimee avant reinstallation.       ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    log_info "Suppression de l'ancienne installation..."

    # Arreter et desactiver le service
    if systemctl is-active --quiet siem-agent 2>/dev/null; then
        systemctl stop siem-agent
        log_ok "Service siem-agent arrete"
    fi
    if systemctl is-enabled --quiet siem-agent 2>/dev/null; then
        systemctl disable siem-agent
        log_ok "Service siem-agent desactive"
    fi

    # Supprimer le fichier service
    if [ -f "/etc/systemd/system/siem-agent.service" ]; then
        rm -f /etc/systemd/system/siem-agent.service
        systemctl daemon-reload
        log_ok "Fichier service supprime"
    fi

    # Supprimer les fichiers de l'agent
    if [ -d "/opt/siem-africa/agent" ]; then
        rm -rf /opt/siem-africa/agent
        log_ok "Dossier /opt/siem-africa/agent supprime"
    fi

    # Supprimer les modeles ML
    if [ -d "/opt/siem-africa/models" ]; then
        rm -rf /opt/siem-africa/models
        log_ok "Modeles ML supprimes"
    fi

    # Archiver les anciens logs (ne pas supprimer — utile pour le debug)
    if [ -f "/var/log/siem-africa/agent.log" ]; then
        mv /var/log/siem-africa/agent.log            "/var/log/siem-africa/agent.log.$(date +%Y%m%d_%H%M%S).bak"
        log_ok "Anciens logs archives"
    fi

    # Supprimer l'utilisateur systeme
    if id "siem-agent" &>/dev/null 2>&1; then
        userdel siem-agent 2>/dev/null || true
        log_ok "Utilisateur siem-agent supprime"
    fi

    log_ok "Ancienne installation supprimee — reinstallation en cours..."
    echo ""
    sleep 2
}

# ── Etape 1 : Verifications ───────────────────────────────────────
check_all() {
    log_etape "1/6" "VERIFICATIONS"

    [ "$EUID" -ne 0 ] && quitter "sudo requis"
    log_ok "Root confirme"

    [ ! -f "$ENV_FILE" ] && quitter "Module 1 non installe"
    log_ok "Module 1 detecte"

    DB_PATH=$(grep "^DB_PATH=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 | tr -d '"' | tr -d "'" | xargs)
    [ -z "$DB_PATH" ] && DB_PATH="/opt/siem-africa/siem_africa.db"
    [ ! -f "$DB_PATH" ] && quitter "Base SQLite non trouvee — lancez database/install.sh"
    log_ok "Base SQLite : $DB_PATH"

    NB_SIG=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM attaques;" 2>/dev/null || echo "0")
    [ "${NB_SIG:-0}" -lt 1 ] && quitter "Table attaques vide"
    log_ok "Signatures : $NB_SIG"

    # Telecharger agent.py automatiquement si absent
    if [ ! -f "${SCRIPT_DIR}/agent.py" ]; then
        log_warn "agent.py absent — telechargement automatique..."
        curl -sL "https://raw.githubusercontent.com/luciesys/SIEM-AFRICA/main/agent/agent.py" \
             -o "${SCRIPT_DIR}/agent.py" 2>/dev/null || true
        [ ! -f "${SCRIPT_DIR}/agent.py" ] && quitter "agent.py introuvable"
        log_ok "agent.py telecharge"
    else
        log_ok "agent.py present"
    fi

    python3 --version > /dev/null 2>&1 || quitter "Python3 non installe"
    log_ok "Python3 OK"
}

# ── Etape 2 : Detection MDP Wazuh (4 methodes) ────────────────────
detect_wazuh_password() {
    log_etape "2/6" "DETECTION MOT DE PASSE WAZUH"
    WAZUH_PASS=""

    # Methode 1 : wazuh-install-files.tar
    for TAR_PATH in /root/wazuh-install-files.tar /tmp/wazuh-install-files.tar; do
        if [ -f "$TAR_PATH" ]; then
            log_info "Lecture $TAR_PATH..."
            # Format 1
            WAZUH_PASS=$(tar -xf "$TAR_PATH" -O \
                wazuh-install-files/wazuh-passwords.txt 2>/dev/null | \
                grep -A2 "api_username.*wazuh" | grep -i "password" | \
                grep -oP "(?<=')[^']+(?=')" | head -1)
            # Format 2
            if [ -z "$WAZUH_PASS" ]; then
                tar -xf "$TAR_PATH" -C /tmp \
                    wazuh-install-files/wazuh-passwords.txt 2>/dev/null || true
                [ -f "/tmp/wazuh-install-files/wazuh-passwords.txt" ] && \
                    WAZUH_PASS=$(grep -A2 "api_username.*wazuh" \
                        /tmp/wazuh-install-files/wazuh-passwords.txt | \
                        grep -i "password" | grep -oP "(?<=')[^']+(?=')" | head -1)
            fi
            [ -n "$WAZUH_PASS" ] && { log_ok "MDP detecte depuis tar"; break; }
        fi
    done

    # Methode 2 : deja dans .env
    if [ -z "$WAZUH_PASS" ]; then
        WAZUH_PASS=$(grep "^WAZUH_PASSWORD=" "$ENV_FILE" 2>/dev/null | \
                     cut -d'=' -f2 | tr -d '"' | tr -d "'" | xargs)
        [ -n "$WAZUH_PASS" ] && log_ok "MDP lu depuis .env"
    fi

    # Methode 3 : wazuh-passwords.txt direct
    if [ -z "$WAZUH_PASS" ]; then
        for PWD_FILE in /root/wazuh-passwords.txt /opt/wazuh-install-files/wazuh-passwords.txt; do
            [ -f "$PWD_FILE" ] && \
                WAZUH_PASS=$(grep -A2 "api_username.*wazuh" "$PWD_FILE" | \
                    grep -i "password" | grep -oP "(?<=')[^']+(?=')" | head -1)
            [ -n "$WAZUH_PASS" ] && { log_ok "MDP lu depuis $PWD_FILE"; break; }
        done
    fi

    # Methode 4 : saisie manuelle
    if [ -z "$WAZUH_PASS" ]; then
        echo ""
        log_warn "MDP Wazuh non detecte automatiquement."
        echo -n "  Entrez le MDP Wazuh API (Entree pour ignorer) : "
        read -s WAZUH_PASS_INPUT
        echo ""
        if [ -n "$WAZUH_PASS_INPUT" ]; then
            WAZUH_PASS="$WAZUH_PASS_INPUT"
            log_ok "MDP saisi manuellement"
        else
            log_warn "MDP non configure — modifiez $ENV_FILE apres installation"
        fi
    fi

    # Sauvegarder
    if [ -n "$WAZUH_PASS" ]; then
        if grep -q "^WAZUH_PASSWORD=" "$ENV_FILE"; then
            sed -i "s|^WAZUH_PASSWORD=.*|WAZUH_PASSWORD=${WAZUH_PASS}|" "$ENV_FILE"
        else
            echo "WAZUH_PASSWORD=${WAZUH_PASS}" >> "$ENV_FILE"
        fi
        grep -q "^WAZUH_USER=" "$ENV_FILE" && \
            sed -i "s|^WAZUH_USER=.*|WAZUH_USER=wazuh|" "$ENV_FILE" || \
            echo "WAZUH_USER=wazuh" >> "$ENV_FILE"
        log_ok "MDP sauvegarde dans .env"
    fi
}

# ── Etape 3 : Utilisateur systeme ─────────────────────────────────
create_user() {
    log_etape "3/6" "CREATION UTILISATEUR SYSTEME"
    if id "$USER_AGENT" > /dev/null 2>&1; then
        log_info "Utilisateur $USER_AGENT existe"
    else
        useradd --system --no-create-home --shell /sbin/nologin \
                --comment "SIEM Africa Agent" "$USER_AGENT"
        log_ok "Utilisateur $USER_AGENT cree"
    fi
}

# ── Etape 4 : Dependances Python ──────────────────────────────────
install_deps() {
    log_etape "4/6" "DEPENDANCES PYTHON"
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        python3-pip python3-dev build-essential libssl-dev > /dev/null 2>&1
    log_ok "Dependances systeme installees"

    pip3 install --quiet scikit-learn numpy --break-system-packages 2>/dev/null || \
    pip3 install --quiet scikit-learn numpy 2>/dev/null || \
        log_warn "scikit-learn non installe — ML desactive"

    python3 -c "from sklearn.ensemble import IsolationForest" 2>/dev/null && \
        log_ok "scikit-learn OK — ML actif" || log_warn "ML desactive"
}

# ── Etape 5 : Installation + permissions corrigees ────────────────
install_agent() {
    log_etape "5/6" "INSTALLATION DE L'AGENT"

    mkdir -p "$AGENT_DIR" /var/log/siem-africa /opt/siem-africa/models

    # CORRECTION [5] : dossier parent doit etre 755
    # sinon systemd ne peut pas faire le CHDIR vers agent/
    chmod 755 /opt/siem-africa/
    log_ok "chmod 755 /opt/siem-africa/ (correction CHDIR)"

    # Copier l'agent
    cp "${SCRIPT_DIR}/agent.py" "${AGENT_DIR}/agent.py"
    log_ok "agent.py copie dans $AGENT_DIR"

    # CORRECTION [4] : 755 au lieu de 750
    # 750 empechait l'utilisateur siem-agent d'entrer dans le dossier
    chown -R "${USER_AGENT}:${USER_AGENT}" "$AGENT_DIR"
    chmod 755 "$AGENT_DIR"
    chmod 644 "${AGENT_DIR}/agent.py"
    log_ok "chmod 755 $AGENT_DIR (correction CHDIR)"

    # Logs
    chown -R "${USER_AGENT}:${USER_AGENT}" /var/log/siem-africa
    chmod 755 /var/log/siem-africa
    touch /var/log/siem-africa/agent.log
    chown "${USER_AGENT}:${USER_AGENT}" /var/log/siem-africa/agent.log
    chmod 644 /var/log/siem-africa/agent.log

    # Models ML
    chown -R "${USER_AGENT}:${USER_AGENT}" /opt/siem-africa/models
    chmod 755 /opt/siem-africa/models

    # SQLite
    DB_PATH=$(grep "^DB_PATH=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 | tr -d '"' | xargs)
    [ -z "$DB_PATH" ] && DB_PATH="/opt/siem-africa/siem_africa.db"
    if [ -f "$DB_PATH" ]; then
        chown "$(stat -c '%U' "$DB_PATH"):${USER_AGENT}" "$DB_PATH"
        chmod 664 "$DB_PATH"
        log_ok "Acces SQLite configure"
    fi

    # .env
    chown "root:${USER_AGENT}" "$ENV_FILE"
    chmod 640 "$ENV_FILE"
    log_ok "Acces .env configure"

    # Logs Snort
    if [ -d "/var/log/snort" ]; then
        setfacl -R -m u:"${USER_AGENT}":rX /var/log/snort 2>/dev/null || \
            chmod o+rX /var/log/snort 2>/dev/null || true
    fi

    # ── Service systemd ───────────────────────────────────────────
    # CORRECTIONS [1][2][3] :
    # ProtectSystem=strict, PrivateTmp=yes et NoNewPrivileges=yes
    # ont ete SUPPRIMES car ils causaient tous l'erreur CHDIR 200.
    # Ces options empechaient systemd d'acceder a /opt/siem-africa/
    cat > /etc/systemd/system/siem-agent.service << SYSTEMD
[Unit]
Description=SIEM Africa Agent intelligent v2.1
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

[Install]
WantedBy=multi-user.target
SYSTEMD

    systemctl daemon-reload
    systemctl enable siem-agent
    log_ok "Service siem-agent cree"

    # Demarrer
    systemctl stop siem-agent 2>/dev/null || true
    sleep 1
    systemctl start siem-agent 2>/dev/null || true
    sleep 4

    if systemctl is-active --quiet siem-agent; then
        log_ok "Service siem-agent ACTIF"
    else
        log_warn "Service non actif — diagnostic..."
        _diagnostic
    fi
}

_diagnostic() {
    echo ""
    log_info "=== DIAGNOSTIC ==="
    log_info "Permissions :"
    ls -la /opt/siem-africa/ 2>/dev/null | tee -a "$LOG_FILE"
    ls -la "$AGENT_DIR/" 2>/dev/null | tee -a "$LOG_FILE"

    log_info "Test acces par $USER_AGENT :"
    if sudo -u "$USER_AGENT" test -r "${AGENT_DIR}/agent.py" 2>/dev/null; then
        log_ok "agent.py lisible"
    else
        log_err "agent.py non lisible — correction..."
        chmod 644 "${AGENT_DIR}/agent.py"
        chown "${USER_AGENT}:${USER_AGENT}" "${AGENT_DIR}/agent.py"
    fi

    log_info "Erreur Python :"
    timeout 5 sudo -u "$USER_AGENT" \
        python3 "${AGENT_DIR}/agent.py" 2>&1 | head -5 | tee -a "$LOG_FILE" || true

    systemctl restart siem-agent 2>/dev/null || true
    sleep 3
    if systemctl is-active --quiet siem-agent; then
        log_ok "Service actif apres correction"
    else
        echo ""
        log_warn "Commandes de diagnostic :"
        echo "  journalctl -u siem-agent -n 30"
        echo "  cat /var/log/siem-africa/agent.log"
        echo ""
        log_warn "Si MDP Wazuh manquant :"
        echo "  sudo nano $ENV_FILE"
        echo "  -> WAZUH_PASSWORD=votre_mdp"
        echo "  sudo systemctl restart siem-agent"
    fi
    echo ""
}

# ── Etape 6 : Credentials ─────────────────────────────────────────
update_credentials() {
    log_etape "6/6" "CREDENTIALS"
    WAZUH_PASS_CRED=$(grep "^WAZUH_PASSWORD=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 | xargs || echo "non configure")
    SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")

    cat >> "$CRED_FILE" << CREDS

── MODULE 3 — AGENT INTELLIGENT (v2.1) ──────────────────────
  Installe le : $(date '+%d/%m/%Y a %H:%M')
  Dossier     : ${AGENT_DIR}
  Logs        : /var/log/siem-africa/agent.log
  Wazuh API   : https://${SERVER_IP}:55000
  Wazuh MDP   : ${WAZUH_PASS_CRED}

  Etat        : systemctl status siem-agent
  Logs live   : tail -f /var/log/siem-africa/agent.log
  MDP Wazuh   : sudo nano ${ENV_FILE} -> WAZUH_PASSWORD=...
                sudo systemctl restart siem-agent
CREDS

    chmod 600 "$CRED_FILE"
    log_ok "credentials.txt mis a jour"
}

# ── Resume ────────────────────────────────────────────────────────
show_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     MODULE 3 — INSTALLATION TERMINEE                ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    if systemctl is-active --quiet siem-agent; then
        echo -e "  ${GREEN}[ACTIF]${NC}  siem-agent"
    else
        echo -e "  ${RED}[INACTIF]${NC} siem-agent -> journalctl -u siem-agent -n 30"
    fi
    WAZUH_PASS_CRED=$(grep "^WAZUH_PASSWORD=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 | xargs)
    if [ -n "$WAZUH_PASS_CRED" ]; then
        echo -e "  ${GREEN}[OK]${NC}     MDP Wazuh configure"
    else
        echo -e "  ${YELLOW}[--]${NC}     MDP Wazuh manquant -> nano $ENV_FILE"
    fi
    echo ""
    python3 -c "import sklearn" 2>/dev/null && \
        echo -e "  ${GREEN}[OK]${NC} Machine Learning actif" || \
        echo -e "  ${YELLOW}[--]${NC} ML desactive (pip3 install scikit-learn)"
    echo ""
    echo -e "  tail -f /var/log/siem-africa/agent.log"
    echo ""
}

# ── MAIN ──────────────────────────────────────────────────────────
main() {
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    echo "=== SIEM Africa Module 3 v2.1 - $(date) ===" >> "$LOG_FILE"
    show_banner
    desinstaller_si_present
    check_all
    detect_wazuh_password
    create_user
    install_deps
    install_agent
    update_credentials
    show_summary
    log_info "Module 3 termine — $(date)"
}

main "$@"
