#!/bin/bash
# ================================================================
#  SIEM Africa — Module 1 : Installation Snort + Wazuh
#  Fichier  : installation/install.sh
#  Version  : 2.2 — Refonte complete
#  Usage    : sudo bash install.sh
#
#  Corrections v2.2 :
#  - Groupe siem-africa cree en premier (resout tous les pb droits)
#  - Wazuh Manager uniquement (pas d'indexer ni dashboard Wazuh)
#  - Sans set -e — gestion d'erreurs explicite
#  - Permissions /opt/siem-africa/ correctes des le depart
#  - Detection interface reseau automatique
# ================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

LOG_FILE="/var/log/siem-africa-install.log"
ENV_FILE="/opt/siem-africa/.env"
CRED_FILE="/opt/siem-africa/credentials.txt"
OPT_DIR="/opt/siem-africa"
GROUPE="siem-africa"
USER_PRINCIPAL="siem-africa"
WAZUH_VERSION="4.x"
WAZUH_MODE="manager-only"  # Manager uniquement
MIN_RAM=4
MIN_DISK=60

log()        { echo -e "$1" | tee -a "$LOG_FILE"; }
log_ok()     { log "${GREEN}[OK]${NC} $1"; }
log_info()   { log "${CYAN}[INFO]${NC} $1"; }
log_warn()   { log "${YELLOW}[ATTENTION]${NC} $1"; }
log_etape()  { log "\n${BLUE}━━━ ETAPE $1 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }
log_err()    { log "${RED}[ERREUR]${NC} $1"; }

quitter() {
    log_err "$1"
    echo -e "\n${RED}Installation arretee. Journal : $LOG_FILE${NC}"
    exit 1
}

show_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║       SIEM Africa — Module 1 v2.2                   ║"
    echo "  ║       Installation Snort + Wazuh Manager Only       ║"
    echo "  ║       github.com/luciesys/SIEM-AFRICA               ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ================================================================
# ETAPE 1 : Verifications systeme
# ================================================================
check_systeme() {
    log_etape "1/7" "VERIFICATIONS SYSTEME"

    # Root
    [ "$EUID" -ne 0 ] && quitter "Lancez avec : sudo bash install.sh"
    log_ok "Root confirme"

    # OS
    [ ! -f /etc/os-release ] && quitter "OS non detecte"
    . /etc/os-release
    case "$ID" in
        ubuntu)
            case "$VERSION_ID" in
                20.04|22.04|24.04) log_ok "Ubuntu $VERSION_ID supporte" ;;
                *) quitter "Ubuntu $VERSION_ID non supporte (requis: 20.04/22.04/24.04)" ;;
            esac ;;
        debian)
            case "$VERSION_ID" in
                11|12) log_ok "Debian $VERSION_ID supporte" ;;
                *) quitter "Debian $VERSION_ID non supporte (requis: 11/12)" ;;
            esac ;;
        *) quitter "OS non supporte : $ID (requis: Ubuntu ou Debian)" ;;
    esac

    # RAM
    RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
    if [ "${RAM_GB:-0}" -lt "$MIN_RAM" ]; then
        quitter "RAM insuffisante : ${RAM_GB}GB (minimum ${MIN_RAM}GB requis)"
    fi
    log_ok "RAM : ${RAM_GB}GB"

    # Disque
    DISK_GB=$(df -BG / | awk 'NR==2{gsub("G","",$4); print $4}')
    if [ "${DISK_GB:-0}" -lt "$MIN_DISK" ]; then
        quitter "Disque insuffisant : ${DISK_GB}GB libres (minimum ${MIN_DISK}GB)"
    fi
    log_ok "Disque : ${DISK_GB}GB libres"

    # Internet
    ping -c 2 8.8.8.8 > /dev/null 2>&1 || quitter "Pas de connexion internet"
    log_ok "Connexion internet OK"

    # Detection interface reseau
    INTERFACE=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
    [ -z "$INTERFACE" ] && INTERFACE=$(ip link show | grep -v lo | grep "state UP" | \
        awk -F': ' '{print $2}' | head -1)
    [ -z "$INTERFACE" ] && INTERFACE="eth0"
    log_ok "Interface reseau : $INTERFACE"

    # IP du serveur
    SERVER_IP=$(hostname -I | awk '{print $1}')
    log_ok "IP serveur : $SERVER_IP"
}

# ================================================================
# ETAPE 2 : Creation groupe et structure de base
# ================================================================
setup_base() {
    log_etape "2/7" "CREATION GROUPE ET STRUCTURE"

    # ── Groupe central siem-africa ────────────────────────────────
    # Ce groupe sera partage par TOUS les services SIEM Africa
    # Cela resout definitivement les problemes de droits SQLite
    if getent group "$GROUPE" > /dev/null 2>&1; then
        log_info "Groupe $GROUPE existe deja"
    else
        groupadd --system "$GROUPE"
        log_ok "Groupe $GROUPE cree"
    fi

    # ── Utilisateur principal ─────────────────────────────────────
    if id "$USER_PRINCIPAL" > /dev/null 2>&1; then
        log_info "Utilisateur $USER_PRINCIPAL existe deja"
    else
        useradd --system --no-create-home --shell /sbin/nologin \
                --gid "$GROUPE" \
                --comment "SIEM Africa - Proprietaire principal" \
                "$USER_PRINCIPAL"
        log_ok "Utilisateur $USER_PRINCIPAL cree"
    fi

    # ── Dossier principal /opt/siem-africa/ ───────────────────────
    mkdir -p "$OPT_DIR"
    mkdir -p "$OPT_DIR/rapports"
    mkdir -p "$OPT_DIR/models"
    mkdir -p /var/log/siem-africa

    # Permissions correctes des le depart
    # 775 = le groupe siem-africa peut lire ET ecrire
    chown -R "${USER_PRINCIPAL}:${GROUPE}" "$OPT_DIR"
    chmod 775 "$OPT_DIR"
    chmod 775 "$OPT_DIR/rapports"
    chmod 775 "$OPT_DIR/models"
    chmod 755 /var/log/siem-africa
    log_ok "Dossier $OPT_DIR cree (chmod 775, groupe $GROUPE)"

    # ── Fichier .env ──────────────────────────────────────────────
    cat > "$ENV_FILE" << ENV
# ================================================================
#  SIEM Africa — Configuration
#  Genere automatiquement le $(date '+%d/%m/%Y a %H:%M')
# ================================================================

# Reseau
SERVER_IP=${SERVER_IP}
INTERFACE=${INTERFACE}

# Base de donnees
DB_PATH=/opt/siem-africa/siem_africa.db

# Wazuh
WAZUH_HOST=127.0.0.1
WAZUH_PORT=55000
WAZUH_USER=wazuh
WAZUH_PASSWORD=
WAZUH_ALERTS_LOG=/var/ossec/logs/alerts/alerts.json

# Agent
POLLING_INTERVAL=10
CORRELATION_WINDOW=60
CORRELATION_THRESHOLD=3
ACTIVE_RESPONSE_DELAY=300
HONEYPOT_ENABLED=1
HONEYPOT_SSH_PORT=2222
HONEYPOT_HTTP_PORT=8888
HONEYPOT_MYSQL_PORT=3307
ML_APPRENTISSAGE_JOURS=7

# Notifications
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
ALERT_EMAIL=

# Organisation
ORG_NOM=Mon Entreprise
LANG=fr

# Rapports
REPORTS_DIR=/opt/siem-africa/rapports

# Cle secrete Django (generee automatiquement)
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")
ENV

    chown "${USER_PRINCIPAL}:${GROUPE}" "$ENV_FILE"
    chmod 660 "$ENV_FILE"
    log_ok "Fichier .env cree"

    # ── Fichier credentials.txt ───────────────────────────────────
    cat > "$CRED_FILE" << CREDS
================================================================
  SIEM Africa — Fichier d'acces
  Genere le : $(date '+%d/%m/%Y a %H:%M')
  CONFIDENTIEL — Ne pas partager
================================================================

── INFORMATIONS SERVEUR ──────────────────────────────────────
  IP serveur    : ${SERVER_IP}
  Interface     : ${INTERFACE}
  OS            : ${PRETTY_NAME:-Ubuntu}

CREDS

    chown "${USER_PRINCIPAL}:${GROUPE}" "$CRED_FILE"
    chmod 640 "$CRED_FILE"
    log_ok "Fichier credentials.txt cree"
}

# ================================================================
# ETAPE 3 : Installation Snort
# ================================================================
install_snort() {
    log_etape "3/7" "INSTALLATION SNORT"

    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        snort \
        snort-rules-default \
        libpcap-dev \
        libpcre3-dev \
        libdumbnet-dev \
        build-essential > /dev/null 2>&1

    if command -v snort > /dev/null 2>&1; then
        SNORT_VER=$(snort --version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1)
        log_ok "Snort installe : version $SNORT_VER"
    else
        log_warn "Snort non disponible via apt — tentative depuis les sources..."
        _install_snort_source
    fi

    # Configuration Snort
    _configurer_snort

    # Creer l'utilisateur snort
    if ! id "snort" > /dev/null 2>&1; then
        useradd --system --no-create-home --shell /sbin/nologin snort
        log_ok "Utilisateur snort cree"
    fi
    usermod -aG "$GROUPE" snort
    log_ok "Utilisateur snort ajoute au groupe $GROUPE"

    # Service systemd Snort
    cat > /etc/systemd/system/snort.service << SNORTSVC
[Unit]
Description=SIEM Africa — Snort IDS
After=network.target

[Service]
Type=simple
User=snort
Group=snort
ExecStart=/usr/sbin/snort -q -u snort -g snort \
    -c /etc/snort/snort.conf \
    -i ${INTERFACE} \
    -l /var/log/snort \
    -A fast
Restart=on-failure
RestartSec=10
StandardOutput=append:/var/log/siem-africa/snort.log
StandardError=append:/var/log/siem-africa/snort.log

[Install]
WantedBy=multi-user.target
SNORTSVC

    systemctl daemon-reload
    systemctl enable snort 2>/dev/null || true
    systemctl restart snort 2>/dev/null || true
    sleep 2

    if systemctl is-active --quiet snort; then
        log_ok "Service Snort ACTIF"
    else
        log_warn "Service Snort non actif — verifier : journalctl -u snort -n 10"
    fi
}

_install_snort_source() {
    log_info "Installation Snort depuis les depots officiels..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        snort 2>/dev/null || \
    apt-get install -y -qq snort 2>/dev/null || \
        log_warn "Snort non installe — installation manuelle requise"
}

_configurer_snort() {
    # Creer les dossiers necessaires
    mkdir -p /var/log/snort
    mkdir -p /etc/snort/rules
    mkdir -p /etc/snort/so_rules
    mkdir -p /etc/snort/preproc_rules

    # Determiner l'IP du reseau local
    LOCAL_NET=$(ip -4 addr show "$INTERFACE" 2>/dev/null | \
        grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+/\d+' | head -1)
    [ -z "$LOCAL_NET" ] && LOCAL_NET="192.168.0.0/16"

    # Configuration minimale Snort
    SNORT_CONF="/etc/snort/snort.conf"
    if [ -f "$SNORT_CONF" ]; then
        # Mettre a jour le reseau local
        sed -i "s|^ipvar HOME_NET.*|ipvar HOME_NET ${LOCAL_NET}|" "$SNORT_CONF" \
            2>/dev/null || true
        log_ok "Configuration Snort mise a jour (HOME_NET: $LOCAL_NET)"
    else
        cat > "$SNORT_CONF" << SNORTCONF
# SIEM Africa — Configuration Snort minimale
ipvar HOME_NET ${LOCAL_NET}
ipvar EXTERNAL_NET !\$HOME_NET
var RULE_PATH /etc/snort/rules
var SO_RULE_PATH /etc/snort/so_rules
var PREPROC_RULE_PATH /etc/snort/preproc_rules
var WHITE_LIST_PATH /etc/snort/rules
var BLACK_LIST_PATH /etc/snort/rules

# Output
output alert_fast: /var/log/snort/alert
output log_unified2: filename snort.log, limit 128

# Preprocesseurs
preprocessor frag3_global: max_frags 65536
preprocessor stream5_global: track_tcp yes, track_udp yes
preprocessor stream5_tcp: policy first, detect_anomalies, \
    require_3whs 180, overlap_limit 10, \
    small_segments 3 bytes 150, timeout 180

# Detection
config detection: search-method ac-split search-optimize max-pattern-len 20

# Regles
include \$RULE_PATH/local.rules
SNORTCONF
        # Regles locales vides par defaut
        touch /etc/snort/rules/local.rules
        log_ok "Configuration Snort creee"
    fi

    # Acces logs pour le groupe siem-africa
    chown -R snort:snort /var/log/snort
    chmod 775 /var/log/snort
    setfacl -R -m g:"${GROUPE}":rX /var/log/snort 2>/dev/null || \
        chmod o+rX /var/log/snort 2>/dev/null || true
    log_ok "Acces logs Snort configure pour groupe $GROUPE"
}

# ================================================================
# ETAPE 4 : Installation Wazuh Manager uniquement
#           Mode leger — sans Indexer ni Dashboard
# ================================================================
install_wazuh() {
    log_etape "4/7" "INSTALLATION WAZUH MANAGER (mode leger)"
    log_info "Installation : Wazuh Manager uniquement — sans Indexer ni Dashboard"
    log_warn "Cette etape prend 10 a 20 minutes selon votre connexion."
    echo ""

    # URL officielle Wazuh
    WAZUH_SCRIPT_URL="https://packages.wazuh.com/4.14/wazuh-install.sh"

    log_info "Telechargement depuis $WAZUH_SCRIPT_URL ..."
    curl -sL "$WAZUH_SCRIPT_URL" -o wazuh-install.sh 2>/dev/null || \
    wget -q  "$WAZUH_SCRIPT_URL" -O wazuh-install.sh 2>/dev/null || \
        quitter "Impossible de telecharger le script Wazuh — verifiez votre connexion"

    # Verifier que c'est bien un script bash et pas une page d'erreur XML HTML
    [ ! -f wazuh-install.sh ] && quitter "Fichier wazuh-install.sh absent"
    FIRST_LINE=$(head -1 wazuh-install.sh)
    echo "$FIRST_LINE" | grep -q "^#!" || \
        quitter "Fichier telecharge invalide (page erreur XML ?). Verifiez connexion internet."

    chmod +x wazuh-install.sh
    log_ok "Script Wazuh telecharge et valide"

    # -wm = Wazuh Manager uniquement
    log_info "Lancement installation Wazuh Manager..."
    bash wazuh-install.sh -wm 2>&1 | tee -a "$LOG_FILE" | \
        grep -E "INFO|ERROR|WARNING|Starting|Complete|Password" || true

    # Verifier l'installation
    if [ ! -d /var/ossec ]; then
        quitter "Wazuh Manager non installe — verifier le journal"
    fi

    WAZUH_VER=$(/var/ossec/bin/wazuh-control info 2>/dev/null | \
        grep WAZUH_VERSION | cut -d'=' -f2 | tr -d '"' || echo "?")
    log_ok "Wazuh Manager installe : $WAZUH_VER"

    # Verifier le service
    if systemctl is-active --quiet wazuh-manager 2>/dev/null; then
        log_ok "Service wazuh-manager ACTIF"
    else
        log_warn "Service wazuh-manager non actif"
    fi

    # Configuration supplementaire
    _configurer_wazuh
}

_configurer_wazuh() {
    log_info "Configuration Wazuh Manager..."

    # Ajouter les sources de logs pour SIEM Africa
    OSSEC_CONF="/var/ossec/etc/ossec.conf"

    # Activer la sortie JSON des alertes (requis pour notre agent)
    if [ -f "$OSSEC_CONF" ]; then
        # Verifier si le JSON output est deja configure
        if ! grep -q "alerts.json" "$OSSEC_CONF"; then
            # Ajouter avant la balise </ossec_config>
            sed -i 's|</ossec_config>|  <logging>\n    <log_alert_level>1</log_alert_level>\n  </logging>\n\n  <global>\n    <jsonout_output>yes</jsonout_output>\n    <alerts_log>yes</alerts_log>\n    <logall>no</logall>\n    <logall_json>no</logall_json>\n    <email_notification>no</email_notification>\n  </global>\n\n</ossec_config>|' \
                "$OSSEC_CONF" 2>/dev/null || true
        fi

        # Ajouter les localfiles Snort si pas deja presents
        if ! grep -q "snort" "$OSSEC_CONF" 2>/dev/null; then
            sed -i 's|</ossec_config>|  <!-- Logs Snort -->\n  <localfile>\n    <log_format>snort-fast</log_format>\n    <location>/var/log/snort/alert</location>\n  </localfile>\n\n  <!-- Logs systeme -->\n  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/auth.log</location>\n  </localfile>\n\n  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/syslog</location>\n  </localfile>\n\n</ossec_config>|' \
                "$OSSEC_CONF" 2>/dev/null || true
        fi
        log_ok "Configuration Wazuh mise a jour (JSON + Snort + logs systeme)"
    fi

    # Creer le dossier alerts si inexistant
    mkdir -p /var/ossec/logs/alerts
    chown -R wazuh:wazuh /var/ossec/logs 2>/dev/null || true

    # Acces au fichier alerts.json pour le groupe siem-africa
    chmod 755 /var/ossec/logs/alerts 2>/dev/null || true
    # Le fichier sera cree par Wazuh quand il detectera des alertes
    touch /var/ossec/logs/alerts/alerts.json 2>/dev/null || true
    chown wazuh:wazuh /var/ossec/logs/alerts/alerts.json 2>/dev/null || true
    chmod 664 /var/ossec/logs/alerts/alerts.json 2>/dev/null || true
    setfacl -m g:"${GROUPE}":r /var/ossec/logs/alerts/alerts.json 2>/dev/null || \
        chmod o+r /var/ossec/logs/alerts/alerts.json 2>/dev/null || true
    log_ok "Acces alerts.json configure pour groupe $GROUPE"
}

# ================================================================
# ETAPE 5 : Detection mot de passe Wazuh API
# ================================================================
detect_wazuh_mdp() {
    log_etape "5/7" "DETECTION MOT DE PASSE WAZUH API"

    WAZUH_PASS=""

    # Methode 1 : wazuh-install-files.tar
    for TAR_PATH in /root/wazuh-install-files.tar /tmp/wazuh-install-files.tar; do
        [ ! -f "$TAR_PATH" ] && continue
        log_info "Lecture de $TAR_PATH..."

        # Extraire wazuh-passwords.txt
        tar -xf "$TAR_PATH" -C /tmp \
            wazuh-install-files/wazuh-passwords.txt 2>/dev/null || true

        if [ -f /tmp/wazuh-install-files/wazuh-passwords.txt ]; then
            # Parser le mot de passe API wazuh
            WAZUH_PASS=$(grep -A3 "api_username.*'wazuh'" \
                /tmp/wazuh-install-files/wazuh-passwords.txt 2>/dev/null | \
                grep "api_password" | \
                grep -oP "(?<=')[^']+(?=')" | head -1)

            # Fallback : chercher directement
            [ -z "$WAZUH_PASS" ] && \
                WAZUH_PASS=$(grep -A1 "Password for wazuh API" \
                    /tmp/wazuh-install-files/wazuh-passwords.txt 2>/dev/null | \
                    grep "api_password" | \
                    grep -oP "(?<=')[^']+(?=')" | head -1)

            [ -n "$WAZUH_PASS" ] && {
                log_ok "Mot de passe Wazuh API detecte automatiquement"
                break
            }
        fi
    done

    # Methode 2 : Generer via l'API Wazuh si Manager tourne
    if [ -z "$WAZUH_PASS" ] && systemctl is-active --quiet wazuh-manager; then
        log_info "Tentative de recuperation depuis l'API Wazuh..."
        # Attendre que l'API soit prete
        sleep 5
        # Essayer avec le mot de passe par defaut
        for DEFAULT_PASS in "wazuh" "Wazuh1234!"; do
            RESP=$(curl -sk -u "wazuh:${DEFAULT_PASS}" \
                https://127.0.0.1:55000/security/user/authenticate \
                2>/dev/null)
            if echo "$RESP" | grep -q "token"; then
                WAZUH_PASS="$DEFAULT_PASS"
                log_ok "Mot de passe Wazuh par defaut fonctionne : $DEFAULT_PASS"
                break
            fi
        done
    fi

    # Methode 3 : Saisie manuelle
    if [ -z "$WAZUH_PASS" ]; then
        echo ""
        log_warn "Mot de passe Wazuh API non detecte automatiquement."
        log_warn "Il sera disponible apres l'installation complete de Wazuh."
        echo -n "  Entrez le mot de passe maintenant (ou Entree pour ignorer) : "
        read -s WAZUH_PASS_INPUT
        echo ""
        [ -n "$WAZUH_PASS_INPUT" ] && {
            WAZUH_PASS="$WAZUH_PASS_INPUT"
            log_ok "Mot de passe saisi manuellement"
        }
    fi

    # Sauvegarder dans .env
    if [ -n "$WAZUH_PASS" ]; then
        sed -i "s|^WAZUH_PASSWORD=.*|WAZUH_PASSWORD=${WAZUH_PASS}|" "$ENV_FILE"
        log_ok "Mot de passe Wazuh sauvegarde dans .env"
    else
        log_warn "Mot de passe non configure — a faire manuellement :"
        log_warn "  sudo nano $ENV_FILE → WAZUH_PASSWORD=votre_mdp"
    fi
}

# ================================================================
# ETAPE 6 : Lier Wazuh et Snort
# ================================================================
lier_wazuh_snort() {
    log_etape "6/7" "LIAISON WAZUH + SNORT"

    # Ajouter wazuh au groupe snort pour lire les logs
    usermod -aG snort wazuh 2>/dev/null || true
    usermod -aG "$GROUPE" wazuh 2>/dev/null || true
    log_ok "Utilisateur wazuh ajoute aux groupes snort et $GROUPE"

    # Verifier que Wazuh lit bien les alertes Snort
    if [ -f "/var/ossec/etc/ossec.conf" ]; then
        if grep -q "snort" /var/ossec/etc/ossec.conf 2>/dev/null; then
            log_ok "Wazuh configure pour lire les alertes Snort"
        else
            log_warn "Configuration Snort dans Wazuh a verifier"
        fi
    fi

    # Redemarrer Wazuh pour prendre en compte les changements
    systemctl restart wazuh-manager 2>/dev/null || true
    sleep 3

    if systemctl is-active --quiet wazuh-manager; then
        log_ok "Wazuh Manager operationnel"
    else
        log_warn "Wazuh Manager non actif"
    fi
}

# ================================================================
# ETAPE 7 : Finalisation
# ================================================================
finaliser() {
    log_etape "7/7" "FINALISATION"

    SERVER_IP=$(grep "^SERVER_IP=" "$ENV_FILE" | cut -d'=' -f2)
    WAZUH_PASS=$(grep "^WAZUH_PASSWORD=" "$ENV_FILE" | cut -d'=' -f2)

    # Mettre a jour credentials.txt
    cat >> "$CRED_FILE" << CREDS

── MODULE 1 — SNORT + WAZUH ─────────────────────────────────
  Installe le : $(date '+%d/%m/%Y a %H:%M')

── GROUPE CENTRAL ────────────────────────────────────────────
  Groupe      : siem-africa (partage par tous les services)
  Proprietaire: siem-africa (shell: /sbin/nologin)
  Dossier     : /opt/siem-africa/ (chmod 775)

── SNORT ─────────────────────────────────────────────────────
  Version     : $(snort --version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1)
  Config      : /etc/snort/snort.conf
  Interface   : ${INTERFACE}
  Logs        : /var/log/snort/alert
  Service     : snort.service

── WAZUH MANAGER ─────────────────────────────────────────────
  Version     : $(/var/ossec/bin/wazuh-control info 2>/dev/null | grep WAZUH_VERSION | cut -d'=' -f2 | tr -d '"')
  API URL     : https://${SERVER_IP}:55000
  API User    : wazuh
  API Password: ${WAZUH_PASS:-Non configure}
  Alertes     : /var/ossec/logs/alerts/alerts.json
  Service     : wazuh-manager uniquement
  Dashboard   : https://${SERVER_IP}:443

── COMMANDES UTILES ──────────────────────────────────────────
  Etat Snort  : systemctl status snort
  Etat Wazuh  : systemctl status wazuh-manager
  Logs Wazuh  : tail -f /var/ossec/logs/ossec.log
  Alertes     : tail -f /var/ossec/logs/alerts/alerts.json

  Configurer MDP Wazuh (si non detecte) :
    sudo nano /opt/siem-africa/.env
    -> WAZUH_PASSWORD=votre_mot_de_passe
    sudo systemctl restart siem-agent  (apres installation Module 3)

── PROCHAINE ETAPE ───────────────────────────────────────────
  Module 2 — Base de donnees SQLite
  Commande :
    curl -sL https://raw.githubusercontent.com/luciesys/SIEM-AFRICA/main/database/install.sh \\
      -o /tmp/install_db.sh && sudo bash /tmp/install_db.sh

CREDS

    chmod 640 "$CRED_FILE"
    log_ok "credentials.txt mis a jour"

    # Afficher le resume
    _show_summary
}

_show_summary() {
    SERVER_IP=$(grep "^SERVER_IP=" "$ENV_FILE" | cut -d'=' -f2)
    echo ""
    echo -e "${GREEN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║     MODULE 1 — INSTALLATION TERMINEE                ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "${CYAN}── SERVICES ─────────────────────────────────────────${NC}"
    for svc in snort wazuh-manager; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            echo -e "  ${GREEN}[ACTIF]${NC}   $svc"
        else
            echo -e "  ${YELLOW}[INACTIF]${NC} $svc"
        fi
    done

    echo ""
    echo -e "${CYAN}── GROUPE SIEM-AFRICA ───────────────────────────────${NC}"
    echo -e "  ${GREEN}[OK]${NC} Groupe siem-africa cree"
    echo -e "  ${GREEN}[OK]${NC} /opt/siem-africa/ → chmod 775"
    echo -e "  ${GREEN}[OK]${NC} Tous les futurs services rejoindront ce groupe"
    echo ""
    echo -e "${CYAN}── WAZUH ────────────────────────────────────────────${NC}"
    echo -e "  API : https://${SERVER_IP}:55000"
    echo -e "  Alertes JSON : /var/ossec/logs/alerts/alerts.json"
    echo ""
    echo -e "${CYAN}── PROCHAINE ETAPE ──────────────────────────────────${NC}"
    echo -e "  ${YELLOW}Module 2 — Base de donnees SQLite${NC}"
    echo ""
}

# ================================================================
# MAIN
# ================================================================
main() {
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    echo "" >> "$LOG_FILE"
    echo "=== SIEM Africa Module 1 v2.2 - $(date) ===" >> "$LOG_FILE"

    show_banner

    echo -e "  Ce script va installer :"
    echo -e "  ${CYAN}→ Groupe siem-africa${NC} (permissions centralisees)"
    echo -e "  ${CYAN}→ Snort IDS${NC} (detection reseau)"
    echo -e "  ${CYAN}→ Wazuh Manager${NC} (SIEM + API alertes)"
    echo ""
    echo -n "  Lancer l'installation ? (oui/non) : "
    read CONFIRM
    [ "$CONFIRM" != "oui" ] && { echo "Annule."; exit 0; }
    echo ""

    check_systeme
    setup_base
    install_snort
    install_wazuh
    detect_wazuh_mdp
    lier_wazuh_snort
    finaliser

    log_info "Module 1 termine — $(date)"
}

main "$@"
