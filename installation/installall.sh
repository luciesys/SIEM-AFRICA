#!/bin/bash
# ================================================================
#  SIEM Africa — Module 1 : Installation Snort + Wazuh Manager
#  Fichier  : installation/install.sh
#  Version  : 3.0 — Réécriture complete
#  Usage    : sudo bash install.sh
#
#  Ce script installe :
#  - Snort IDS (detection d'intrusion reseau)
#  - Wazuh Manager (SIEM + collecte alertes)
#  - Liaison Snort → Wazuh via ossec.conf
#  - Groupe central siem-africa (droits partages)
# ================================================================

# Pas de set -e — gestion d'erreurs explicite
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Variables globales
LOG_FILE="/var/log/siem-africa-install.log"
OPT_DIR="/opt/siem-africa"
ENV_FILE="/opt/siem-africa/.env"
CRED_FILE="/opt/siem-africa/credentials.txt"
GROUPE="siem-africa"
USER_PRINCIPAL="siem-africa"
INTERFACE=""
SERVER_IP=""
LANGUE="fr"

# Messages bilingues
msg() {
    local fr="$1" en="$2"
    [ "$LANGUE" = "en" ] && echo "$en" || echo "$fr"
}

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
    echo ""
    echo -e "${RED}Installation arretee.${NC}"
    echo -e "Journal complet : ${YELLOW}$LOG_FILE${NC}"
    exit 1
}

# ================================================================
# BANNIERE
# ================================================================
show_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║                                                      ║"
    echo "  ║          SIEM Africa — Module 1 v3.0                ║"
    echo "  ║          Snort IDS + Wazuh All-in-One               ║"
    echo "  ║                                                      ║"
    echo "  ║          github.com/luciesys/SIEM-AFRICA            ║"
    echo "  ║                                                      ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ================================================================
# CHOIX DE LANGUE
# ================================================================
choisir_langue() {
    echo -e "  ${BOLD}Choisissez votre langue / Choose your language :${NC}"
    echo ""
    echo "  [1] Francais (par defaut)"
    echo "  [2] English"
    echo ""
    echo -n "  Votre choix / Your choice [1/2] : "
    read CHOIX_LANGUE
    case "$CHOIX_LANGUE" in
        2|en|EN|english|English) LANGUE="en" ; echo -e "  ${GREEN}Language: English${NC}" ;;
        *)                        LANGUE="fr" ; echo -e "  ${GREEN}Langue : Francais${NC}" ;;
    esac
    echo ""
}

# ================================================================
# DESINSTALLATION SI INSTALLATION EXISTANTE
# ================================================================
desinstaller_si_present() {
    local deja=0
    [ -d /var/ossec ]            && deja=1
    [ -f /etc/snort/snort.conf ] && deja=1
    [ -d "$OPT_DIR" ]            && deja=1

    [ "$deja" -eq 0 ] && return 0

    echo ""
    echo -e "${YELLOW}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    if [ "$LANGUE" = "en" ]; then
        echo "  ║   Previous installation detected !               ║"
        echo "  ║   Removing before clean reinstall...             ║"
    else
        echo "  ║   Installation anterieure detectee !             ║"
        echo "  ║   Suppression avant reinstallation propre...     ║"
    fi
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    # Arreter tous les services SIEM Africa
    log_info "$(msg 'Arret des services...' 'Stopping services...')"
    for svc in snort wazuh-manager wazuh-indexer wazuh-dashboard \
               siem-agent siem-dashboard siem-reports; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            systemctl stop "$svc" 2>/dev/null || true
        fi
        systemctl disable "$svc" 2>/dev/null || true
        rm -f "/etc/systemd/system/${svc}.service"
    done
    systemctl daemon-reload 2>/dev/null || true
    log_ok "$(msg 'Services arretes' 'Services stopped')"

    # Supprimer Wazuh via apt
    if [ -d /var/ossec ]; then
        log_info "$(msg 'Suppression de Wazuh...' 'Removing Wazuh...')"
        DEBIAN_FRONTEND=noninteractive apt-get remove -y --purge \
            wazuh-manager wazuh-indexer wazuh-dashboard wazuh-agent \
            > /dev/null 2>&1 || true
        rm -rf /var/ossec /etc/wazuh* 2>/dev/null || true
        rm -f /etc/apt/sources.list.d/wazuh.list 2>/dev/null || true
        rm -f /usr/share/keyrings/wazuh.gpg 2>/dev/null || true
        log_ok "$(msg 'Wazuh supprime' 'Wazuh removed')"
    fi

    # Supprimer Snort
    if command -v snort > /dev/null 2>&1 || [ -f /etc/snort/snort.conf ]; then
        log_info "$(msg 'Suppression de Snort...' 'Removing Snort...')"
        DEBIAN_FRONTEND=noninteractive apt-get remove -y --purge \
            snort snort-rules-default > /dev/null 2>&1 || true
        rm -rf /etc/snort /var/log/snort 2>/dev/null || true
        log_ok "$(msg 'Snort supprime' 'Snort removed')"
    fi

    # Supprimer le dossier SIEM Africa
    if [ -d "$OPT_DIR" ]; then
        rm -rf "$OPT_DIR"
        log_ok "$(msg 'Dossier /opt/siem-africa supprime' '/opt/siem-africa removed')"
    fi

    # Supprimer les utilisateurs systeme
    for usr in snort siem-africa siem-agent siem-dashboard siem-reports; do
        id "$usr" &>/dev/null && {
            userdel "$usr" 2>/dev/null || true
        }
    done

    # Supprimer le groupe
    getent group "$GROUPE" &>/dev/null && \
        groupdel "$GROUPE" 2>/dev/null || true

    # Archiver les anciens logs
    if [ -d /var/log/siem-africa ]; then
        mv /var/log/siem-africa \
           "/var/log/siem-africa-backup-$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
    fi

    apt-get autoremove -y > /dev/null 2>&1 || true
    log_ok "$(msg 'Ancienne installation supprimee — reinstallation en cours' \
              'Previous installation removed — reinstalling')"
    echo ""
    sleep 2
}

# ================================================================
# ETAPE 1 : Verifications systeme
# ================================================================
check_systeme() {
    log_etape "1/7 — $(msg 'VERIFICATIONS SYSTEME' 'SYSTEM CHECKS')"

    # Root
    [ "$EUID" -ne 0 ] && \
        quitter "$(msg 'Lancez avec : sudo bash install.sh' 'Run with: sudo bash install.sh')"
    log_ok "$(msg 'Droits root confirmes' 'Root rights confirmed')"

    # OS
    [ ! -f /etc/os-release ] && quitter "OS non detecte"
    . /etc/os-release
    case "$ID" in
        ubuntu)
            case "$VERSION_ID" in
                20.04|22.04|24.04)
                    log_ok "OS : Ubuntu $VERSION_ID (supporte)" ;;
                *)
                    quitter "Ubuntu $VERSION_ID non supporte. Requis : 20.04 / 22.04 / 24.04" ;;
            esac ;;
        debian)
            case "$VERSION_ID" in
                11|12) log_ok "OS : Debian $VERSION_ID (supporte)" ;;
                *)     quitter "Debian $VERSION_ID non supporte. Requis : 11 / 12" ;;
            esac ;;
        *) quitter "OS non supporte : $ID. Requis : Ubuntu ou Debian" ;;
    esac

    # RAM
    RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
    if [ "${RAM_GB:-0}" -lt 4 ]; then
        quitter "$(msg "RAM insuffisante : ${RAM_GB}GB (minimum 4GB)" \
                    "Insufficient RAM: ${RAM_GB}GB (minimum 4GB)")"
    fi
    log_ok "$(msg "RAM : ${RAM_GB}GB disponible" "RAM: ${RAM_GB}GB available")"

    # Disque
    DISK_GB=$(df -BG / | awk 'NR==2{gsub("G","",$4); print $4}')
    if [ "${DISK_GB:-0}" -lt 20 ]; then
        quitter "$(msg "Disque insuffisant : ${DISK_GB}GB libres (minimum 20GB)" \
                    "Insufficient disk: ${DISK_GB}GB free (minimum 20GB)")"
    fi
    log_ok "$(msg "Disque : ${DISK_GB}GB libres" "Disk: ${DISK_GB}GB free")"

    # Interface reseau
    log_info "$(msg 'Detection des interfaces reseau...' 'Detecting network interfaces...')"
    INTERFACES_UP=$(ip link show 2>/dev/null | \
        awk -F': ' '/state UP/{print $2}' | grep -v "lo" | xargs)
    NB_INTERFACES=$(echo "$INTERFACES_UP" | wc -w)

    if [ "$NB_INTERFACES" -eq 0 ]; then
        # Fallback : prendre la premiere interface non-lo
        INTERFACE=$(ip link show 2>/dev/null | \
            awk -F': ' '!/lo:/{print $2}' | head -1 | xargs)
        [ -z "$INTERFACE" ] && INTERFACE="eth0"
        log_warn "$(msg "Aucune interface UP detectee — utilisation de $INTERFACE" \
                    "No UP interface detected — using $INTERFACE")"
    elif [ "$NB_INTERFACES" -eq 1 ]; then
        INTERFACE="$INTERFACES_UP"
        log_ok "$(msg "Interface reseau : $INTERFACE (detectee automatiquement)" \
                   "Network interface: $INTERFACE (auto-detected)")"
    else
        echo ""
        log_info "$(msg 'Plusieurs interfaces disponibles :' 'Multiple interfaces available:')"
        echo ""
        for iface in $INTERFACES_UP; do
            IP_IFACE=$(ip addr show "$iface" 2>/dev/null | \
                grep "inet " | awk '{print $2}' | head -1)
            echo -e "    ${CYAN}$iface${NC}  ${IP_IFACE:-aucune IP}"
        done
        echo ""
        if [ "$LANGUE" = "en" ]; then
            echo -n "  Interface to monitor (press Enter for first one) : "
        else
            echo -n "  Interface a surveiller (Entree pour la premiere) : "
        fi
        read IFACE_INPUT
        IFACE_INPUT=$(echo "$IFACE_INPUT" | xargs)
        if [ -n "$IFACE_INPUT" ] && ip link show "$IFACE_INPUT" > /dev/null 2>&1; then
            INTERFACE="$IFACE_INPUT"
        else
            INTERFACE=$(echo "$INTERFACES_UP" | awk '{print $1}')
        fi
        log_ok "$(msg "Interface choisie : $INTERFACE" "Chosen interface: $INTERFACE")"
    fi

    # IP du serveur
    SERVER_IP=$(ip addr show "$INTERFACE" 2>/dev/null | \
        grep "inet " | awk '{print $2}' | cut -d'/' -f1 | head -1)
    [ -z "$SERVER_IP" ] && SERVER_IP=$(hostname -I | awk '{print $1}')
    log_ok "$(msg "IP serveur : $SERVER_IP" "Server IP: $SERVER_IP")"

    # Connexion internet
    log_info "$(msg 'Verification connexion internet...' 'Checking internet connection...')"
    if ping -c 2 -W 3 8.8.8.8 > /dev/null 2>&1 || \
       ping -c 2 -W 3 1.1.1.1 > /dev/null 2>&1; then
        log_ok "$(msg 'Connexion internet OK' 'Internet connection OK')"
    else
        quitter "$(msg 'Pas de connexion internet — requise pour installation' \
                    'No internet connection — required for installation')"
    fi
}

# ================================================================
# ETAPE 2 : Groupe central et structure de base
# ================================================================
setup_base() {
    log_etape "2/7 — $(msg 'GROUPE CENTRAL ET STRUCTURE' 'CENTRAL GROUP AND STRUCTURE')"

    # Groupe siem-africa — partage entre TOUS les services
    if getent group "$GROUPE" > /dev/null 2>&1; then
        log_info "$(msg "Groupe $GROUPE existe deja" "Group $GROUPE already exists")"
    else
        groupadd --system "$GROUPE"
        log_ok "$(msg "Groupe $GROUPE cree" "Group $GROUPE created")"
    fi

    # Utilisateur principal
    if id "$USER_PRINCIPAL" > /dev/null 2>&1; then
        log_info "$(msg "Utilisateur $USER_PRINCIPAL existe deja" \
                    "User $USER_PRINCIPAL already exists")"
    else
        useradd --system --no-create-home --shell /sbin/nologin \
                --gid "$GROUPE" \
                --comment "SIEM Africa principal" \
                "$USER_PRINCIPAL"
        log_ok "$(msg "Utilisateur $USER_PRINCIPAL cree" "User $USER_PRINCIPAL created")"
    fi

    # Dossiers
    mkdir -p "$OPT_DIR" \
             "$OPT_DIR/rapports" \
             "$OPT_DIR/models" \
             /var/log/siem-africa

    chown -R "${USER_PRINCIPAL}:${GROUPE}" "$OPT_DIR"
    chmod 775 "$OPT_DIR"
    chmod 775 "$OPT_DIR/rapports"
    chmod 775 "$OPT_DIR/models"
    chmod 755 /var/log/siem-africa
    log_ok "$(msg "Dossier $OPT_DIR cree (groupe $GROUPE, chmod 775)" \
               "Folder $OPT_DIR created (group $GROUPE, chmod 775)")"

    # Reseau local pour Snort
    LOCAL_NET=$(ip addr show "$INTERFACE" 2>/dev/null | \
        grep "inet " | awk '{print $2}' | head -1)
    [ -z "$LOCAL_NET" ] && LOCAL_NET="192.168.0.0/16"

    # Fichier .env
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))" 2>/dev/null || \
                 cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 50)

    cat > "$ENV_FILE" << ENV
# ================================================================
#  SIEM Africa — Configuration
#  Genere le : $(date '+%d/%m/%Y a %H:%M')
# ================================================================

# Reseau
SERVER_IP=${SERVER_IP}
INTERFACE=${INTERFACE}
LOCAL_NET=${LOCAL_NET}

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

# Notifications SMTP
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
ALERT_EMAIL=

# Organisation
ORG_NOM=Mon Entreprise
LANG=${LANGUE}

# Django
SECRET_KEY=${SECRET_KEY}
ENV

    chown "${USER_PRINCIPAL}:${GROUPE}" "$ENV_FILE"
    chmod 660 "$ENV_FILE"
    log_ok "Fichier .env genere / .env file generated"

    # Fichier credentials.txt
    cat > "$CRED_FILE" << CREDS
================================================================
  SIEM Africa — Fichier d'acces / Access File
  Genere le : $(date '+%d/%m/%Y a %H:%M')
  CONFIDENTIEL — Ne pas partager / CONFIDENTIAL — Do not share
================================================================

── INFORMATIONS SERVEUR / SERVER INFORMATION ─────────────────
  IP serveur    : ${SERVER_IP}
  Interface     : ${INTERFACE}
  Reseau local  : ${LOCAL_NET}
  OS            : ${PRETTY_NAME:-Ubuntu}
  Langue        : ${LANGUE}

CREDS

    chown "${USER_PRINCIPAL}:${GROUPE}" "$CRED_FILE"
    chmod 640 "$CRED_FILE"
    log_ok "Fichier credentials.txt cree / credentials.txt file created"
}

# ================================================================
# ETAPE 3 : Installation Snort
# ================================================================
install_snort() {
    log_etape "3/7 — $(msg 'INSTALLATION SNORT IDS' 'SNORT IDS INSTALLATION')"

    apt-get update -qq
    log_info "[3.1] $(msg 'Installation Snort...' 'Installing Snort...')"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq         snort         snort-rules-default         libpcap-dev         libpcre3-dev         libdumbnet-dev         build-essential         libcap2-bin > /dev/null 2>&1

    if command -v snort > /dev/null 2>&1; then
        SNORT_VER=$(snort --version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1)
        log_ok "$(msg "Snort installe : version $SNORT_VER" "Snort installed: version $SNORT_VER")"
    else
        quitter "$(msg 'Snort non installe' 'Snort not installed')"
    fi

    _configurer_snort
    _creer_service_snort
}

_configurer_snort() {
    log_info "[3.2] $(msg 'Configuration Snort...' 'Configuring Snort...')"

    # Creer les dossiers necessaires
    mkdir -p /var/log/snort /etc/snort/rules /etc/snort/so_rules /etc/snort/preproc_rules
    touch /etc/snort/rules/local.rules 2>/dev/null || true
    touch /etc/snort/rules/white_list.rules 2>/dev/null || true
    touch /etc/snort/rules/black_list.rules 2>/dev/null || true

    # Determiner le reseau local
    LOCAL_NET=$(ip -4 addr show "$INTERFACE" 2>/dev/null |         grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+/\d+' | head -1)
    [ -z "$LOCAL_NET" ] && LOCAL_NET="192.168.0.0/16"

    SNORT_CONF="/etc/snort/snort.conf"

    if [ -f "$SNORT_CONF" ]; then
        # Le snort.conf existe (installe par apt) — on met juste HOME_NET a jour
        sed -i "s|^ipvar HOME_NET.*|ipvar HOME_NET ${LOCAL_NET}|"             "$SNORT_CONF" 2>/dev/null || true
        log_ok "$(msg "HOME_NET configure : $LOCAL_NET" "HOME_NET set: $LOCAL_NET")"
    else
        # Creer un snort.conf minimal si absent
        cat > "$SNORT_CONF" << SNORTCONF
# SIEM Africa — Configuration Snort minimale
ipvar HOME_NET ${LOCAL_NET}
ipvar EXTERNAL_NET !\$HOME_NET
var RULE_PATH /etc/snort/rules
var SO_RULE_PATH /etc/snort/so_rules
var PREPROC_RULE_PATH /etc/snort/preproc_rules
var WHITE_LIST_PATH /etc/snort/rules
var BLACK_LIST_PATH /etc/snort/rules

output alert_fast: /var/log/snort/alert
output log_unified2: filename snort.log, limit 128

preprocessor frag3_global: max_frags 65536
preprocessor stream5_global: track_tcp yes, track_udp yes
preprocessor stream5_tcp: policy first, detect_anomalies,     require_3whs 180, overlap_limit 10, small_segments 3 bytes 150, timeout 180

config detection: search-method ac-split search-optimize max-pattern-len 20

include \$RULE_PATH/local.rules
SNORTCONF
        log_ok "$(msg 'snort.conf cree' 'snort.conf created')"
    fi

    # Creer l'utilisateur snort
    if ! id "snort" > /dev/null 2>&1; then
        useradd --system --no-create-home --shell /sbin/nologin snort
    fi
    usermod -aG "$GROUPE" snort

    # Droits sur les logs
    chown -R snort:snort /var/log/snort
    chmod 775 /var/log/snort
    setfacl -R -m g:"${GROUPE}":rX /var/log/snort 2>/dev/null ||         chmod o+rX /var/log/snort 2>/dev/null || true

    log_ok "$(msg 'Utilisateur snort ajoute au groupe siem-africa'                'User snort added to siem-africa group')"
}

_creer_service_snort() {
    log_info "[3.3] $(msg 'Creation service Snort...' 'Creating Snort service...')"

    # Donner les droits reseau a Snort
    SNORT_BIN=$(which snort)
    setcap cap_net_raw,cap_net_admin=eip "$SNORT_BIN" 2>/dev/null || true

    cat > /etc/systemd/system/snort.service << SNORTSVC
[Unit]
Description=SIEM Africa Snort IDS
Documentation=https://github.com/luciesys/SIEM-AFRICA
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
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
SNORTSVC

    systemctl daemon-reload
    systemctl enable snort 2>/dev/null || true
    systemctl start snort 2>/dev/null || true
    sleep 3

    if systemctl is-active --quiet snort; then
        log_ok "$(msg 'Service Snort : ACTIF' 'Snort service: ACTIVE')"
    else
        log_warn "$(msg 'Snort non actif — verifier : journalctl -u snort -n 10'                     'Snort not active — check: journalctl -u snort -n 10')"
    fi
}

# ================================================================
# ETAPE 4 : Installation Wazuh All-in-One
#           Manager + Indexer + Dashboard
# ================================================================
install_wazuh() {
    log_etape "4/7 — $(msg 'INSTALLATION WAZUH ALL-IN-ONE' 'WAZUH ALL-IN-ONE INSTALLATION')"
    log_info "$(msg 'Composants : Manager + Indexer + Dashboard'                  'Components: Manager + Indexer + Dashboard')"
    log_warn "$(msg 'Cette etape prend 30 a 60 minutes — soyez patient'                  'This step takes 30 to 60 minutes — please be patient')"
    echo ""

    # 4.1 : Telecharger le script officiel Wazuh
    log_info "[4.1] $(msg 'Telechargement du script Wazuh...' 'Downloading Wazuh script...')"
    WAZUH_URL="https://packages.wazuh.com/4.14/wazuh-install.sh"
    curl -sL "$WAZUH_URL" -o /tmp/wazuh-install.sh 2>/dev/null ||     wget -q   "$WAZUH_URL" -O /tmp/wazuh-install.sh 2>/dev/null ||         quitter "$(msg 'Impossible de telecharger le script Wazuh'                     'Cannot download Wazuh script')"

    [ ! -f /tmp/wazuh-install.sh ] &&         quitter "$(msg 'Fichier wazuh-install.sh absent' 'wazuh-install.sh file missing')"

    # Verifier que c'est un vrai script bash et pas une page d'erreur XML
    head -1 /tmp/wazuh-install.sh | grep -q "^#!" ||         quitter "$(msg 'Fichier telecharge invalide (page erreur ?) — verifiez la connexion'                     'Downloaded file invalid (error page?) — check connection')"

    chmod +x /tmp/wazuh-install.sh
    log_ok "$(msg 'Script Wazuh telecharge et valide' 'Wazuh script downloaded and valid')"

    # 4.2 : Installation all-in-one
    log_info "[4.2] $(msg 'Installation Wazuh all-in-one (-a)...'                          'Installing Wazuh all-in-one (-a)...')"
    log_info "$(msg 'Affichage installation en cours — c est normal.'                  'Installation output scrolling — this is normal.')"
    echo ""

    bash /tmp/wazuh-install.sh -a 2>&1 | tee -a "$LOG_FILE" |         grep -E "INFO|ERROR|WARNING|Starting|Complete|Password|Installing|Configuring" |         while read line; do log_info "  $line"; done

    echo ""

    # 4.3 : Verification
    if [ ! -d /var/ossec ]; then
        log_err "$(msg 'Wazuh non installe. Voir journal pour details.'                     'Wazuh not installed. Check log for details.')"
        tail -10 /var/log/apt/term.log 2>/dev/null | tee -a "$LOG_FILE" || true
        quitter "$(msg 'Wazuh non installe' 'Wazuh not installed')"
    fi

    WAZUH_VER=$(/var/ossec/bin/wazuh-control info 2>/dev/null |         grep WAZUH_VERSION | cut -d'=' -f2 | tr -d '"' || echo "?")
    log_ok "$(msg "Wazuh installe : $WAZUH_VER" "Wazuh installed: $WAZUH_VER")"

    # 4.4 : Verifier les 3 services
    log_info "[4.4] $(msg 'Verification des services Wazuh...' 'Checking Wazuh services...')"
    for svc in wazuh-manager wazuh-indexer wazuh-dashboard; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            log_ok "  $svc : $(msg 'ACTIF' 'ACTIVE')"
        else
            log_warn "  $svc : $(msg 'non actif — tentative de demarrage' 'not active — trying to start')"
            systemctl start "$svc" 2>/dev/null || true
            sleep 3
            systemctl is-active --quiet "$svc" &&                 log_ok "  $svc : $(msg 'demarre' 'started')" ||                 log_warn "  $svc : $(msg 'toujours inactif' 'still inactive')"
        fi
    done
}

# ================================================================
# ETAPE 5 : Liaison Snort et Wazuh
# ================================================================
lier_snort_wazuh() {
    log_etape "5/7 — $(msg 'LIAISON SNORT ET WAZUH' 'SNORT AND WAZUH LINK')"

    OSSEC_CONF="/var/ossec/etc/ossec.conf"
    [ ! -f "$OSSEC_CONF" ] && log_warn "ossec.conf absent" && return

    # Nettoyer ossec.conf :
    # 1. Supprimer les blocs localfile contenant snort
    # 2. Supprimer les blocs localfile vides (sans log_format)
    python3 - "$OSSEC_CONF" << 'PYEOF2'
import sys
path = sys.argv[1]
lines = open(path).readlines()
result = []
i = 0
while i < len(lines):
    if '<localfile>' in lines[i]:
        j = i + 1
        while j < len(lines) and '</localfile>' not in lines[j]:
            j += 1
        block = ''.join(lines[i:j+1])
        # Supprimer si bloc snort OU bloc vide sans log_format
        if 'snort' in block.lower() or '<log_format>' not in block:
            i = j + 1
            continue
    result.append(lines[i])
    i += 1
open(path, 'w').writelines(result)
print("OK: " + str(len(result)) + " lignes")
PYEOF2

    log_ok "$(msg 'ossec.conf nettoye (snort + blocs vides supprimes)'                'ossec.conf cleaned (snort + empty blocks removed)')"

    # Activer JSON output
    sed -i 's|<jsonout_output>no</jsonout_output>|<jsonout_output>yes</jsonout_output>|g'         "$OSSEC_CONF" 2>/dev/null || true
    log_ok "$(msg 'Sortie JSON Wazuh activee' 'Wazuh JSON output enabled')"

    # Ajouter wazuh au groupe siem-africa
    usermod -aG "$GROUPE" wazuh 2>/dev/null || true
    log_ok "$(msg 'Utilisateur wazuh ajoute au groupe siem-africa'                'User wazuh added to siem-africa group')"
}

# ================================================================
# ETAPE 6 : Demarrage et configuration finale Wazuh
# ================================================================
demarrer_wazuh() {
    log_etape "6/7 — $(msg 'DEMARRAGE WAZUH MANAGER' 'STARTING WAZUH MANAGER')"

    systemctl daemon-reload
    systemctl enable wazuh-manager 2>/dev/null || true

    log_info "$(msg 'Demarrage de Wazuh Manager...' 'Starting Wazuh Manager...')"
    systemctl start wazuh-manager 2>/dev/null || true
    sleep 5

    if systemctl is-active --quiet wazuh-manager; then
        log_ok "$(msg 'Service wazuh-manager : ACTIF' 'wazuh-manager service: ACTIVE')"
    else
        # Tenter un second demarrage
        log_warn "$(msg 'Premier demarrage echoue — nouvelle tentative...' \
                    'First start failed — retrying...')"
        sleep 5
        systemctl start wazuh-manager 2>/dev/null || true
        sleep 5
        if systemctl is-active --quiet wazuh-manager; then
            log_ok "$(msg 'Wazuh Manager : ACTIF' 'Wazuh Manager: ACTIVE')"
        else
            WAZUH_ERR=$(journalctl -u wazuh-manager -n 5 --no-pager 2>/dev/null | \
                grep -E "error|Error|ERROR" | head -2 || echo "")
            log_warn "$(msg 'Wazuh Manager non actif.' 'Wazuh Manager not active.')"
            [ -n "$WAZUH_ERR" ] && log_warn "$WAZUH_ERR"
            log_warn "$(msg 'Commande de diagnostic : journalctl -u wazuh-manager -n 20' \
                        'Diagnostic: journalctl -u wazuh-manager -n 20')"
        fi
    fi

    # Configurer l'acces au fichier alerts.json
    log_info "$(msg 'Configuration acces alerts.json...' 'Configuring alerts.json access...')"
    mkdir -p /var/ossec/logs/alerts
    touch /var/ossec/logs/alerts/alerts.json 2>/dev/null || true
    chown -R wazuh:wazuh /var/ossec/logs/ 2>/dev/null || true
    chmod 755 /var/ossec/logs/alerts
    chmod 664 /var/ossec/logs/alerts/alerts.json 2>/dev/null || true

    # Acces lecture pour le groupe siem-africa
    setfacl -m g:"${GROUPE}":r /var/ossec/logs/alerts/alerts.json 2>/dev/null || \
        chmod o+r /var/ossec/logs/alerts/alerts.json 2>/dev/null || true
    log_ok "$(msg 'Acces alerts.json configure pour groupe siem-africa' \
               'alerts.json access configured for siem-africa group')"
}

# ================================================================
# ETAPE 7 : Credentials et resume
# ================================================================
finaliser() {
    log_etape "7/7 — $(msg 'FINALISATION' 'FINALIZATION')"

    WAZUH_VER=$(/var/ossec/bin/wazuh-control info 2>/dev/null | \
        grep WAZUH_VERSION | cut -d'=' -f2 | tr -d '"' || echo "?")
    SNORT_VER=$(snort --version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1 || echo "?")

    cat >> "$CRED_FILE" << CREDS
── MODULE 1 — SNORT + WAZUH ─────────────────────────────────
  $(msg 'Installe le' 'Installed on') : $(date '+%d/%m/%Y a %H:%M')

── VERSIONS INSTALLEES ───────────────────────────────────────
  Snort         : $SNORT_VER
  Wazuh Manager : $WAZUH_VER
  Python3       : $(python3 --version 2>&1 | cut -d' ' -f2)
  OS            : ${PRETTY_NAME:-Ubuntu}

── GROUPE CENTRAL SIEM-AFRICA ────────────────────────────────
  Groupe    : siem-africa
  Membres   : $(getent group siem-africa | cut -d: -f4)
  Dossier   : /opt/siem-africa/ (chmod 775)

── SNORT IDS ─────────────────────────────────────────────────
  Version   : $SNORT_VER
  Config    : /etc/snort/snort.conf
  Interface : ${INTERFACE}
  Reseau    : $(grep "^LOCAL_NET=" "$ENV_FILE" | cut -d'=' -f2)
  Logs      : /var/log/snort/alert
  Service   : snort.service

── WAZUH MANAGER ─────────────────────────────────────────────
  Version   : $WAZUH_VER
  API URL   : https://${SERVER_IP}:55000
  Config    : /var/ossec/etc/ossec.conf
  Alertes   : /var/ossec/logs/alerts/alerts.json
  Services  : wazuh-manager + wazuh-indexer + wazuh-dashboard
  Dashboard : https://${SERVER_IP} (admin / mot_de_passe_genere)
  MDP API   : $(msg 'Voir /root/wazuh-install-files.tar' \
                    'See /root/wazuh-install-files.tar')

── COMMANDES UTILES ──────────────────────────────────────────
  systemctl status snort
  systemctl status wazuh-manager
  tail -f /var/ossec/logs/alerts/alerts.json
  journalctl -u wazuh-manager -f

── PROCHAINE ETAPE ───────────────────────────────────────────
  Module 2 — Base de donnees SQLite
  curl -sL https://raw.githubusercontent.com/luciesys/SIEM-AFRICA/main/database/install.sh \\
    -o /tmp/install_db.sh && sudo bash /tmp/install_db.sh

CREDS

    chmod 640 "$CRED_FILE"
    log_ok "credentials.txt mis a jour / updated"

    # Afficher le resume final
    echo ""
    echo -e "${GREEN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    if [ "$LANGUE" = "en" ]; then
        echo "  ║     MODULE 1 — INSTALLATION COMPLETE !           ║"
    else
        echo "  ║     MODULE 1 — INSTALLATION TERMINEE !           ║"
    fi
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "${CYAN}── $(msg 'SERVICES INSTALLES' 'INSTALLED SERVICES') ─────────────────────────────${NC}"
    for svc in snort wazuh-manager wazuh-indexer wazuh-dashboard; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            echo -e "  ${GREEN}[ACTIF]${NC}    $svc"
        else
            echo -e "  ${YELLOW}[INACTIF]${NC}  $svc  ← journalctl -u $svc -n 10"
        fi
    done

    echo ""
    echo -e "${CYAN}── $(msg 'VERSIONS' 'VERSIONS') ───────────────────────────────────────${NC}"
    echo -e "  Snort         : $SNORT_VER"
    echo -e "  Wazuh Manager : $WAZUH_VER"
    echo -e "  OS            : ${PRETTY_NAME:-Ubuntu}"

    echo ""
    echo -e "${CYAN}── $(msg 'ACCES' 'ACCESS') ─────────────────────────────────────────${NC}"
    echo -e "  Wazuh Dashboard : https://${SERVER_IP}
  Wazuh API       : https://${SERVER_IP}:55000"
    echo -e "  Alertes   : /var/ossec/logs/alerts/alerts.json"
    echo -e "  Credentials : $CRED_FILE"

    echo ""
    echo -e "${CYAN}── $(msg 'GROUPE CENTRAL' 'CENTRAL GROUP') ─────────────────────────────────${NC}"
    echo -e "  Groupe  : ${GREEN}siem-africa${NC}"
    echo -e "  Membres : $(getent group siem-africa | cut -d: -f4)"
    echo -e "  $(msg 'Tous les services futurs rejoindront ce groupe' \
                  'All future services will join this group')"

    echo ""
    echo -e "${CYAN}── $(msg 'PROCHAINE ETAPE' 'NEXT STEP') ─────────────────────────────────${NC}"
    echo -e "  ${YELLOW}Module 2 — $(msg 'Base de donnees SQLite' 'SQLite Database')${NC}"
    echo ""
}

# ================================================================
# MAIN
# ================================================================
main() {
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    echo "" >> "$LOG_FILE"
    echo "=== SIEM Africa Module 1 v3.0 - $(date) ===" >> "$LOG_FILE"

    show_banner
    choisir_langue
    desinstaller_si_present
    check_systeme
    setup_base
    install_snort
    install_wazuh
    lier_snort_wazuh
    demarrer_wazuh
    finaliser

    log_info "Module 1 termine — $(date)"
}

main "$@"
