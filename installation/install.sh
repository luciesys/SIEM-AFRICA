#!/bin/bash
# ================================================================
#  SIEM Africa — Module 1 : Installation Snort + Wazuh
#  Fichier  : installation/install.sh
#  Usage    : sudo bash install.sh
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

# ── Desinstallation propre si installation anterieure detectee ────
desinstaller_si_present() {
    local deja=0
    [ -d /var/ossec ]          && deja=1
    [ -f /etc/snort/snort.conf ] && deja=1
    [ -d /opt/siem-africa ]    && deja=1

    [ "$deja" -eq 0 ] && return 0

    echo ""
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  Installation anterieure detectee !                 ║${NC}"
    echo -e "${YELLOW}║  Suppression avant reinstallation propre...         ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Arreter les services
    for svc in snort wazuh-manager wazuh-indexer wazuh-dashboard siem-agent siem-dashboard siem-reports; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            systemctl stop "$svc" 2>/dev/null || true
            log_ok "Service $svc arrete"
        fi
        systemctl disable "$svc" 2>/dev/null || true
        rm -f "/etc/systemd/system/${svc}.service"
    done
    systemctl daemon-reload 2>/dev/null || true
    log_ok "Services arretes et desactives"

    # Supprimer Wazuh
    if [ -d /var/ossec ]; then
        DEBIAN_FRONTEND=noninteractive apt-get remove -y --purge \
            wazuh-manager wazuh-indexer wazuh-dashboard wazuh-agent \
            > /dev/null 2>&1 || true
        rm -rf /var/ossec /etc/wazuh* /usr/share/wazuh* 2>/dev/null || true
        rm -f /etc/apt/sources.list.d/wazuh.list 2>/dev/null || true
        rm -f /usr/share/keyrings/wazuh.gpg 2>/dev/null || true
        log_ok "Wazuh supprime"
    fi

    # Supprimer Snort
    if command -v snort > /dev/null 2>&1 || [ -f /etc/snort/snort.conf ]; then
        DEBIAN_FRONTEND=noninteractive apt-get remove -y --purge \
            snort snort-rules-default > /dev/null 2>&1 || true
        rm -rf /etc/snort /var/log/snort 2>/dev/null || true
        log_ok "Snort supprime"
    fi

    # Supprimer le dossier SIEM Africa
    if [ -d /opt/siem-africa ]; then
        rm -rf /opt/siem-africa
        log_ok "Dossier /opt/siem-africa supprime"
    fi

    # Supprimer les utilisateurs systeme
    for usr in snort wazuh siem-africa siem-agent siem-dashboard siem-reports; do
        id "$usr" &>/dev/null && userdel "$usr" 2>/dev/null && log_ok "Utilisateur $usr supprime" || true
    done

    # Supprimer le groupe
    getent group siem-africa &>/dev/null && groupdel siem-africa 2>/dev/null && log_ok "Groupe siem-africa supprime" || true

    # Archiver les anciens logs
    [ -d /var/log/siem-africa ] && \
        mv /var/log/siem-africa "/var/log/siem-africa-backup-$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true

    # Nettoyer apt
    apt-get autoremove -y > /dev/null 2>&1 || true
    apt-get autoclean > /dev/null 2>&1 || true

    log_ok "Ancienne installation supprimee — reinstallation propre en cours..."
    echo ""
    sleep 2
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
    # Detection et selection interface reseau
    INTERFACES=$(ip link show 2>/dev/null | grep -v "lo:" | grep "state UP" | awk -F': ' '{print $2}' | tr -d ' ')
    NB=$(echo "$INTERFACES" | grep -c "." 2>/dev/null || echo "0")

    if [ "$NB" -le 1 ]; then
        INTERFACE=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
        [ -z "$INTERFACE" ] && INTERFACE=$(echo "$INTERFACES" | head -1)
        [ -z "$INTERFACE" ] && INTERFACE="eth0"
        log_ok "Interface reseau : $INTERFACE (detectee automatiquement)"
    else
        echo ""
        log_info "Plusieurs interfaces reseau detectees :"
        echo "$INTERFACES" | cat -n | while read line; do echo "    $line"; done
        echo -n "  Interface a surveiller (Entree pour auto) : "
        read IFACE_INPUT
        IFACE_INPUT=$(echo "$IFACE_INPUT" | xargs)
        if [ -n "$IFACE_INPUT" ] && ip link show "$IFACE_INPUT" > /dev/null 2>&1; then
            INTERFACE="$IFACE_INPUT"
            log_ok "Interface choisie : $INTERFACE"
        else
            INTERFACE=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' | head -1 || echo "eth0")
            log_ok "Interface auto : $INTERFACE"
        fi
    fi

    # Verification connexion internet
    log_info "Verification connexion internet..."
    if ping -c 2 -W 3 8.8.8.8 > /dev/null 2>&1 || ping -c 2 -W 3 1.1.1.1 > /dev/null 2>&1; then
        log_ok "Connexion internet OK"
    else
        quitter "Pas de connexion internet — requise pour l'installation"
    fi

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

    log_info "[3.1] Mise a jour des paquets systeme..."
    apt-get update 2>&1 | grep -c "Hit\|Get" | xargs -I{} log_info "  {} sources mises a jour"

    log_info "[3.2] Installation de Snort et ses dependances..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        snort \
        snort-rules-default \
        libpcap-dev \
        libpcre3-dev \
        libdumbnet-dev \
        build-essential 2>&1 | \
        grep -E "Unpacking|Setting up|installed|Preparing" || true

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

    # Donner a snort les droits de capture reseau via setcap
    # Cela permet a snort de capturer les paquets SANS besoin de root
    apt-get install -y -qq libcap2-bin > /dev/null 2>&1 || true
    SNORT_BIN=$(which snort 2>/dev/null || echo "/usr/sbin/snort")
    if setcap cap_net_raw,cap_net_admin=eip "$SNORT_BIN" 2>/dev/null; then
        log_ok "Droits capture reseau accordes a Snort via setcap"
    else
        log_warn "setcap echoue — Snort tournera en root (fonctionnel mais moins securise)"
    fi

    # Droits sur les dossiers de logs pour l'utilisateur snort
    chown -R snort:snort /var/log/snort 2>/dev/null || true
    chmod 755 /var/log/snort

    # ── Service systemd Snort ────────────────────────────────────
    # Test de la configuration avant de creer le service
    log_info "Test de la configuration Snort..."
    if snort -T -c /etc/snort/snort.conf -i "$INTERFACE" > /dev/null 2>&1; then
        log_ok "Configuration Snort valide"
    else
        log_warn "Configuration Snort avec avertissements — on continue quand meme"
    fi

    # Creer le service systemd avec une config simple et robuste
    # Determiner l'utilisateur Snort selon les droits accordes
    SNORT_BIN=$(which snort 2>/dev/null || echo "/usr/sbin/snort")
    if getcap "$SNORT_BIN" 2>/dev/null | grep -q "cap_net_raw"; then
        SNORT_USER="snort"
        SNORT_GROUP="snort"
        log_ok "Snort utilisera l'utilisateur dedie (setcap OK)"
    else
        SNORT_USER="root"
        SNORT_GROUP="root"
        log_info "Snort utilisera root (setcap non disponible)"
    fi

    cat > /etc/systemd/system/snort.service << SNORTSVC
[Unit]
Description=SIEM Africa — Snort IDS
Documentation=https://github.com/luciesys/SIEM-AFRICA
After=network.target
Wants=network.target

[Service]
Type=simple
User=${SNORT_USER}
Group=${SNORT_GROUP}
ExecStart=/usr/sbin/snort -q \
    -c /etc/snort/snort.conf \
    -i ${INTERFACE} \
    -l /var/log/snort \
    -A fast \
    -K ascii
Restart=on-failure
RestartSec=15
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
        log_ok "Service Snort ACTIF"
    else
        log_warn "Snort non actif — diagnostic rapide :"
        # Tenter en mode test pour voir l'erreur
        SNORT_ERR=$(snort -T -c /etc/snort/snort.conf -i "$INTERFACE" 2>&1 | tail -5)
        log_warn "$SNORT_ERR"
        log_warn "Snort sera relance apres configuration complete"
        log_warn "Commande manuelle : systemctl start snort"
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
# ETAPE 4 : Installation Wazuh Manager via APT (methode directe)
# ================================================================
install_wazuh() {
    log_etape "4/7" "INSTALLATION WAZUH MANAGER"
    log_info "Methode : Installation directe via apt (plus fiable)"
    log_warn "Cette etape prend 10 a 20 minutes selon votre connexion."
    echo ""

    # ── Etape 4.1 : Cle GPG Wazuh ────────────────────────────────
    log_info "[4.1] Ajout de la cle GPG Wazuh..."
    curl -sL https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
        gpg --dearmor -o /usr/share/keyrings/wazuh.gpg 2>/dev/null || \
    wget -qO- https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
        gpg --dearmor -o /usr/share/keyrings/wazuh.gpg 2>/dev/null

    if [ ! -f /usr/share/keyrings/wazuh.gpg ]; then
        quitter "Impossible de telecharger la cle GPG Wazuh — verifiez votre connexion"
    fi
    log_ok "Cle GPG Wazuh ajoutee"

    # ── Etape 4.2 : Depot Wazuh ───────────────────────────────────
    log_info "[4.2] Ajout du depot Wazuh..."
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
https://packages.wazuh.com/4.x/apt/ stable main" | \
        tee /etc/apt/sources.list.d/wazuh.list > /dev/null
    log_ok "Depot Wazuh ajoute : packages.wazuh.com/4.x/apt/"

    # ── Etape 4.3 : Mise a jour apt ───────────────────────────────
    log_info "[4.3] Mise a jour de la liste des paquets..."
    apt-get update 2>&1 | grep -E "wazuh|Err|Hit|Get" | head -5 || true
    log_ok "Liste des paquets mise a jour"

    # ── Etape 4.4 : Installation Wazuh Manager ────────────────────
    log_info "[4.4] Installation de wazuh-manager..."
    log_info "Vous allez voir defiler l'installation — c'est normal."
    echo ""

    DEBIAN_FRONTEND=noninteractive apt-get install -y wazuh-manager 2>&1 | \
        tee -a "$LOG_FILE" | \
        grep -E "Unpacking|Setting up|installed|Preparing|Get:|Err" || true

    echo ""

    # ── Verification ─────────────────────────────────────────────
    if [ ! -d /var/ossec ]; then
        log_err "Wazuh Manager non installe. Logs apt :"
        tail -20 /var/log/apt/term.log 2>/dev/null | tee -a "$LOG_FILE" || true
        quitter "Wazuh Manager non installe — voir logs ci-dessus"
    fi

    WAZUH_VER=$(/var/ossec/bin/wazuh-control info 2>/dev/null | \
        grep WAZUH_VERSION | cut -d'=' -f2 | tr -d '"' || echo "inconnue")
    log_ok "Wazuh Manager installe : version $WAZUH_VER"

    # ── Etape 4.5 : Demarrage ────────────────────────────────────
    log_info "[4.5] Demarrage du service Wazuh Manager..."
    systemctl daemon-reload
    systemctl enable wazuh-manager 2>/dev/null || true
    systemctl start wazuh-manager 2>/dev/null || true
    sleep 5

    if systemctl is-active --quiet wazuh-manager; then
        log_ok "Service wazuh-manager : ACTIF"
    else
        log_warn "Service wazuh-manager non actif — verifier :"
        log_warn "  journalctl -u wazuh-manager -n 20"
        # Tenter de le demarrer autrement
        /var/ossec/bin/wazuh-control start 2>/dev/null || true
        sleep 3
        systemctl is-active --quiet wazuh-manager && log_ok "Wazuh demarre" || \
            log_warn "Wazuh toujours inactif — installation continuee quand meme"
    fi

    # ── Configuration supplementaire ─────────────────────────────
    _configurer_wazuh
}

_configurer_wazuh() {
    log_info "Configuration Wazuh Manager..."
    OSSEC_CONF="/var/ossec/etc/ossec.conf"

    # Activer jsonout (utiliser sed propre, pas de concatenation XML)
    if [ -f "$OSSEC_CONF" ]; then
        sed -i "s|<jsonout_output>no</jsonout_output>|<jsonout_output>yes</jsonout_output>|" \
            "$OSSEC_CONF" 2>/dev/null || true

        # Ajouter source logs Snort seulement si absente
        if ! grep -q "snort-fast" "$OSSEC_CONF"; then
            sed -i "/<\/ossec_config>/i\  <localfile>\n    <log_format>snort-fast<\/log_format>\n    <location>\/var\/log\/snort\/alert<\/location>\n  <\/localfile>" \
                "$OSSEC_CONF" 2>/dev/null || true
        fi
        log_ok "Configuration Wazuh mise a jour (JSON + Snort)"
    fi

    # Permissions alerts.json
    mkdir -p /var/ossec/logs/alerts
    touch /var/ossec/logs/alerts/alerts.json 2>/dev/null || true
    chown -R wazuh:wazuh /var/ossec/logs/ 2>/dev/null || true
    chmod 755 /var/ossec/logs/alerts
    chmod 664 /var/ossec/logs/alerts/alerts.json 2>/dev/null || true
    setfacl -m g:"${GROUPE}":r /var/ossec/logs/alerts/alerts.json 2>/dev/null || \
        chmod o+r /var/ossec/logs/alerts/alerts.json 2>/dev/null || true
    usermod -aG "$GROUPE" wazuh 2>/dev/null || true
    log_ok "Acces alerts.json configure pour groupe $GROUPE"

    # Redemarrer Wazuh
    systemctl restart wazuh-manager 2>/dev/null || true
    sleep 3
    systemctl is-active --quiet wazuh-manager && \
        log_ok "Wazuh Manager operationnel" || \
        log_warn "Wazuh non actif — verifier : journalctl -u wazuh-manager -n 10"
}

# ================================================================
# Module 3 s'occupera de detecter le MDP Wazuh automatiquement
# depuis /root/wazuh-install-files.tar
# ================================================================
detect_wazuh_mdp() {
    log_info "MDP Wazuh : sera detecte automatiquement au Module 3 (Agent)"
    log_info "Le fichier source : /root/wazuh-install-files.tar"
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

    echo -e "${CYAN}── SERVICES INSTALLES ───────────────────────────────${NC}"
    for svc in snort wazuh-manager; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            echo -e "  ${GREEN}[ACTIF]${NC}    $svc"
        else
            echo -e "  ${YELLOW}[INACTIF]${NC}  $svc — verifier : journalctl -u $svc -n 10"
        fi
    done

    echo ""
    echo -e "${CYAN}── VERSIONS INSTALLEES ──────────────────────────────${NC}"
    SNV=$(snort --version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1 || echo "?")
    WZV=$(/var/ossec/bin/wazuh-control info 2>/dev/null | grep VERSION | cut -d= -f2 | tr -d '"' || echo "?")
    echo -e "  Snort         : $SNV"
    echo -e "  Wazuh Manager : $WZV"
    echo -e "  Python3       : $(python3 --version 2>&1 | cut -d' ' -f2)"
    echo -e "  OS            : $(. /etc/os-release && echo "$PRETTY_NAME")"

    echo ""
    echo -e "${CYAN}── FICHIERS CREES ───────────────────────────────────${NC}"
    echo -e "  /opt/siem-africa/           (dossier principal)"
    echo -e "  /opt/siem-africa/.env       (configuration)"
    echo -e "  /opt/siem-africa/credentials.txt (identifiants)"
    echo -e "  /etc/snort/snort.conf       (config Snort)"
    echo -e "  /var/ossec/etc/ossec.conf   (config Wazuh)"
    echo -e "  /var/ossec/logs/alerts/alerts.json (alertes JSON)"
    echo -e "  /var/log/siem-africa/       (logs SIEM Africa)"

    echo ""
    echo -e "${CYAN}── GROUPE CENTRAL ───────────────────────────────────${NC}"
    echo -e "  Groupe    : siem-africa"
    echo -e "  Membres   : $(getent group siem-africa | cut -d: -f4)"
    echo -e "  Dossier   : /opt/siem-africa/ (chmod 775)"
    echo -e "  Base DB   : /opt/siem-africa/siem_africa.db (sera cree au module 2)"


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
    desinstaller_si_present

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
    lier_wazuh_snort
    finaliser

    log_info "Module 1 termine — $(date)"
}

main "$@"
