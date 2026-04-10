#!/bin/bash
# ================================================================
#  SIEM Africa — Module 1 : Installation Snort + Wazuh
#  Adapté de : luciesys/snort-wazuh-package
#  Usage     : sudo bash install.sh
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
WAZUH_VERSION="4.7"
SNORT_CONF="/etc/snort/snort.conf"
MIN_RAM=4
MIN_DISK=60
RETRY_COUNT=3

# Utilisateurs système du module 1
USER_SNORT="snort"
USER_WAZUH="wazuh"

# Fichier credentials
CRED_FILE="/opt/siem-africa/credentials.txt"

# ================================================================
# FONCTIONS AFFICHAGE
# ================================================================
log()         { echo -e "$1" | tee -a "$LOG_FILE"; }
log_ok()      { log "${GREEN}[OK]${NC} $1"; }
log_info()    { log "${CYAN}[INFO]${NC} $1"; }
log_warn()    { log "${YELLOW}[ATTENTION]${NC} $1"; }
log_erreur()  { log "${RED}[ERREUR]${NC} $1"; }
log_etape()   { log "${BLUE}[ETAPE $1]${NC} $2"; }

quitter() {
    echo ""
    echo -e "${RED}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║     INSTALLATION ARRETEE                             ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Raison : $1"
    echo -e "  Journal : $LOG_FILE"
    echo ""
    exit 1
}

# ================================================================
# BANNIERE
# ================================================================
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║       SIEM Africa — Module 1                        ║"
    echo "║       Installation Snort IDS + Wazuh SIEM           ║"
    echo "║       Version 2.0 — Logs supplementaires            ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  ${YELLOW}Ubuntu 20.04/22.04/24.04  |  Debian 11/12${NC}"
    echo ""
}

# ================================================================
# VERIFICATIONS OBLIGATOIRES
# ================================================================

check_root() {
    if [ "$EUID" -ne 0 ]; then
        quitter "Lancez avec : sudo bash install.sh"
    fi
    log_ok "Execution en tant que root"
}

check_os() {
    [ ! -f /etc/os-release ] && quitter "Impossible de detecter l OS"

    . /etc/os-release

    case $ID in
        ubuntu)
            if [ "$VERSION_ID" != "20.04" ] && [ "$VERSION_ID" != "22.04" ] && [ "$VERSION_ID" != "24.04" ]; then
                quitter "Ubuntu $VERSION_ID non supporte. Versions : 20.04, 22.04, 24.04"
            fi
            log_ok "OS compatible : Ubuntu $VERSION_ID"
            ;;
        debian)
            if [ "$VERSION_ID" != "11" ] && [ "$VERSION_ID" != "12" ]; then
                quitter "Debian $VERSION_ID non supporte. Versions : 11, 12"
            fi
            log_ok "OS compatible : Debian $VERSION_ID"
            ;;
        *)
            quitter "OS non supporte : $ID. Utilisez Ubuntu ou Debian."
            ;;
    esac
}

check_ram() {
    TOTAL_RAM=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$TOTAL_RAM" -lt "$MIN_RAM" ]; then
        quitter "RAM insuffisante : ${TOTAL_RAM}Go (minimum : ${MIN_RAM}Go)"
    fi
    log_ok "RAM : ${TOTAL_RAM}Go"
}

check_disk() {
    DISPO_DISK=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ "$DISPO_DISK" -lt "$MIN_DISK" ]; then
        quitter "Disque insuffisant : ${DISPO_DISK}Go libres (minimum : ${MIN_DISK}Go)"
    fi
    log_ok "Disque : ${DISPO_DISK}Go libres"
}

check_cpu() {
    CPU_CORES=$(nproc)
    if [ "$CPU_CORES" -lt 2 ]; then
        quitter "CPU insuffisant : ${CPU_CORES} coeur(s) (minimum : 2)"
    fi
    log_ok "CPU : ${CPU_CORES} coeurs"
}

check_internet() {
    log_info "Verification connexion internet..."

    ping -c 3 8.8.8.8 > /dev/null 2>&1 || quitter "Pas de connexion internet"

    if ! ping -c 3 google.com > /dev/null 2>&1; then
        log_warn "Probleme DNS - Correction en cours..."
        echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4" > /etc/resolv.conf
        ping -c 3 google.com > /dev/null 2>&1 || quitter "DNS non fonctionnel"
    fi

    curl -s --head --connect-timeout 10 https://packages.wazuh.com > /dev/null 2>&1 || \
        quitter "Impossible d acceder aux depots Wazuh"

    log_ok "Connexion internet OK"
}

# ================================================================
# NETTOYAGE SI INSTALLATION EXISTANTE
# ================================================================
cleanup_all() {
    log_info "Nettoyage de l installation existante..."

    systemctl stop snort wazuh-manager wazuh-indexer wazuh-dashboard 2>/dev/null || true
    systemctl disable snort wazuh-manager wazuh-indexer wazuh-dashboard 2>/dev/null || true

    apt-get remove --purge -y snort wazuh-manager wazuh-indexer wazuh-dashboard 2>/dev/null || true

    rm -rf /var/ossec
    rm -rf /etc/wazuh-indexer /var/lib/wazuh-indexer /usr/share/wazuh-indexer
    rm -rf /usr/share/wazuh-dashboard /etc/wazuh-dashboard
    rm -rf /etc/snort /var/log/snort
    rm -f /root/wazuh-install.sh /root/wazuh-install-files.tar
    rm -f /etc/systemd/system/snort.service

    systemctl daemon-reload
    apt-get autoremove -y 2>/dev/null || true
    apt-get clean 2>/dev/null || true

    log_ok "Nettoyage termine"
}

check_existing() {
    log_info "Verification des installations existantes..."

    if dpkg -l | grep -qE "snort|wazuh" 2>/dev/null || \
       [ -d "/etc/snort" ] || [ -d "/var/ossec" ]; then
        log_warn "Installation existante detectee — Suppression et reinstallation"
        cleanup_all
    else
        log_ok "Aucune installation existante"
    fi
}

# ================================================================
# CONFIGURATION INTERACTIVE
# ================================================================
get_config() {
    echo ""
    echo -e "${BOLD}  Quelques questions avant de commencer :${NC}"
    echo ""

    # Langue
    echo "  Choisissez la langue :"
    echo "  [1] Francais"
    echo "  [2] English"
    echo -n "  Votre choix [1] : "
    read CHOIX_LANGUE

    if [ "$CHOIX_LANGUE" = "2" ]; then
        SIEM_LANG="en"
        log_ok "Language : English"
    else
        SIEM_LANG="fr"
        log_ok "Langue : Francais"
    fi

    echo ""

    # IP du serveur
    IP_DEFAUT=$(hostname -I | awk '{print $1}')
    echo -n "  Adresse IP du serveur [${IP_DEFAUT}] : "
    read SERVER_IP

    if [ -z "$SERVER_IP" ]; then
        SERVER_IP="$IP_DEFAUT"
    fi
    log_ok "IP Serveur : ${SERVER_IP}"

    echo ""

    # Detection et choix de l'interface réseau
    log_info "Detection des interfaces reseau..."
    echo ""

    COMPTEUR=0
    LISTE_INTERFACES=""

    while read -r LIGNE; do
        NOM=$(echo "$LIGNE" | awk '{print $2}' | tr -d ':')
        if [ "$NOM" != "lo" ]; then
            COMPTEUR=$(( COMPTEUR + 1 ))
            LISTE_INTERFACES="$LISTE_INTERFACES $NOM"
            IP_IF=$(ip addr show "$NOM" 2>/dev/null | grep "inet " | awk '{print $2}' | head -1)
            echo -e "  ${CYAN}[${COMPTEUR}]${NC} ${BOLD}${NOM}${NC} — IP : ${IP_IF:-N/A}"
        fi
    done < <(ip link show | grep "^[0-9]")

    echo ""

    if [ "$COMPTEUR" -eq 0 ]; then
        quitter "Aucune interface reseau detectee"
    fi

    if [ "$COMPTEUR" -eq 1 ]; then
        SNORT_IFACE=$(echo "$LISTE_INTERFACES" | tr -d ' ')
        log_info "Interface unique detectee : ${SNORT_IFACE}"
    else
        echo -n "  Interface a surveiller avec Snort [1] : "
        read CHOIX_IF

        if [ -z "$CHOIX_IF" ]; then
            CHOIX_IF=1
        fi

        if [ "$CHOIX_IF" -lt 1 ] || [ "$CHOIX_IF" -gt "$COMPTEUR" ]; then
            CHOIX_IF=1
        fi

        SNORT_IFACE=$(echo "$LISTE_INTERFACES" | tr ' ' '\n' | grep -v '^$' | sed -n "${CHOIX_IF}p")
    fi

    log_ok "Interface Snort : ${SNORT_IFACE}"

    # Récapitulatif
    echo ""
    echo -e "${BOLD}  +----------------------------------------------+${NC}"
    echo -e "${BOLD}  |            RECAPITULATIF                     |${NC}"
    echo -e "${BOLD}  +----------------------------------------------+${NC}"
    echo -e "  |  Langue       : ${CYAN}${SIEM_LANG}${NC}"
    echo -e "  |  IP Serveur   : ${CYAN}${SERVER_IP}${NC}"
    echo -e "  |  Interface    : ${CYAN}${SNORT_IFACE}${NC}"
    echo -e "${BOLD}  +----------------------------------------------+${NC}"
    echo ""
    echo -n "  Lancer l installation ? (oui/non) : "
    read CONFIRMER

    if [ "$CONFIRMER" != "oui" ]; then
        quitter "Annule par l utilisateur"
    fi
}

# ================================================================
# PREPARATION DU SYSTEME
# ================================================================
update_system() {
    log_info "Mise a jour du systeme..."
    apt-get update -qq || quitter "Echec mise a jour APT"
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq || quitter "Echec mise a jour systeme"
    log_ok "Systeme mis a jour"
}

install_dependencies() {
    log_info "Installation des dependances..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        curl wget gnupg apt-transport-https \
        lsb-release ca-certificates \
        software-properties-common \
        net-tools jq python3 python3-pip \
        openssl bc || quitter "Echec installation dependances"
    log_ok "Dependances installees"
}

# ================================================================
# ETAPE 1 — CREATION DES UTILISATEURS SYSTEME
# ================================================================
create_users() {
    log_etape "1/4" "CREATION DES UTILISATEURS SYSTEME"
    log_info "Chaque service tourne sous son propre utilisateur isole..."

    # Utilisateur snort
    if id "$USER_SNORT" > /dev/null 2>&1; then
        log_info "Utilisateur ${USER_SNORT} existe deja"
    else
        useradd --system --no-create-home --shell /sbin/nologin \
                --comment "SIEM Africa - Snort IDS" "$USER_SNORT"
        log_ok "Utilisateur ${USER_SNORT} cree"
    fi

    # Utilisateur wazuh
    if id "$USER_WAZUH" > /dev/null 2>&1; then
        log_info "Utilisateur ${USER_WAZUH} existe deja"
    else
        useradd --system --no-create-home --shell /sbin/nologin \
                --comment "SIEM Africa - Wazuh SIEM" "$USER_WAZUH"
        log_ok "Utilisateur ${USER_WAZUH} cree"
    fi

    # Utilisateur siem-africa (dashboard + agent — utilisé par les modules suivants)
    if id "siem-africa" > /dev/null 2>&1; then
        log_info "Utilisateur siem-africa existe deja"
    else
        useradd --system --create-home --home-dir /opt/siem-africa \
                --shell /sbin/nologin \
                --comment "SIEM Africa - Dashboard et Agent" siem-africa
        log_ok "Utilisateur siem-africa cree"
    fi

    echo ""
    echo -e "  ${GREEN}[OK]${NC} snort        — Snort IDS (shell: /sbin/nologin)"
    echo -e "  ${GREEN}[OK]${NC} wazuh        — Wazuh SIEM (shell: /sbin/nologin)"
    echo -e "  ${GREEN}[OK]${NC} siem-africa  — Dashboard + Agent (shell: /sbin/nologin)"
    echo ""
}

# ================================================================
# ETAPE 2 — INSTALLATION ET CONFIGURATION SNORT
# ================================================================
install_snort() {
    log_etape "2/4" "INSTALLATION SNORT IDS"

    DEBIAN_FRONTEND=noninteractive apt-get install -y snort 2>/dev/null || {
        log_warn "Snort non disponible via apt. Installation depuis les sources..."

        cd /tmp

        log_info "Installation de DAQ..."
        wget -q https://www.snort.org/downloads/snort/daq-2.0.7.tar.gz
        tar -xzf daq-2.0.7.tar.gz
        cd daq-2.0.7
        ./configure --quiet
        make -j"$(nproc)"
        make install
        ldconfig
        cd /tmp

        log_info "Installation de Snort..."
        wget -q https://www.snort.org/downloads/snort/snort-2.9.20.tar.gz
        tar -xzf snort-2.9.20.tar.gz
        cd snort-2.9.20
        ./configure --quiet --enable-sourcefire
        make -j"$(nproc)"
        make install
        ldconfig
        ln -sf /usr/local/bin/snort /usr/sbin/snort
        cd /tmp
    }

    if ! command -v snort > /dev/null 2>&1; then
        quitter "Echec installation Snort"
    fi

    log_ok "Snort installe : $(snort --version 2>&1 | head -1)"
}

configure_snort() {
    log_info "Configuration de Snort..."

    # Detecter le reseau local
    LOCAL_NET=$(ip route | grep -oP 'src \K[\d.]+' | head -1 | sed 's/\.[0-9]*$/.0\/24/')
    if [ -z "$LOCAL_NET" ]; then
        LOCAL_NET="192.168.1.0/24"
    fi

    mkdir -p /var/log/snort /etc/snort/rules

    # Modifier snort.conf si il existe
    if [ -f "$SNORT_CONF" ]; then
        sed -i "s|ipvar HOME_NET any|ipvar HOME_NET $LOCAL_NET|g" "$SNORT_CONF" 2>/dev/null || true
        sed -i "s|var HOME_NET any|var HOME_NET $LOCAL_NET|g" "$SNORT_CONF" 2>/dev/null || true
    else
        # Créer un snort.conf minimal
        cat > "$SNORT_CONF" << SNORTCONF
# SIEM Africa — Configuration Snort
# Organisation : SIEM Africa
# Date : $(date)

var HOME_NET $LOCAL_NET
var EXTERNAL_NET any
var RULE_PATH /etc/snort/rules
var LOG_PATH  /var/log/snort

config interface: ${SNORT_IFACE}
config checksum_mode: none

output alert_json: /var/log/snort/alert.json default
output log_unified2: filename snort.log, limit 128

include \$RULE_PATH/local.rules
SNORTCONF
    fi

    # Creer les regles locales
    cat > /etc/snort/rules/local.rules << 'LRULES'
# SIEM Africa — Regles Snort locales
# Ajoutez vos regles personnalisees ici
LRULES

    # Droits
    chown -R "$USER_SNORT":"$USER_SNORT" /var/log/snort /etc/snort 2>/dev/null || true
    chmod 755 /var/log/snort

    # Service systemd
    cat > /etc/systemd/system/snort.service << SNORTSVC
[Unit]
Description=Snort IDS SIEM Africa
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/sbin/snort -q -c /etc/snort/snort.conf -i ${SNORT_IFACE} -A json
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SNORTSVC

    systemctl daemon-reload
    systemctl enable snort
    systemctl start snort 2>/dev/null || true

    log_ok "Snort configure (HOME_NET: $LOCAL_NET, Interface: $SNORT_IFACE)"
}

# ================================================================
# ETAPE 3 — INSTALLATION WAZUH
# ================================================================
install_wazuh() {
    log_etape "3/4" "INSTALLATION WAZUH $WAZUH_VERSION"
    log_info "Cette etape prend 20 a 40 minutes en fonction de l'état de votre connection internet"

    # Télécharger le script d'installation Wazuh
    curl -sO https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh || \
        quitter "Impossible de telecharger le script Wazuh"

    chmod +x wazuh-install.sh

    # Tentatives d'installation
    TENTATIVE=1
    SUCCES="non"

    while [ "$TENTATIVE" -le "$RETRY_COUNT" ]; do
        log_info "Tentative $TENTATIVE/$RETRY_COUNT..."

        if bash wazuh-install.sh -a -i >> "$LOG_FILE" 2>&1; then
            SUCCES="oui"
            break
        fi

        log_warn "Tentative $TENTATIVE echouee"

        if [ "$TENTATIVE" -lt "$RETRY_COUNT" ]; then
            systemctl stop wazuh-manager wazuh-indexer wazuh-dashboard 2>/dev/null || true
            apt-get remove --purge wazuh-manager wazuh-indexer wazuh-dashboard -y 2>/dev/null || true
            rm -rf /var/ossec /etc/wazuh-indexer /var/lib/wazuh-indexer wazuh-install-files.tar 2>/dev/null || true
            sleep 5
        fi

        TENTATIVE=$(( TENTATIVE + 1 ))
    done

    if [ "$SUCCES" = "non" ]; then
        quitter "Installation Wazuh echouee apres $RETRY_COUNT tentatives. Voir : $LOG_FILE"
    fi

    log_ok "Wazuh installe"

    # Droits sur /var/ossec
    chown -R "$USER_WAZUH":"$USER_WAZUH" /var/ossec 2>/dev/null || true

    # Sauvegarder le fichier d'installation
    if [ -f "wazuh-install-files.tar" ]; then
        cp wazuh-install-files.tar /root/
    fi
}

# ================================================================
# ETAPE 4 — LIAISON SNORT VERS WAZUH
# ================================================================
configure_integration() {
    log_etape "4/4" "LIAISON SNORT VERS WAZUH"

    OSSEC_CONF="/var/ossec/etc/ossec.conf"

    if [ ! -f "$OSSEC_CONF" ]; then
        quitter "ossec.conf introuvable — Wazuh n est pas correctement installe"
    fi

    # Sauvegarder ossec.conf
    cp "$OSSEC_CONF" "${OSSEC_CONF}.backup"

    # Ajouter la lecture des logs Snort
    if ! grep -q "/var/log/snort/alert" "$OSSEC_CONF"; then
        sed -i '/<\/ossec_config>/i \  <!-- SIEM Africa - Logs Snort IDS -->\n  <localfile>\n    <log_format>snort-full<\/log_format>\n    <location>\/var\/log\/snort\/alert<\/location>\n  <\/localfile>' "$OSSEC_CONF"
        log_ok "Liaison Snort configuree dans ossec.conf"
    else
        log_info "Liaison Snort deja presente dans ossec.conf"
    fi

    # Ajouter les logs supplementaires (auth.log, syslog, nginx/apache)
    log_info "Ajout des logs supplementaires dans Wazuh..."

    if ! grep -q "auth.log" "$OSSEC_CONF"; then
        sed -i '/<\/ossec_config>/i \  <!-- SIEM Africa - Logs SSH et sudo -->\n  <localfile>\n    <log_format>syslog<\/log_format>\n    <location>\/var\/log\/auth.log<\/location>\n  <\/localfile>' "$OSSEC_CONF"
        log_ok "Logs auth.log ajoutes (SSH, sudo, connexions)"
    fi

    if ! grep -q "syslog" "$OSSEC_CONF"; then
        sed -i '/<\/ossec_config>/i \  <!-- SIEM Africa - Logs systeme -->\n  <localfile>\n    <log_format>syslog<\/log_format>\n    <location>\/var\/log\/syslog<\/location>\n  <\/localfile>' "$OSSEC_CONF"
        log_ok "Logs syslog ajoutes (modifications systeme)"
    fi

    # Nginx (si installe)
    if [ -f "/var/log/nginx/access.log" ]; then
        if ! grep -q "nginx/access" "$OSSEC_CONF"; then
            sed -i '/<\/ossec_config>/i \  <!-- SIEM Africa - Logs Nginx -->\n  <localfile>\n    <log_format>apache<\/log_format>\n    <location>\/var\/log\/nginx\/access.log<\/location>\n  <\/localfile>' "$OSSEC_CONF"
            log_ok "Logs Nginx ajoutes (attaques web)"
        fi
    fi

    # Apache (si installe)
    if [ -f "/var/log/apache2/access.log" ]; then
        if ! grep -q "apache2/access" "$OSSEC_CONF"; then
            sed -i '/<\/ossec_config>/i \  <!-- SIEM Africa - Logs Apache -->\n  <localfile>\n    <log_format>apache<\/log_format>\n    <location>\/var\/log\/apache2\/access.log<\/location>\n  <\/localfile>' "$OSSEC_CONF"
            log_ok "Logs Apache ajoutes (attaques web)"
        fi
    fi

    # Ajouter les règles Wazuh pour Snort
    cat > /var/ossec/etc/rules/snort_siem_africa.xml << 'SRULES'
<!-- SIEM Africa — Regles Wazuh pour Snort IDS -->
<group name="snort,ids,siem-africa,">

  <rule id="100001" level="3">
    <decoded_as>json</decoded_as>
    <field name="source">snort</field>
    <description>Snort IDS - Alerte detectee</description>
  </rule>

  <rule id="100002" level="14">
    <if_sid>100001</if_sid>
    <field name="priority">1</field>
    <description>Snort IDS - Alerte CRITIQUE</description>
  </rule>

  <rule id="100003" level="10">
    <if_sid>100001</if_sid>
    <field name="priority">2</field>
    <description>Snort IDS - Alerte HAUTE</description>
  </rule>

  <rule id="100004" level="7">
    <if_sid>100001</if_sid>
    <field name="priority">3</field>
    <description>Snort IDS - Alerte MOYENNE</description>
  </rule>

  <rule id="100005" level="4">
    <if_sid>100001</if_sid>
    <field name="priority">4</field>
    <description>Snort IDS - Alerte FAIBLE</description>
  </rule>

</group>
SRULES

    # Redémarrer Wazuh pour appliquer
    systemctl restart wazuh-manager || quitter "Impossible de redemarrer Wazuh"

    log_ok "Integration Snort-Wazuh configuree"
}

# ================================================================
# GENERATION DU FICHIER CREDENTIALS
# ================================================================
create_credentials() {
    log_info "Generation du fichier credentials..."

    mkdir -p /opt/siem-africa
    mkdir -p /opt/siem-africa/rapports/installation

    # Récupérer le mot de passe Wazuh
    WAZUH_PASS="Voir /root/wazuh-install-files.tar"
    if [ -f "/root/wazuh-install-files.tar" ]; then
        tar -xf /root/wazuh-install-files.tar -C /tmp 2>/dev/null || true
        WAZUH_PASS=$(grep -A1 "admin" /tmp/wazuh-install-files/wazuh-passwords.txt 2>/dev/null | tail -1 | tr -d ' ' || echo "Voir wazuh-install-files.tar")
        rm -rf /tmp/wazuh-install-files
    fi

    # Générer la clé secrète Flask
    SECRET_KEY=$(openssl rand -hex 32)

    cat > "$CRED_FILE" << CREDENTIALS
================================================================
  SIEM Africa — Fichier de credentials
  Serveur : ${SERVER_IP}
  Date    : $(date '+%d/%m/%Y a %H:%M:%S')
================================================================
  CONFIDENTIEL — Ne partagez JAMAIS ce fichier
================================================================

── UTILISATEURS SYSTEME ──────────────────────────────────────

  snort
  - Role    : Snort IDS
  - Shell   : /sbin/nologin (connexion directe impossible)
  - Dossier : /etc/snort/ et /var/log/snort/

  wazuh
  - Role    : Wazuh SIEM
  - Shell   : /sbin/nologin (connexion directe impossible)
  - Dossier : /var/ossec/

  siem-africa
  - Role    : Dashboard + Agent (modules suivants)
  - Shell   : /sbin/nologin (connexion directe impossible)
  - Dossier : /opt/siem-africa/

── SNORT IDS ─────────────────────────────────────────────────
  Interface      : ${SNORT_IFACE}
  Configuration  : /etc/snort/snort.conf
  Logs           : /var/log/snort/alert.json
  Service        : systemctl status snort

── WAZUH SIEM ────────────────────────────────────────────────
  Dashboard URL  : https://${SERVER_IP}
  Login          : admin
  Mot de passe   : ${WAZUH_PASS}
  IMPORTANT      : Changer a la premiere connexion

  API URL        : https://${SERVER_IP}:55000
  Service        : systemctl status wazuh-manager

── SIEM AFRICA ───────────────────────────────────────────────
  Dashboard URL  : http://${SERVER_IP}:5000 (module 4)
  Cle secrete    : ${SECRET_KEY}
  IMPORTANT      : Login et MDP definis au module 4

── FICHIERS IMPORTANTS ───────────────────────────────────────
  Ce fichier     : ${CRED_FILE}
  Config .env    : /opt/siem-africa/.env
  Logs Snort     : /var/log/snort/alert.json
  Logs Wazuh     : /var/ossec/logs/ossec.log
  Journal inst.  : ${LOG_FILE}
  Rapports       : /opt/siem-africa/rapports/

── COMMANDES UTILES ──────────────────────────────────────────
  Verifier Snort   : systemctl status snort
  Verifier Wazuh   : systemctl status wazuh-manager
  Alertes Snort    : tail -f /var/log/snort/alert.json
  Logs Wazuh       : tail -f /var/ossec/logs/ossec.log
  Ports ouverts    : ss -tlnp | grep -E '443|9200|55000'

── PORTS UTILISES ────────────────────────────────────────────
  443   — Wazuh Dashboard (HTTPS)
  1514  — Wazuh Agent communication
  1515  — Wazuh Agent enrollment
  9200  — Wazuh Indexer
  55000 — Wazuh API REST
  5000  — SIEM Africa Dashboard (module 4)

── PROCHAINE ETAPE ───────────────────────────────────────────
  Module 2 — Base de donnees SQLite
  Commande : cd ../2-database && sudo bash install.sh

================================================================
CREDENTIALS

    # Sauvegarder la clé secrète dans .env
    cat > /opt/siem-africa/.env << ENV
# SIEM Africa — Configuration
# Date : $(date)
# IMPORTANT : Ne partagez jamais ce fichier

LANG=${SIEM_LANG}
SERVER_IP=${SERVER_IP}
FLASK_PORT=5000
SECRET_KEY=${SECRET_KEY}

SNORT_INTERFACE=${SNORT_IFACE}
SNORT_LOG=/var/log/snort/alert.json

WAZUH_HOST=127.0.0.1
WAZUH_PORT=55000
WAZUH_USER=wazuh-api
WAZUH_PASSWORD=

DB_PATH=/opt/siem-africa/siem_africa.db

SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=

POLLING_INTERVAL=10
CORRELATION_WINDOW=60
CORRELATION_THRESHOLD=3

CLOUDFLARE_TOKEN=
CLOUDFLARE_URL=

REPORTS_DIR=/opt/siem-africa/rapports
ENV

    chmod 600 "$CRED_FILE"
    chmod 600 /opt/siem-africa/.env
    chown -R siem-africa:siem-africa /opt/siem-africa 2>/dev/null || true

    log_ok "Credentials : $CRED_FILE"
}

# ================================================================
# RESUME FINAL
# ================================================================
show_summary() {
    IP=$(hostname -I | awk '{print $1}')

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     MODULE 1 — INSTALLATION TERMINEE AVEC SUCCES    ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo -e "${CYAN}── ACCES WAZUH DASHBOARD ─────────────────────────────${NC}"
    echo -e "  URL         : ${GREEN}https://${IP}${NC}"
    echo -e "  Utilisateur : admin"
    echo -e "  Mot de passe: voir ${YELLOW}${CRED_FILE}${NC}"
    echo ""

    echo -e "${CYAN}── UTILISATEURS SYSTEME CREES ────────────────────────${NC}"
    echo -e "  ${GREEN}[OK]${NC} snort        — Snort IDS"
    echo -e "  ${GREEN}[OK]${NC} wazuh        — Wazuh SIEM"
    echo -e "  ${GREEN}[OK]${NC} siem-africa  — Dashboard + Agent"
    echo ""

    echo -e "${CYAN}── ETAT DES SERVICES ─────────────────────────────────${NC}"
    for SERVICE in snort wazuh-manager wazuh-indexer wazuh-dashboard; do
        if systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
            echo -e "  ${GREEN}[ACTIF]${NC}   $SERVICE"
        else
            echo -e "  ${RED}[INACTIF]${NC} $SERVICE"
        fi
    done
    echo ""

    echo -e "${CYAN}── FICHIERS IMPORTANTS ───────────────────────────────${NC}"
    echo -e "  Credentials : ${YELLOW}${CRED_FILE}${NC}"
    echo -e "  Afficher    : ${GREEN}cat ${CRED_FILE}${NC}"
    echo ""

    echo -e "${CYAN}── COMMANDES DE VERIFICATION ─────────────────────────${NC}"
    echo -e "  systemctl status snort"
    echo -e "  systemctl status wazuh-manager"
    echo -e "  ss -tlnp | grep -E '443|9200|55000'"
    echo -e "  tail -f /var/log/snort/alert.json"
    echo ""

    echo -e "${CYAN}── PROCHAINE ETAPE ───────────────────────────────────${NC}"
    echo -e "  ${YELLOW}cd ../2-database && sudo bash install.sh${NC}"
    echo ""

    echo -e "  Note : Le certificat SSL Wazuh est auto-signe."
    echo -e "  Cliquez sur 'Avancer' dans le navigateur."
    echo ""
}

# ================================================================
# MAIN — PROGRAMME PRINCIPAL
# ================================================================
main() {
    echo "=== SIEM Africa Installation - $(date) ===" > "$LOG_FILE"

    show_banner

    # Verifications
    echo -e "${CYAN}[VERIFICATIONS]${NC}"
    echo "────────────────────────────────────────────────────"
    check_root
    check_os
    check_ram
    check_disk
    check_cpu
    check_internet
    echo ""

    # Verifier installation existante
    echo -e "${CYAN}[INSTALLATION EXISTANTE]${NC}"
    echo "────────────────────────────────────────────────────"
    check_existing
    echo ""

    # Configuration
    echo -e "${CYAN}[CONFIGURATION]${NC}"
    echo "────────────────────────────────────────────────────"
    get_config
    echo ""

    # Preparation
    echo -e "${CYAN}[PREPARATION]${NC}"
    echo "────────────────────────────────────────────────────"
    update_system
    install_dependencies
    echo ""

    # Installation
    echo -e "${CYAN}[INSTALLATION]${NC}"
    echo "────────────────────────────────────────────────────"
    create_users
    echo ""
    install_snort
    configure_snort
    echo ""
    install_wazuh
    echo ""
    configure_integration
    echo ""
    create_credentials
    echo ""

    show_summary

    log_info "Installation terminee - $(date)"
}

main "$@"
