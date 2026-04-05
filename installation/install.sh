#!/bin/bash
# ================================================================
#  SIEM Africa — Module 1 : Installation Snort + Wazuh
#  Fichiers : 1-installation/install.sh
#  Usage    : sudo bash install.sh
#  Version  : 2.0 — Syntaxe corrigée
# ================================================================

# Arrêter le script si une commande échoue
set -e

# ================================================================
# COULEURS
# ================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# ================================================================
# FONCTIONS
# ================================================================

log_ok() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[ATTENTION]${NC} $1"
}

log_erreur() {
    echo -e "${RED}[ERREUR]${NC} $1"
}

log_etape() {
    echo ""
    echo -e "${BOLD}${BLUE}===================================================${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BOLD}${BLUE}===================================================${NC}"
    echo ""
}

quitter() {
    echo ""
    echo -e "${RED}===================================================${NC}"
    echo -e "${RED}  INSTALLATION ANNULEE${NC}"
    echo -e "${RED}  Raison : $1${NC}"
    echo -e "${RED}===================================================${NC}"
    echo ""
    exit 1
}

# ================================================================
# BANNIERE
# ================================================================
clear
echo ""
echo -e "${CYAN}  ╔═══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}  ║          SIEM Africa — Module 1               ║${NC}"
echo -e "${CYAN}  ║    Installation Snort IDS + Wazuh SIEM        ║${NC}"
echo -e "${CYAN}  ╚═══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${YELLOW}Ubuntu 20.04 / 22.04 / 24.04  |  Debian 11 / 12${NC}"
echo ""

# ================================================================
# ETAPE 1 — VERIFICATION ROOT
# ================================================================
log_etape "Etape 1/10 — Verification des droits"

if [ "$EUID" -ne 0 ]; then
    quitter "Lancez avec : sudo bash install.sh"
fi

log_ok "Droits root confirmes"

# ================================================================
# ETAPE 2 — DETECTION OS
# ================================================================
log_etape "Etape 2/10 — Detection du systeme d exploitation"

if [ ! -f /etc/os-release ]; then
    quitter "Impossible de detecter l OS"
fi

# Lire les informations OS
OS_NAME=$(grep "^NAME=" /etc/os-release | cut -d'=' -f2 | tr -d '"')
OS_VERSION=$(grep "^VERSION_ID=" /etc/os-release | cut -d'=' -f2 | tr -d '"')
OS_ID=$(grep "^ID=" /etc/os-release | cut -d'=' -f2 | tr -d '"')

log_info "OS detecte : ${OS_NAME} ${OS_VERSION}"

# Verifier si l'OS est supporte
SUPPORTE="non"

if [ "$OS_ID" = "ubuntu" ]; then
    if [ "$OS_VERSION" = "20.04" ] || [ "$OS_VERSION" = "22.04" ] || [ "$OS_VERSION" = "24.04" ]; then
        SUPPORTE="oui"
    fi
fi

if [ "$OS_ID" = "debian" ]; then
    if [ "$OS_VERSION" = "11" ] || [ "$OS_VERSION" = "12" ]; then
        SUPPORTE="oui"
    fi
fi

if [ "$SUPPORTE" = "non" ]; then
    log_warn "OS non supporte officiellement : ${OS_NAME} ${OS_VERSION}"
    echo -n "  Continuer quand meme ? (oui/non) : "
    read CONTINUER
    if [ "$CONTINUER" != "oui" ]; then
        quitter "OS non supporte"
    fi
else
    log_ok "OS supporte : ${OS_NAME} ${OS_VERSION}"
fi

# ================================================================
# ETAPE 3 — VERIFICATION PREREQUIS MATERIELS
# ================================================================
log_etape "Etape 3/10 — Verification des prerequis materiels"

ERREURS=0

# RAM
RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
RAM_GB=$(( RAM_KB / 1024 / 1024 ))
RAM_AFFICHE=$(echo "scale=1; $RAM_KB/1024/1024" | bc)

if [ "$RAM_GB" -lt 4 ]; then
    log_erreur "RAM : ${RAM_AFFICHE} GB — 4 GB minimum requis"
    ERREURS=$(( ERREURS + 1 ))
else
    log_ok "RAM : ${RAM_AFFICHE} GB"
fi

# DISQUE
DISK_KB=$(df / | tail -1 | awk '{print $4}')
DISK_GB=$(( DISK_KB / 1024 / 1024 ))

if [ "$DISK_GB" -lt 60 ]; then
    log_erreur "Disque : ${DISK_GB} GB libres — 60 GB minimum requis"
    ERREURS=$(( ERREURS + 1 ))
else
    log_ok "Disque : ${DISK_GB} GB libres"
fi

# CPU
CPU_CORES=$(nproc)

if [ "$CPU_CORES" -lt 2 ]; then
    log_erreur "CPU : ${CPU_CORES} coeur(s) — 2 coeurs minimum requis"
    ERREURS=$(( ERREURS + 1 ))
else
    log_ok "CPU : ${CPU_CORES} coeurs"
fi

# INTERNET
log_info "Verification connexion internet..."
if ping -c 1 -W 5 8.8.8.8 > /dev/null 2>&1; then
    log_ok "Internet"
else
    log_erreur "Pas de connexion internet"
    ERREURS=$(( ERREURS + 1 ))
fi

# Arreter si erreurs
if [ "$ERREURS" -gt 0 ]; then
    quitter "Corrigez les prerequis ci-dessus et relancez"
fi

log_ok "Tous les prerequis sont satisfaits"

# ================================================================
# ETAPE 4 — CONFIGURATION INTERACTIVE
# ================================================================
log_etape "Etape 4/10 — Configuration"

echo -e "${BOLD}  Repondez aux questions suivantes :${NC}"
echo ""

# Langue
echo "  Choisissez la langue :"
echo "  [1] Francais"
echo "  [2] English"
echo -n "  Votre choix [1] : "
read CHOIX_LANGUE

if [ "$CHOIX_LANGUE" = "2" ]; then
    SIEM_LANG="en"
    log_ok "Language: English"
else
    SIEM_LANG="fr"
    log_ok "Langue : Francais"
fi

echo ""

# Nom organisation
echo -n "  Nom de l organisation / PME : "
read ORG_NAME

if [ -z "$ORG_NAME" ]; then
    ORG_NAME="MonEntreprise"
fi
log_ok "Organisation : ${ORG_NAME}"

# IP serveur
IP_DEFAUT=$(hostname -I | awk '{print $1}')
echo -n "  Adresse IP du serveur [${IP_DEFAUT}] : "
read SERVER_IP

if [ -z "$SERVER_IP" ]; then
    SERVER_IP="$IP_DEFAUT"
fi
log_ok "IP Serveur : ${SERVER_IP}"

# Email admin
echo -n "  Email de l administrateur : "
read ADMIN_EMAIL

if [ -z "$ADMIN_EMAIL" ]; then
    ADMIN_EMAIL="admin@siem-africa.local"
fi
log_ok "Email : ${ADMIN_EMAIL}"

# Mot de passe admin
echo ""
MDP_OK="non"
while [ "$MDP_OK" = "non" ]; do
    echo -n "  Mot de passe admin SIEM Africa (min. 12 caracteres) : "
    read -s ADMIN_PASS
    echo ""
    echo -n "  Confirmez le mot de passe : "
    read -s ADMIN_PASS2
    echo ""

    if [ "$ADMIN_PASS" != "$ADMIN_PASS2" ]; then
        log_warn "Les mots de passe ne correspondent pas. Reessayez."
    elif [ ${#ADMIN_PASS} -lt 12 ]; then
        log_warn "Minimum 12 caracteres requis. Reessayez."
    else
        log_ok "Mot de passe configure"
        MDP_OK="oui"
    fi
done

echo ""

# ================================================================
# DETECTION INTERFACES RESEAU
# ================================================================
log_info "Detection des interfaces reseau..."
echo ""

# Lister les interfaces (sans lo)
INTERFACES=""
COMPTEUR=0

while read -r LIGNE; do
    NOM=$(echo "$LIGNE" | awk '{print $2}' | tr -d ':')
    if [ "$NOM" != "lo" ]; then
        COMPTEUR=$(( COMPTEUR + 1 ))
        INTERFACES="$INTERFACES $NOM"
        IP_IF=$(ip addr show "$NOM" 2>/dev/null | grep "inet " | awk '{print $2}' | head -1)
        echo -e "  ${CYAN}[${COMPTEUR}]${NC} ${BOLD}${NOM}${NC} — IP: ${IP_IF:-N/A}"
    fi
done < <(ip link show | grep "^[0-9]")

echo ""

if [ "$COMPTEUR" -eq 0 ]; then
    quitter "Aucune interface reseau detectee"
fi

if [ "$COMPTEUR" -eq 1 ]; then
    SNORT_IFACE=$(echo $INTERFACES | tr -d ' ')
    log_info "Interface unique : ${SNORT_IFACE} — selectionnee automatiquement"
else
    echo -n "  Selectionnez l interface a surveiller [1] : "
    read CHOIX_IF

    if [ -z "$CHOIX_IF" ]; then
        CHOIX_IF=1
    fi

    # Verifier que le choix est valide
    if [ "$CHOIX_IF" -lt 1 ] || [ "$CHOIX_IF" -gt "$COMPTEUR" ]; then
        CHOIX_IF=1
    fi

    # Recuperer le nom de l'interface choisie
    SNORT_IFACE=$(echo $INTERFACES | tr ' ' '\n' | grep -v '^$' | sed -n "${CHOIX_IF}p")
fi

log_ok "Interface Snort : ${SNORT_IFACE}"

# ================================================================
# RECAPITULATIF AVANT INSTALLATION
# ================================================================
echo ""
echo -e "${BOLD}  +-------------------------------------------+${NC}"
echo -e "${BOLD}  |           RECAPITULATIF                   |${NC}"
echo -e "${BOLD}  +-------------------------------------------+${NC}"
echo -e "  |  OS           : ${CYAN}${OS_NAME} ${OS_VERSION}${NC}"
echo -e "  |  Langue       : ${CYAN}${SIEM_LANG}${NC}"
echo -e "  |  Organisation : ${CYAN}${ORG_NAME}${NC}"
echo -e "  |  IP Serveur   : ${CYAN}${SERVER_IP}${NC}"
echo -e "  |  Email admin  : ${CYAN}${ADMIN_EMAIL}${NC}"
echo -e "  |  Interface    : ${CYAN}${SNORT_IFACE}${NC}"
echo -e "${BOLD}  +-------------------------------------------+${NC}"
echo ""
echo -n "  Lancer l installation ? (oui/non) : "
read CONFIRMER

if [ "$CONFIRMER" != "oui" ]; then
    quitter "Annule par l utilisateur"
fi

# Activer le journal
LOG_FILE="/var/log/siem-africa-install.log"
exec > >(tee -a "$LOG_FILE") 2>&1
log_info "Journal : ${LOG_FILE}"

# ================================================================
# ETAPE 5 — CREATION DES UTILISATEURS SYSTEME
# ================================================================
log_etape "Etape 5/10 — Creation des utilisateurs systeme"

log_info "Chaque service tourne sous son propre utilisateur isole..."

# Creer l'utilisateur snort
if id "snort" > /dev/null 2>&1; then
    log_info "Utilisateur snort existe deja"
else
    useradd --system --no-create-home --shell /sbin/nologin \
            --comment "SIEM Africa - Snort IDS" snort
    log_ok "Utilisateur snort cree"
fi

# Creer l'utilisateur wazuh
if id "wazuh" > /dev/null 2>&1; then
    log_info "Utilisateur wazuh existe deja"
else
    useradd --system --no-create-home --shell /sbin/nologin \
            --comment "SIEM Africa - Wazuh SIEM" wazuh
    log_ok "Utilisateur wazuh cree"
fi

# Creer l'utilisateur siem-africa
if id "siem-africa" > /dev/null 2>&1; then
    log_info "Utilisateur siem-africa existe deja"
else
    useradd --system --create-home --home-dir /opt/siem-africa \
            --shell /sbin/nologin \
            --comment "SIEM Africa - Dashboard et Agent" siem-africa
    log_ok "Utilisateur siem-africa cree"
fi

echo ""
echo -e "  ${GREEN}[OK]${NC} snort       — Snort IDS"
echo -e "  ${GREEN}[OK]${NC} wazuh       — Wazuh SIEM"
echo -e "  ${GREEN}[OK]${NC} siem-africa — Dashboard + Agent"
echo ""

# ================================================================
# ETAPE 6 — MISE A JOUR DU SYSTEME
# ================================================================
log_etape "Etape 6/10 — Mise a jour du systeme"

export DEBIAN_FRONTEND=noninteractive

log_info "Mise a jour des paquets..."
apt-get update -qq
log_ok "Liste des paquets mise a jour"

log_info "Mise a jour du systeme..."
apt-get upgrade -y -qq
log_ok "Systeme mis a jour"

log_info "Installation des dependances..."
apt-get install -y -qq \
    curl \
    wget \
    gnupg2 \
    lsb-release \
    apt-transport-https \
    ca-certificates \
    software-properties-common \
    build-essential \
    git \
    net-tools \
    iptables \
    iptables-persistent \
    python3 \
    python3-pip \
    openssl \
    jq \
    bc \
    libpcap-dev \
    libpcre3-dev \
    zlib1g-dev \
    libssl-dev

log_ok "Dependances installees"

# ================================================================
# ETAPE 7 — INSTALLATION SNORT IDS
# ================================================================
log_etape "Etape 7/10 — Installation de Snort IDS"

log_info "Installation de Snort..."

apt-get install -y -qq snort 2>/dev/null

# Verifier si Snort est installe
if ! command -v snort > /dev/null 2>&1; then
    log_warn "Snort non disponible via apt. Installation depuis les sources..."

    cd /tmp

    log_info "Telechargement et installation de DAQ..."
    wget -q https://www.snort.org/downloads/snort/daq-2.0.7.tar.gz
    tar -xzf daq-2.0.7.tar.gz
    cd daq-2.0.7
    ./configure --quiet
    make -j"$(nproc)"
    make install
    ldconfig
    cd /tmp

    log_info "Telechargement et installation de Snort..."
    wget -q https://www.snort.org/downloads/snort/snort-2.9.20.tar.gz
    tar -xzf snort-2.9.20.tar.gz
    cd snort-2.9.20
    ./configure --quiet --enable-sourcefire
    make -j"$(nproc)"
    make install
    ldconfig
    ln -sf /usr/local/bin/snort /usr/sbin/snort
    cd /tmp
fi

# Verifier l'installation
if ! command -v snort > /dev/null 2>&1; then
    quitter "Echec installation Snort"
fi

SNORT_VERSION=$(snort --version 2>&1 | head -1)
log_ok "Snort installe : ${SNORT_VERSION}"

# Configuration Snort
log_info "Configuration de Snort..."

mkdir -p /etc/snort/rules
mkdir -p /var/log/snort
mkdir -p /usr/local/lib/snort_dynamicrules

cat > /etc/snort/snort.conf << SNORTCONF
# SIEM Africa — Configuration Snort
# Organisation : ${ORG_NAME}
# Date : $(date)

var HOME_NET any
var EXTERNAL_NET any
var RULE_PATH /etc/snort/rules
var LOG_PATH  /var/log/snort

config interface: ${SNORT_IFACE}
config checksum_mode: none

output alert_json: /var/log/snort/alert.json default
output log_unified2: filename snort.log, limit 128

include \$RULE_PATH/local.rules
SNORTCONF

cat > /etc/snort/rules/local.rules << 'LRULES'
# SIEM Africa — Regles Snort locales
# Ajoutez vos regles personnalisees ici
LRULES

chown -R snort:snort /var/log/snort
chown -R snort:snort /etc/snort
chmod 755 /var/log/snort

# Service systemd pour Snort
cat > /etc/systemd/system/snort.service << SNORTSVC
[Unit]
Description=Snort IDS SIEM Africa
After=network.target

[Service]
Type=simple
User=snort
Group=snort
ExecStart=/usr/sbin/snort -q -c /etc/snort/snort.conf -i ${SNORT_IFACE} -l /var/log/snort -A json
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SNORTSVC

log_ok "Snort configure — interface : ${SNORT_IFACE}"

# ================================================================
# ETAPE 8 — INSTALLATION WAZUH
# ================================================================
log_etape "Etape 8/10 — Installation de Wazuh SIEM"

log_info "Ajout du depot Wazuh..."

curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
    gpg --dearmor | \
    tee /usr/share/keyrings/wazuh.gpg > /dev/null

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | \
    tee /etc/apt/sources.list.d/wazuh.list > /dev/null

apt-get update -qq
log_ok "Depot Wazuh ajoute"

log_info "Installation Wazuh Manager..."
apt-get install -y -qq wazuh-manager
log_ok "Wazuh Manager installe"

log_info "Installation Wazuh Indexer..."
apt-get install -y -qq wazuh-indexer
log_ok "Wazuh Indexer installe"

log_info "Installation Wazuh Dashboard..."
apt-get install -y -qq wazuh-dashboard
log_ok "Wazuh Dashboard installe"

# Generer les credentials Wazuh
WAZUH_API_USER="wazuh-api"
WAZUH_API_PASS=$(openssl rand -hex 16)
WAZUH_DASH_PASS=$(openssl rand -hex 16)

# Configuration API Wazuh
cat > /var/ossec/api/configuration/api.yaml << WAPICONF
host: 0.0.0.0
port: 55000
https:
  enabled: true
  key: "api/configuration/ssl/server.key"
  cert: "api/configuration/ssl/server.crt"
logs:
  level: "info"
access:
  max_login_attempts: 5
  block_time: 300
  max_request_per_minute: 300
WAPICONF

log_ok "API Wazuh configuree — port 55000"

# ================================================================
# ETAPE 9 — LIAISON SNORT VERS WAZUH
# ================================================================
log_etape "Etape 9/10 — Liaison Snort vers Wazuh"

log_info "Configuration de Wazuh pour lire les logs Snort..."

OSSEC_CONF="/var/ossec/etc/ossec.conf"
cp "$OSSEC_CONF" "${OSSEC_CONF}.backup"

# Ajouter la configuration Snort dans ossec.conf
python3 << 'PYCONF'
conf = "/var/ossec/etc/ossec.conf"
bloc = """
  <!-- SIEM Africa — Logs Snort IDS -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/snort/alert.json</location>
    <label key="source">snort</label>
  </localfile>
"""
with open(conf, 'r') as f:
    contenu = f.read()

if "alert.json" not in contenu:
    contenu = contenu.replace("</ossec_config>", bloc + "\n</ossec_config>")
    with open(conf, 'w') as f:
        f.write(contenu)
    print("Liaison Snort configuree dans ossec.conf")
else:
    print("Liaison Snort deja presente dans ossec.conf")
PYCONF

# Regles Wazuh pour Snort
cat > /var/ossec/etc/rules/snort_siem_africa.xml << 'SRULES'
<!-- SIEM Africa — Regles Wazuh pour Snort -->
<group name="snort,ids,siem-africa,">

  <rule id="100001" level="3">
    <decoded_as>json</decoded_as>
    <field name="source">snort</field>
    <description>Snort IDS - Alerte detectee</description>
  </rule>

  <rule id="100002" level="14">
    <if_sid>100001</if_sid>
    <field name="priority">1</field>
    <description>Snort IDS - Alerte CRITIQUE priorite 1</description>
  </rule>

  <rule id="100003" level="10">
    <if_sid>100001</if_sid>
    <field name="priority">2</field>
    <description>Snort IDS - Alerte HAUTE priorite 2</description>
  </rule>

  <rule id="100004" level="7">
    <if_sid>100001</if_sid>
    <field name="priority">3</field>
    <description>Snort IDS - Alerte MOYENNE priorite 3</description>
  </rule>

  <rule id="100005" level="4">
    <if_sid>100001</if_sid>
    <field name="priority">4</field>
    <description>Snort IDS - Alerte FAIBLE priorite 4</description>
  </rule>

</group>
SRULES

log_ok "Regles Wazuh pour Snort creees"

# Demarrer les services
log_info "Demarrage des services..."
systemctl daemon-reload

systemctl enable wazuh-manager
systemctl start wazuh-manager
sleep 5

if systemctl is-active --quiet wazuh-manager; then
    log_ok "Wazuh Manager demarre"
else
    log_warn "Wazuh Manager non demarre — verifiez : journalctl -u wazuh-manager"
fi

systemctl enable wazuh-indexer
systemctl start wazuh-indexer
sleep 5

if systemctl is-active --quiet wazuh-indexer; then
    log_ok "Wazuh Indexer demarre"
else
    log_warn "Wazuh Indexer non demarre"
fi

systemctl enable wazuh-dashboard
systemctl start wazuh-dashboard
sleep 3

if systemctl is-active --quiet wazuh-dashboard; then
    log_ok "Wazuh Dashboard demarre"
else
    log_warn "Wazuh Dashboard non demarre"
fi

systemctl enable snort
systemctl start snort
sleep 2

if systemctl is-active --quiet snort; then
    log_ok "Snort IDS demarre"
else
    log_warn "Snort non demarre — verifiez la configuration"
fi

# ================================================================
# ETAPE 10 — GENERATION DES FICHIERS DE CONFIGURATION
# ================================================================
log_etape "Etape 10/10 — Generation des fichiers"

mkdir -p /opt/siem-africa
mkdir -p /opt/siem-africa/rapports/installation

SECRET_KEY=$(openssl rand -hex 32)

# ── FICHIER CREDENTIALS ──────────────────────────────────────
CRED_FILE="/opt/siem-africa/credentials.txt"

cat > "$CRED_FILE" << CREDENTIALS
================================================================
  SIEM Africa — Fichier de credentials
  Organisation : ${ORG_NAME}
  Serveur      : ${SERVER_IP}
  Date         : $(date '+%d/%m/%Y a %H:%M:%S')
================================================================
  CONFIDENTIEL — Ne partagez JAMAIS ce fichier
================================================================

── UTILISATEURS SYSTEME ──────────────────────────────────────

  snort
  - Role    : Snort IDS
  - Shell   : /sbin/nologin (pas de connexion directe)
  - Dossier : /etc/snort/ et /var/log/snort/

  wazuh
  - Role    : Wazuh SIEM
  - Shell   : /sbin/nologin (pas de connexion directe)
  - Dossier : /var/ossec/

  siem-africa
  - Role    : Dashboard + Agent
  - Shell   : /sbin/nologin (pas de connexion directe)
  - Dossier : /opt/siem-africa/

── SNORT IDS ─────────────────────────────────────────────────
  Interface      : ${SNORT_IFACE}
  Configuration  : /etc/snort/snort.conf
  Logs JSON      : /var/log/snort/alert.json
  Service        : snort.service
  Verifier       : systemctl status snort

── WAZUH SIEM ────────────────────────────────────────────────
  Dashboard URL  : https://${SERVER_IP}
  Login          : admin
  Mot de passe   : ${WAZUH_DASH_PASS}
  IMPORTANT      : Changer a la premiere connexion

  API URL        : https://${SERVER_IP}:55000
  API User       : ${WAZUH_API_USER}
  API Password   : ${WAZUH_API_PASS}

── SIEM AFRICA DASHBOARD ─────────────────────────────────────
  URL            : http://${SERVER_IP}:5000
  Login          : admin
  Mot de passe   : ${ADMIN_PASS}
  IMPORTANT      : Changer login ET mot de passe
                   a la premiere connexion

── FICHIERS IMPORTANTS ───────────────────────────────────────
  Ce fichier     : /opt/siem-africa/credentials.txt
  Configuration  : /opt/siem-africa/.env
  Logs Snort     : /var/log/snort/alert.json
  Logs Wazuh     : /var/ossec/logs/
  Journal inst.  : /var/log/siem-africa-install.log
  Rapports       : /opt/siem-africa/rapports/

── COMMANDES UTILES ──────────────────────────────────────────
  Voir alertes   : tail -f /var/log/snort/alert.json
  Logs Wazuh     : tail -f /var/ossec/logs/ossec.log
  Restart Snort  : systemctl restart snort
  Restart Wazuh  : systemctl restart wazuh-manager
  Mise a jour    : cd /opt/siem-africa && sudo bash update.sh

── PROCHAINE ETAPE ───────────────────────────────────────────
  Module 2 — Base de donnees
  Commande : cd ../2-database && sudo bash install.sh

================================================================
CREDENTIALS

chmod 600 "$CRED_FILE"
chown root:root "$CRED_FILE"
log_ok "credentials.txt genere : ${CRED_FILE}"

# ── FICHIER .ENV ──────────────────────────────────────────────
ENV_FILE="/opt/siem-africa/.env"

cat > "$ENV_FILE" << ENV
# SIEM Africa — Configuration
# Organisation : ${ORG_NAME}
# Date : $(date)

ORG_NAME=${ORG_NAME}
LANG=${SIEM_LANG}
SERVER_IP=${SERVER_IP}
FLASK_PORT=5000
SECRET_KEY=${SECRET_KEY}

SNORT_INTERFACE=${SNORT_IFACE}
SNORT_LOG=/var/log/snort/alert.json

WAZUH_HOST=127.0.0.1
WAZUH_PORT=55000
WAZUH_USER=${WAZUH_API_USER}
WAZUH_PASSWORD=${WAZUH_API_PASS}

DB_PATH=/opt/siem-africa/siem_africa.db
ADMIN_EMAIL=${ADMIN_EMAIL}

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
WEEKLY_REPORT_TIME=08:00
WEEKLY_REPORT_DAY=0
ENV

chmod 600 "$ENV_FILE"
chown siem-africa:siem-africa "$ENV_FILE" 2>/dev/null || true

# Permissions generales
chown -R siem-africa:siem-africa /opt/siem-africa 2>/dev/null || true
chmod 750 /opt/siem-africa

log_ok ".env genere : ${ENV_FILE}"

# ── RAPPORT D'INSTALLATION ────────────────────────────────────
RAPPORT="/opt/siem-africa/rapports/installation/rapport_module1_$(date +%Y%m%d_%H%M%S).txt"

cat > "$RAPPORT" << RAPPORT_CONTENU
================================================================
  SIEM Africa — Rapport Module 1
  Organisation : ${ORG_NAME}
  Date : $(date '+%d/%m/%Y a %H:%M:%S')
================================================================
STATUT : INSTALLATION REUSSIE

Systeme : ${OS_NAME} ${OS_VERSION}
RAM     : ${RAM_AFFICHE} GB
Disque  : ${DISK_GB} GB libres
CPU     : ${CPU_CORES} coeurs
IP      : ${SERVER_IP}

Utilisateurs crees :
  - snort
  - wazuh
  - siem-africa

Composants installes :
  - Snort IDS     : $(snort --version 2>&1 | head -1)
  - Wazuh Manager : installe
  - Wazuh Indexer : installe
  - Wazuh Dashboard : https://${SERVER_IP}
  - Liaison Snort vers Wazuh : configuree

Fichiers generes :
  - /opt/siem-africa/credentials.txt
  - /opt/siem-africa/.env

Prochaine etape :
  cd ../2-database && sudo bash install.sh
================================================================
RAPPORT_CONTENU

log_ok "Rapport : ${RAPPORT}"

# ================================================================
# RESUME FINAL
# ================================================================
echo ""
echo -e "${GREEN}===================================================${NC}"
echo -e "${GREEN}  MODULE 1 — INSTALLATION TERMINEE AVEC SUCCES${NC}"
echo -e "${GREEN}===================================================${NC}"
echo ""
echo -e "  ${BOLD}Utilisateurs systeme :${NC}"
echo -e "  ${GREEN}[OK]${NC} snort"
echo -e "  ${GREEN}[OK]${NC} wazuh"
echo -e "  ${GREEN}[OK]${NC} siem-africa"
echo ""
echo -e "  ${BOLD}Services :${NC}"
echo -e "  ${GREEN}[OK]${NC} Snort IDS — interface ${CYAN}${SNORT_IFACE}${NC}"
echo -e "  ${GREEN}[OK]${NC} Wazuh Manager — API ${CYAN}:55000${NC}"
echo -e "  ${GREEN}[OK]${NC} Wazuh Dashboard — ${CYAN}https://${SERVER_IP}${NC}"
echo ""
echo -e "  ${BOLD}Fichiers importants :${NC}"
echo -e "  ${GREEN}[OK]${NC} ${CYAN}/opt/siem-africa/credentials.txt${NC}"
echo -e "  ${GREEN}[OK]${NC} ${CYAN}/opt/siem-africa/.env${NC}"
echo ""
echo -e "  ${BOLD}Prochaine etape :${NC}"
echo -e "  ${YELLOW}cd ../2-database && sudo bash install.sh${NC}"
echo ""
echo -e "  Tous vos acces sont dans : ${CYAN}/opt/siem-africa/credentials.txt${NC}"
echo ""
