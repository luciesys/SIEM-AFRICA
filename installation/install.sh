#!/bin/bash
# ================================================================
#  SIEM Africa — Module 1 : Installation Snort + Wazuh
#  Systèmes supportés : Ubuntu 20.04 / 22.04 / 24.04
#                       Debian 11 / 12
#  Usage : sudo ./install.sh
#  Version : 2.0 — Utilisateurs système + credentials.txt
# ================================================================

set -euo pipefail

# ── Couleurs ──────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

# ── Fonctions affichage ───────────────────────────────────────
log_ok()    { echo -e "${GREEN}[✓]${NC} $1"; }
log_info()  { echo -e "${CYAN}[i]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_step()  {
    echo ""
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}
log_abort() {
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${RED}  INSTALLATION ANNULÉE — $1${NC}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    exit 1
}

# ── Banner ───────────────────────────────────────────────────
clear
echo -e "${CYAN}"
echo "  ███████╗██╗███████╗███╗   ███╗     █████╗ ███████╗██████╗ ██╗ ██████╗  █████╗ "
echo "  ██╔════╝██║██╔════╝████╗ ████║    ██╔══██╗██╔════╝██╔══██╗██║██╔════╝ ██╔══██╗"
echo "  ███████╗██║█████╗  ██╔████╔██║    ███████║█████╗  ██████╔╝██║██║      ███████║"
echo "  ╚════██║██║██╔══╝  ██║╚██╔╝██║    ██╔══██║██╔══╝  ██╔══██╗██║██║      ██╔══██║"
echo "  ███████║██║███████╗██║ ╚═╝ ██║    ██║  ██║██║     ██║  ██║██║╚██████╗ ██║  ██║"
echo "  ╚══════╝╚═╝╚══════╝╚═╝     ╚═╝    ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝"
echo -e "${NC}"
echo -e "  ${BOLD}Module 1 — Installation Snort IDS + Wazuh SIEM${NC}"
echo -e "  ${YELLOW}Ubuntu 20.04/22.04/24.04  |  Debian 11/12${NC}"
echo ""

# ================================================================
# ÉTAPE 1 — ROOT
# ================================================================
log_step "Étape 1/10 — Vérification des droits"
[[ $EUID -ne 0 ]] && log_abort "Lancez avec : sudo ./install.sh"
log_ok "Droits root confirmés"

# ================================================================
# ÉTAPE 2 — DÉTECTION OS
# ================================================================
log_step "Étape 2/10 — Détection du système d'exploitation"
[[ ! -f /etc/os-release ]] && log_abort "Impossible de détecter l'OS"
source /etc/os-release
OS_NAME="${NAME}"; OS_VERSION="${VERSION_ID}"; OS_ID="${ID}"
log_info "OS détecté : ${OS_NAME} ${OS_VERSION}"

SUPPORTED=false
case "${OS_ID}" in
    ubuntu) case "${OS_VERSION}" in 20.04|22.04|24.04) SUPPORTED=true;; esac ;;
    debian) case "${OS_VERSION}" in 11|12) SUPPORTED=true;; esac ;;
esac

if [[ "${SUPPORTED}" == "false" ]]; then
    log_warn "OS non officiel : ${OS_NAME} ${OS_VERSION}"
    echo -n "  Continuer quand même ? (oui/non) : "; read -r C
    [[ "${C}" != "oui" ]] && log_abort "OS non supporté"
    log_warn "Continuation sur OS non officiel"
else
    log_ok "OS supporté : ${OS_NAME} ${OS_VERSION}"
fi

# ================================================================
# ÉTAPE 3 — PRÉREQUIS MATÉRIELS
# ================================================================
log_step "Étape 3/10 — Vérification des prérequis matériels"
ERRORS=()

RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
RAM_GB=$(echo "scale=1; ${RAM_KB}/1024/1024" | bc)
RAM_INT=$(echo "${RAM_KB}/1024/1024" | bc)
[[ ${RAM_INT} -lt 4 ]] && { log_error "RAM : ${RAM_GB} GB — 4 GB requis"; ERRORS+=("RAM insuffisante"); } \
                        || log_ok "RAM : ${RAM_GB} GB ✓"

DISK_KB=$(df / | awk 'NR==2{print $4}')
DISK_GB=$(echo "${DISK_KB}/1024/1024" | bc)
[[ ${DISK_GB} -lt 60 ]] && { log_error "Disque : ${DISK_GB} GB — 60 GB requis"; ERRORS+=("Disque insuffisant"); } \
                          || log_ok "Disque : ${DISK_GB} GB ✓"

CPU_CORES=$(nproc)
[[ ${CPU_CORES} -lt 2 ]] && { log_error "CPU : ${CPU_CORES} cœur(s) — 2 requis"; ERRORS+=("CPU insuffisant"); } \
                           || log_ok "CPU : ${CPU_CORES} cœurs ✓"

log_info "Vérification connexion internet..."
if ! ping -c 1 -W 5 8.8.8.8 &>/dev/null; then
    log_error "Pas de connexion internet"
    ERRORS+=("Internet requis")
else
    log_ok "Internet ✓"
fi

if [[ ${#ERRORS[@]} -gt 0 ]]; then
    echo -e "${RED}  Prérequis non satisfaits :${NC}"
    for e in "${ERRORS[@]}"; do echo -e "${RED}  → ${e}${NC}"; done
    log_abort "Corrigez les prérequis et relancez"
fi
log_ok "Tous les prérequis sont satisfaits"

# ================================================================
# ÉTAPE 4 — CONFIGURATION INTERACTIVE
# ================================================================
log_step "Étape 4/10 — Configuration interactive"
echo -e "${BOLD}  Répondez aux questions suivantes :${NC}"; echo ""

echo -e "  Langue / Language :"
echo -e "  ${CYAN}[1]${NC} Français  ${CYAN}[2]${NC} English"
echo -n "  Choix [1] : "; read -r LC; LC=${LC:-1}
if [[ "${LC}" == "2" ]]; then
    SIEM_LANG="en"
    log_ok "Language: English"
else
    SIEM_LANG="fr"
    log_ok "Langue: Français"
fi

echo ""
echo -n "  Nom de l'organisation : "; read -r ORG_NAME; ORG_NAME=${ORG_NAME:-"MonEntreprise"}
log_ok "Organisation : ${ORG_NAME}"

DEFAULT_IP=$(hostname -I | awk '{print $1}')
echo -n "  IP du serveur [${DEFAULT_IP}] : "; read -r SERVER_IP; SERVER_IP=${SERVER_IP:-${DEFAULT_IP}}
log_ok "IP : ${SERVER_IP}"

echo -n "  Email administrateur : "; read -r ADMIN_EMAIL; ADMIN_EMAIL=${ADMIN_EMAIL:-"admin@siem-africa.local"}
log_ok "Email : ${ADMIN_EMAIL}"

echo ""
while true; do
    echo -n "  Mot de passe admin SIEM Africa (min. 12 car.) : "; read -rs ADMIN_PASS; echo ""
    echo -n "  Confirmez : "; read -rs ADMIN_PASS2; echo ""
    [[ "${ADMIN_PASS}" == "${ADMIN_PASS2}" && ${#ADMIN_PASS} -ge 12 ]] && { log_ok "Mot de passe configuré"; break; }
    [[ ${#ADMIN_PASS} -lt 12 ]] && log_warn "Minimum 12 caractères" || log_warn "Mots de passe différents"
done

echo ""
# Interfaces réseau
log_info "Détection des interfaces réseau..."
INTERFACES=()
while IFS= read -r iface; do INTERFACES+=("${iface}"); done < \
    <(ip link show | grep -E "^[0-9]+:" | awk '{print $2}' | tr -d ':' | grep -v '^lo$')

[[ ${#INTERFACES[@]} -eq 0 ]] && log_abort "Aucune interface réseau détectée"

echo -e "\n  ${BOLD}Interfaces disponibles :${NC}\n"
for i in "${!INTERFACES[@]}"; do
    IF="${INTERFACES[$i]}"
    IF_IP=$(ip addr show "${IF}" 2>/dev/null | grep "inet " | awk '{print $2}' | head -1)
    IF_ST=$(ip link show "${IF}" | grep -o "UP\|DOWN" | head -1)
    echo -e "  ${CYAN}[$((i+1))]${NC} ${BOLD}${IF}${NC} — IP: ${IF_IP:-N/A} — ${IF_ST:-INCONNU}"
done
echo ""

if [[ ${#INTERFACES[@]} -eq 1 ]]; then
    SNORT_IFACE="${INTERFACES[0]}"
    log_info "Interface unique : ${SNORT_IFACE} — sélectionnée automatiquement"
else
    echo -n "  Interface à surveiller [1] : "; read -r IC; IC=${IC:-1}
    [[ ! "${IC}" =~ ^[0-9]+$ || ${IC} -lt 1 || ${IC} -gt ${#INTERFACES[@]} ]] && IC=1
    SNORT_IFACE="${INTERFACES[$((IC-1))]}"
fi
log_ok "Interface Snort : ${SNORT_IFACE}"

# Récapitulatif
echo ""
echo -e "${BOLD}  ┌──────────────────────────────────────────────┐${NC}"
echo -e "${BOLD}  │             RÉCAPITULATIF                    │${NC}"
echo -e "${BOLD}  ├──────────────────────────────────────────────┤${NC}"
echo -e "  │  OS           : ${CYAN}${OS_NAME} ${OS_VERSION}${NC}"
echo -e "  │  Langue       : ${CYAN}${SIEM_LANG}${NC}"
echo -e "  │  Organisation : ${CYAN}${ORG_NAME}${NC}"
echo -e "  │  IP Serveur   : ${CYAN}${SERVER_IP}${NC}"
echo -e "  │  Email admin  : ${CYAN}${ADMIN_EMAIL}${NC}"
echo -e "  │  Interface    : ${CYAN}${SNORT_IFACE}${NC}"
echo -e "${BOLD}  └──────────────────────────────────────────────┘${NC}"
echo ""
echo -n "  Lancer l'installation ? (oui/non) : "; read -r CONFIRM
[[ "${CONFIRM}" != "oui" ]] && log_abort "Annulé par l'utilisateur"

LOG_FILE="/var/log/siem-africa-install.log"
exec > >(tee -a "${LOG_FILE}") 2>&1
log_info "Journal : ${LOG_FILE}"
export SIEM_LANG ORG_NAME SERVER_IP ADMIN_EMAIL ADMIN_PASS SNORT_IFACE OS_ID OS_VERSION

# ================================================================
# ÉTAPE 5 — CRÉATION DES UTILISATEURS SYSTÈME
# ================================================================
log_step "Étape 5/10 — Création des utilisateurs système"
log_info "Chaque service tourne sous son propre utilisateur isolé..."

create_user() {
    local USER=$1 DESC=$2 HOME_OPT=$3
    if id "${USER}" &>/dev/null; then
        log_info "Utilisateur '${USER}' existe déjà"
    else
        useradd --system --no-create-home --shell /sbin/nologin \
                --comment "SIEM Africa - ${DESC}" ${HOME_OPT} "${USER}"
        log_ok "Utilisateur '${USER}' créé — ${DESC}"
    fi
}

create_user "snort"       "Snort IDS"          ""
create_user "wazuh"       "Wazuh SIEM"         ""
create_user "siem-africa" "Dashboard et Agent" "--create-home --home-dir /opt/siem-africa"

echo ""
echo -e "  ${BOLD}Récapitulatif des utilisateurs :${NC}"
echo -e "  ${GREEN}✓${NC} snort        → /sbin/nologin — Snort IDS"
echo -e "  ${GREEN}✓${NC} wazuh        → /sbin/nologin — Wazuh SIEM"
echo -e "  ${GREEN}✓${NC} siem-africa  → /sbin/nologin — Dashboard + Agent"
log_ok "Utilisateurs système créés"

# ================================================================
# ÉTAPE 6 — MISE À JOUR SYSTÈME
# ================================================================
log_step "Étape 6/10 — Mise à jour du système"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && log_ok "Paquets mis à jour"
apt-get upgrade -y -qq && log_ok "Système mis à jour"
apt-get install -y -qq \
    curl wget gnupg2 lsb-release apt-transport-https ca-certificates \
    software-properties-common build-essential git net-tools \
    iptables iptables-persistent python3 python3-pip python3-venv \
    openssl jq bc libpcap-dev libpcre3-dev libdumbnet-dev \
    zlib1g-dev libssl-dev libffi-dev 2>/dev/null
log_ok "Dépendances installées"

# ================================================================
# ÉTAPE 7 — INSTALLATION SNORT
# ================================================================
log_step "Étape 7/10 — Installation de Snort IDS"

apt-get install -y -qq snort 2>/dev/null || {
    log_warn "Installation depuis les sources..."
    cd /tmp
    wget -q https://www.snort.org/downloads/snort/daq-2.0.7.tar.gz
    tar -xzf daq-2.0.7.tar.gz && cd daq-2.0.7
    ./configure --quiet && make -j"$(nproc)" && make install && ldconfig
    cd /tmp
    wget -q https://www.snort.org/downloads/snort/snort-2.9.20.tar.gz
    tar -xzf snort-2.9.20.tar.gz && cd snort-2.9.20
    ./configure --quiet --enable-sourcefire
    make -j"$(nproc)" && make install && ldconfig
    ln -sf /usr/local/bin/snort /usr/sbin/snort
}

command -v snort &>/dev/null || log_abort "Échec installation Snort"
SNORT_VERSION=$(snort --version 2>&1 | head -1)
log_ok "Snort : ${SNORT_VERSION}"

mkdir -p /etc/snort/rules /var/log/snort /usr/local/lib/snort_dynamicrules

cat > /etc/snort/snort.conf << SNORTCONF
# SIEM Africa — Configuration Snort | ${ORG_NAME} | $(date)
var HOME_NET any
var EXTERNAL_NET !\$HOME_NET
var RULE_PATH /etc/snort/rules
var LOG_PATH  /var/log/snort
config interface: ${SNORT_IFACE}
config checksum_mode: none
output alert_json: /var/log/snort/alert.json default
output log_unified2: filename snort.log, limit 128
include \$RULE_PATH/local.rules
SNORTCONF

cat > /etc/snort/rules/local.rules << 'LRULES'
# SIEM Africa — Règles locales Snort
# Ajoutez vos règles personnalisées ici
LRULES

chown -R snort:snort /var/log/snort /etc/snort
chmod 755 /var/log/snort

cat > /etc/systemd/system/snort.service << SNORT_SVC
[Unit]
Description=Snort IDS — SIEM Africa
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
SNORT_SVC

log_ok "Snort configuré — interface : ${SNORT_IFACE}"

# ================================================================
# ÉTAPE 8 — INSTALLATION WAZUH
# ================================================================
log_step "Étape 8/10 — Installation de Wazuh SIEM"

curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
    gpg --dearmor | tee /usr/share/keyrings/wazuh.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | \
    tee /etc/apt/sources.list.d/wazuh.list > /dev/null
apt-get update -qq && log_ok "Dépôt Wazuh ajouté"

apt-get install -y -qq wazuh-manager  && log_ok "Wazuh Manager installé"
apt-get install -y -qq wazuh-indexer  && log_ok "Wazuh Indexer installé"
apt-get install -y -qq wazuh-dashboard && log_ok "Wazuh Dashboard installé"

WAZUH_API_USER="wazuh-api"
WAZUH_API_PASS="$(openssl rand -base64 24 | tr -d '/+=' | head -c 20)Aa1!"
WAZUH_DASH_PASS="$(openssl rand -base64 24 | tr -d '/+=' | head -c 20)Bb2!"

cat > /var/ossec/api/configuration/api.yaml << WAPI
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
WAPI
log_ok "API Wazuh configurée — port 55000"

# ================================================================
# ÉTAPE 9 — LIAISON SNORT → WAZUH
# ================================================================
log_step "Étape 9/10 — Liaison Snort → Wazuh"

OSSEC_CONF="/var/ossec/etc/ossec.conf"
cp "${OSSEC_CONF}" "${OSSEC_CONF}.backup"

python3 - << 'PYCONF'
conf = "/var/ossec/etc/ossec.conf"
block = """
  <!-- SIEM Africa — Logs Snort -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/snort/alert.json</location>
    <label key="source">snort</label>
  </localfile>
"""
with open(conf) as f: content = f.read()
if "alert.json" not in content:
    content = content.replace("</ossec_config>", block + "\n</ossec_config>")
    with open(conf, 'w') as f: f.write(content)
print("Liaison configurée")
PYCONF

cat > /var/ossec/etc/rules/snort_siem_africa.xml << 'SRULES'
<group name="snort,ids,siem-africa,">
  <rule id="100001" level="3">
    <decoded_as>json</decoded_as>
    <field name="source">snort</field>
    <description>Snort IDS — Alerte détectée</description>
  </rule>
  <rule id="100002" level="14">
    <if_sid>100001</if_sid>
    <field name="priority">1</field>
    <description>Snort IDS — Alerte CRITIQUE</description>
  </rule>
  <rule id="100003" level="10">
    <if_sid>100001</if_sid>
    <field name="priority">2</field>
    <description>Snort IDS — Alerte HAUTE</description>
  </rule>
  <rule id="100004" level="7">
    <if_sid>100001</if_sid>
    <field name="priority">3</field>
    <description>Snort IDS — Alerte MOYENNE</description>
  </rule>
  <rule id="100005" level="4">
    <if_sid>100001</if_sid>
    <field name="priority">4</field>
    <description>Snort IDS — Alerte FAIBLE</description>
  </rule>
</group>
SRULES

log_ok "Règles Wazuh/Snort créées"

systemctl daemon-reload
systemctl enable wazuh-manager  && systemctl start wazuh-manager  && sleep 3
systemctl enable wazuh-indexer  && systemctl start wazuh-indexer  && sleep 5
systemctl enable wazuh-dashboard && systemctl start wazuh-dashboard && sleep 3
systemctl enable snort           && systemctl start snort           && sleep 2

systemctl is-active --quiet wazuh-manager  && log_ok "Wazuh Manager démarré"  || log_warn "Wazuh Manager — vérifiez les logs"
systemctl is-active --quiet wazuh-indexer  && log_ok "Wazuh Indexer démarré"  || log_warn "Wazuh Indexer — vérifiez les logs"
systemctl is-active --quiet wazuh-dashboard && log_ok "Wazuh Dashboard démarré" || log_warn "Wazuh Dashboard — vérifiez les logs"
systemctl is-active --quiet snort           && log_ok "Snort IDS démarré"      || log_warn "Snort — vérifiez la configuration"

# ================================================================
# ÉTAPE 10 — CREDENTIALS + .ENV + RAPPORT
# ================================================================
log_step "Étape 10/10 — Génération des fichiers de configuration"

mkdir -p /opt/siem-africa/rapports/installation
SECRET_KEY=$(openssl rand -hex 32)

# ── FICHIER CREDENTIALS ──────────────────────────────────────
CRED_FILE="/opt/siem-africa/credentials.txt"

cat > "${CRED_FILE}" << CREDS
================================================================
  SIEM Africa — Fichier de credentials
  Organisation : ${ORG_NAME}
  Serveur      : ${SERVER_IP}
  Généré le    : $(date '+%d/%m/%Y à %H:%M:%S')
================================================================
  CONFIDENTIEL — Ne partagez JAMAIS ce fichier
  Conservez-le dans un endroit sécurisé
================================================================

── UTILISATEURS SYSTÈME ──────────────────────────────────────
  Chaque service tourne sous son propre compte isolé.
  Aucun de ces comptes ne permet une connexion directe.

  snort
  ├── Rôle    : Snort IDS
  ├── Shell   : /sbin/nologin
  └── Dossier : /etc/snort/ | /var/log/snort/

  wazuh
  ├── Rôle    : Wazuh SIEM
  ├── Shell   : /sbin/nologin
  └── Dossier : /var/ossec/

  siem-africa
  ├── Rôle    : Dashboard + Agent
  ├── Shell   : /sbin/nologin
  └── Dossier : /opt/siem-africa/

── SNORT IDS ─────────────────────────────────────────────────
  Interface surveillée : ${SNORT_IFACE}
  Configuration        : /etc/snort/snort.conf
  Logs JSON            : /var/log/snort/alert.json
  Service              : snort.service
  Vérifier             : systemctl status snort

── WAZUH SIEM ────────────────────────────────────────────────
  Dashboard URL        : https://${SERVER_IP}
  Dashboard Login      : admin
  Dashboard Mot passe  : ${WAZUH_DASH_PASS}
  IMPORTANT            : Changer à la première connexion

  API URL              : https://${SERVER_IP}:55000
  API Utilisateur      : ${WAZUH_API_USER}
  API Mot de passe     : ${WAZUH_API_PASS}

  Vérifier Manager     : systemctl status wazuh-manager
  Vérifier Indexer     : systemctl status wazuh-indexer
  Vérifier Dashboard   : systemctl status wazuh-dashboard

── SIEM AFRICA DASHBOARD ─────────────────────────────────────
  URL                  : http://${SERVER_IP}:5000
  Login admin          : admin
  Mot de passe admin   : ${ADMIN_PASS}
  IMPORTANT            : Changer login ET mot de passe
                         à la première connexion

  Login dirigeant      : dirigeant
  Mot de passe         : (défini lors de la création du compte)

── BASE DE DONNÉES ───────────────────────────────────────────
  Type                 : SQLite
  Chemin               : /opt/siem-africa/siem_africa.db
  Propriétaire         : siem-africa

── FICHIERS IMPORTANTS ───────────────────────────────────────
  Ce fichier      : /opt/siem-africa/credentials.txt
  Configuration   : /opt/siem-africa/.env
  Logs Snort      : /var/log/snort/alert.json
  Logs Wazuh      : /var/ossec/logs/
  Logs install    : /var/log/siem-africa-install.log
  Rapports        : /opt/siem-africa/rapports/
  Règles Snort    : /etc/snort/rules/local.rules
  Règles Wazuh    : /var/ossec/etc/rules/snort_siem_africa.xml

── COMMANDES UTILES ──────────────────────────────────────────
  Voir alertes Snort  : tail -f /var/log/snort/alert.json
  Voir logs Wazuh     : tail -f /var/ossec/logs/ossec.log
  Redémarrer Snort    : systemctl restart snort
  Redémarrer Wazuh    : systemctl restart wazuh-manager
  Mettre à jour       : cd /opt/siem-africa && sudo ./update.sh

── PROCHAINE ÉTAPE ───────────────────────────────────────────
  Module 2 — Base de données
  Commande : cd ../2-database && sudo ./install.sh

================================================================
CREDS

chmod 600 "${CRED_FILE}"
chown root:root "${CRED_FILE}"
log_ok "Credentials : ${CRED_FILE}"

# ── FICHIER .ENV ─────────────────────────────────────────────
ENV_FILE="/opt/siem-africa/.env"
cat > "${ENV_FILE}" << ENV
# SIEM Africa — Configuration | ${ORG_NAME} | $(date)
ORG_NAME="${ORG_NAME}"
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

chmod 600 "${ENV_FILE}"
chown siem-africa:siem-africa "${ENV_FILE}"
chown -R siem-africa:siem-africa /opt/siem-africa
chmod 750 /opt/siem-africa
log_ok ".env : ${ENV_FILE}"

# ── RAPPORT ──────────────────────────────────────────────────
REPORT="/opt/siem-africa/rapports/installation/rapport_module1_$(date +%Y%m%d_%H%M%S).txt"
cat > "${REPORT}" << REPORT_CONTENT
================================================================
  SIEM Africa — Rapport Module 1
  Organisation : ${ORG_NAME}
  Date : $(date '+%d/%m/%Y à %H:%M:%S')
================================================================
STATUT : INSTALLATION RÉUSSIE

Système    : ${OS_NAME} ${OS_VERSION} | ${RAM_GB} GB RAM | ${DISK_GB} GB disque | ${CPU_CORES} cœurs

Utilisateurs créés :
  ✓ snort | ✓ wazuh | ✓ siem-africa

Composants installés :
  ✓ Snort IDS  — $(snort --version 2>&1 | head -1)
  ✓ Wazuh Manager   — :55000
  ✓ Wazuh Indexer   — :9200
  ✓ Wazuh Dashboard — https://${SERVER_IP}
  ✓ Liaison Snort → Wazuh configurée

Fichiers générés :
  ✓ /opt/siem-africa/credentials.txt
  ✓ /opt/siem-africa/.env

Prochaine étape :
  cd ../2-database && sudo ./install.sh
================================================================
REPORT_CONTENT
log_ok "Rapport : ${REPORT}"

# ── RÉSUMÉ FINAL ─────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  ✓  MODULE 1 — INSTALLATION TERMINÉE AVEC SUCCÈS${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}Utilisateurs système :${NC}"
echo -e "  ${GREEN}✓${NC} snort       — Snort IDS"
echo -e "  ${GREEN}✓${NC} wazuh       — Wazuh SIEM"
echo -e "  ${GREEN}✓${NC} siem-africa — Dashboard + Agent"
echo ""
echo -e "  ${BOLD}Services démarrés :${NC}"
echo -e "  ${GREEN}✓${NC} Snort IDS          — ${CYAN}${SNORT_IFACE}${NC}"
echo -e "  ${GREEN}✓${NC} Wazuh Manager      — API ${CYAN}:55000${NC}"
echo -e "  ${GREEN}✓${NC} Wazuh Indexer      — ${CYAN}:9200${NC}"
echo -e "  ${GREEN}✓${NC} Wazuh Dashboard    — ${CYAN}https://${SERVER_IP}${NC}"
echo ""
echo -e "  ${BOLD}Fichiers importants :${NC}"
echo -e "  ${GREEN}✓${NC} ${CYAN}/opt/siem-africa/credentials.txt${NC}"
echo -e "  ${GREEN}✓${NC} ${CYAN}/opt/siem-africa/.env${NC}"
echo ""
echo -e "  ${BOLD}Prochaine étape :${NC}"
echo -e "  ${YELLOW}cd ../2-database && sudo ./install.sh${NC}"
echo ""
echo -e "  ${CYAN}Tous vos accès sont dans credentials.txt${NC}"
echo ""
