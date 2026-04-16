#!/bin/bash
# ================================================================
#  SIEM Africa — Installation Globale Modules 1 + 2 + 3
#  Fichier  : install_global.sh
#  Version  : 3.0
#  Usage    : sudo bash install_global.sh
#
#  Ce script installe dans l'ordre :
#  ✓ Module 1 — Snort IDS + Wazuh Manager
#  ✓ Module 2 — Base de données SQLite (380 signatures)
#  ✓ Module 3 — Agent intelligent Python
#
#  Durée estimée : 20 à 45 minutes selon la connexion
# ================================================================

# Pas de set -e — gestion d'erreurs explicite
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Configuration ───────────────────────────────────────────────
GITHUB="https://raw.githubusercontent.com/luciesys/SIEM-AFRICA/main"
LOG_FILE="/var/log/siem-africa-install.log"
WORK_DIR="/tmp/siem-africa-install"
ETAPE_ACTUELLE=0
ETAPES_TOTAL=3
DEBUT=$(date +%s)

# ── Fonctions de log ────────────────────────────────────────────
log()       { echo -e "$1" | tee -a "$LOG_FILE"; }
log_ok()    { log "${GREEN}  [✓]${NC} $1"; }
log_info()  { log "${CYAN}  [→]${NC} $1"; }
log_warn()  { log "${YELLOW}  [!]${NC} $1"; }
log_err()   { log "${RED}  [✗]${NC} $1"; }

quitter() {
    log ""
    log_err "ECHEC : $1"
    log ""
    log "${YELLOW}Journal complet : $LOG_FILE${NC}"
    log "${YELLOW}Pour reprendre : sudo bash install_global.sh${NC}"
    exit 1
}

# ── Bannière principale ─────────────────────────────────────────
show_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║                                                          ║"
    echo "  ║           SIEM AFRICA — Installation Globale            ║"
    echo "  ║           Modules 1 + 2 + 3                             ║"
    echo "  ║           Version 3.0                                   ║"
    echo "  ║                                                          ║"
    echo "  ║           github.com/luciesys/SIEM-AFRICA               ║"
    echo "  ║                                                          ║"
    echo "  ╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo -e "  Ce script va installer :"
    echo -e "  ${GREEN}  Module 1${NC} — Snort IDS + Wazuh Manager"
    echo -e "  ${GREEN}  Module 2${NC} — Base SQLite (380 signatures MITRE ATT&CK)"
    echo -e "  ${GREEN}  Module 3${NC} — Agent intelligent Python + Honeypots"
    echo ""
    echo -e "  ${YELLOW}Durée estimée : 20 à 45 minutes${NC}"
    echo ""
}

# ── Barre de progression ────────────────────────────────────────
barre_module() {
    local num="$1" nom="$2" statut="$3"
    local sym=""
    case "$statut" in
        "fait")    sym="${GREEN}[✓]${NC}" ;;
        "encours") sym="${YELLOW}[→]${NC}" ;;
        "attente") sym="${CYAN}[ ]${NC}" ;;
    esac
    echo -e "  $sym Module $num — $nom"
}

afficher_progression() {
    echo ""
    echo -e "${BOLD}  Progression de l'installation :${NC}"
    echo "  ─────────────────────────────────────────"
    case "$ETAPE_ACTUELLE" in
        0)
            barre_module "1" "Snort IDS + Wazuh Manager" "attente"
            barre_module "2" "Base SQLite" "attente"
            barre_module "3" "Agent Python + Honeypots" "attente"
            ;;
        1)
            barre_module "1" "Snort IDS + Wazuh Manager" "encours"
            barre_module "2" "Base SQLite" "attente"
            barre_module "3" "Agent Python + Honeypots" "attente"
            ;;
        2)
            barre_module "1" "Snort IDS + Wazuh Manager" "fait"
            barre_module "2" "Base SQLite" "encours"
            barre_module "3" "Agent Python + Honeypots" "attente"
            ;;
        3)
            barre_module "1" "Snort IDS + Wazuh Manager" "fait"
            barre_module "2" "Base SQLite" "fait"
            barre_module "3" "Agent Python + Honeypots" "encours"
            ;;
        4)
            barre_module "1" "Snort IDS + Wazuh Manager" "fait"
            barre_module "2" "Base SQLite" "fait"
            barre_module "3" "Agent Python + Honeypots" "fait"
            ;;
    esac
    echo "  ─────────────────────────────────────────"
    echo ""
}

# ── Entête d'étape ──────────────────────────────────────────────
debut_etape() {
    local num="$1" titre="$2"
    ETAPE_ACTUELLE=$num
    echo ""
    log "${BLUE}${BOLD}┌──────────────────────────────────────────────────────────┐${NC}"
    log "${BLUE}${BOLD}│  MODULE $num / 3 — $titre${NC}"
    log "${BLUE}${BOLD}└──────────────────────────────────────────────────────────┘${NC}"
    echo ""
    afficher_progression
}

# ── Vérifications préalables ────────────────────────────────────
verifications() {
    log "${BOLD}Vérifications préalables...${NC}"
    echo ""

    # Root
    if [ "$EUID" -ne 0 ]; then
        quitter "Ce script doit être lancé avec sudo : sudo bash install_global.sh"
    fi
    log_ok "Droits root confirmés"

    # OS
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|debian) log_ok "OS compatible : $PRETTY_NAME" ;;
            *) quitter "OS non supporté : $PRETTY_NAME. Requis : Ubuntu 20.04/22.04/24.04 ou Debian 11/12" ;;
        esac
    else
        quitter "Impossible de détecter l'OS"
    fi

    # RAM
    RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$RAM_GB" -lt 4 ]; then
        quitter "RAM insuffisante : ${RAM_GB}GB détectés, minimum 4GB requis"
    fi
    log_ok "RAM suffisante : ${RAM_GB}GB"

    # Disque
    DISQUE_GB=$(df -BG / | awk 'NR==2{print $4}' | tr -d 'G')
    if [ "$DISQUE_GB" -lt 20 ]; then
        quitter "Espace disque insuffisant : ${DISQUE_GB}GB libres, minimum 20GB requis"
    fi
    log_ok "Espace disque suffisant : ${DISQUE_GB}GB libres"

    # Internet
    if ! ping -c 1 -W 5 8.8.8.8 > /dev/null 2>&1; then
        quitter "Pas de connexion internet. Vérifier la connexion réseau."
    fi
    log_ok "Connexion internet disponible"

    # Python3
    if ! command -v python3 &>/dev/null; then
        log_warn "Python3 non trouvé — installation..."
        apt-get install -y python3 python3-pip > /dev/null 2>&1
    fi
    log_ok "Python3 disponible : $(python3 --version)"
}

# ── Choix de langue ─────────────────────────────────────────────
choisir_langue() {
    echo ""
    echo -e "${BOLD}  Choisissez la langue / Choose your language :${NC}"
    echo ""
    echo "  1) Français"
    echo "  2) English"
    echo ""
    read -p "  Choix / Choice [1]: " CHOIX_LANGUE
    CHOIX_LANGUE=${CHOIX_LANGUE:-1}

    case "$CHOIX_LANGUE" in
        2) LANGUE="en" ;;
        *) LANGUE="fr" ;;
    esac

    log_ok "Langue sélectionnée : $([ "$LANGUE" = "en" ] && echo "English" || echo "Français")"
}

# ── Informations organisation ───────────────────────────────────
saisir_infos() {
    echo ""
    echo -e "${BOLD}  Informations de votre organisation :${NC}"
    echo ""

    read -p "  Nom de l'organisation : " ORG_NOM
    ORG_NOM=${ORG_NOM:-"Mon Entreprise"}

    read -p "  Email pour les alertes de sécurité : " ALERT_EMAIL
    while [ -z "$ALERT_EMAIL" ]; do
        echo -e "  ${RED}L'email est obligatoire.${NC}"
        read -p "  Email pour les alertes : " ALERT_EMAIL
    done

    read -p "  IP de ce serveur [auto-détectée] : " SERVER_IP_INPUT
    if [ -z "$SERVER_IP_INPUT" ]; then
        INTERFACE=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
        SERVER_IP=$(ip -4 addr show "$INTERFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+' | head -1)
    else
        SERVER_IP="$SERVER_IP_INPUT"
    fi

    echo ""
    echo -e "${BOLD}  Récapitulatif :${NC}"
    echo -e "  Organisation  : ${GREEN}$ORG_NOM${NC}"
    echo -e "  Email alertes : ${GREEN}$ALERT_EMAIL${NC}"
    echo -e "  IP serveur    : ${GREEN}$SERVER_IP${NC}"
    echo -e "  Langue        : ${GREEN}$([ "$LANGUE" = "en" ] && echo "English" || echo "Français")${NC}"
    echo ""
    read -p "  Confirmer et lancer l'installation ? [O/n] : " CONFIRM
    CONFIRM=${CONFIRM:-O}
    case "$CONFIRM" in
        [nN]) echo "Installation annulée."; exit 0 ;;
    esac
}

# ── Téléchargement des fichiers ─────────────────────────────────
telecharger_fichiers() {
    log_info "Téléchargement des fichiers depuis GitHub..."
    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR"

    # Module 1
    log_info "Module 1 — install.sh..."
    curl -sL "${GITHUB}/installation/install.sh" -o m1_install.sh
    [ ! -s m1_install.sh ] && quitter "Impossible de télécharger le script Module 1"

    # Module 2
    log_info "Module 2 — install.sh, schema.sql, attacks.sql..."
    curl -sL "${GITHUB}/database/install.sh"   -o m2_install.sh
    curl -sL "${GITHUB}/database/schema.sql"   -o schema.sql
    curl -sL "${GITHUB}/database/attacks.sql"  -o attacks.sql
    [ ! -s m2_install.sh ] && quitter "Impossible de télécharger le script Module 2"
    [ ! -s schema.sql ]    && quitter "Impossible de télécharger schema.sql"
    [ ! -s attacks.sql ]   && quitter "Impossible de télécharger attacks.sql"

    # Module 3
    log_info "Module 3 — install.sh, agent.py..."
    curl -sL "${GITHUB}/agent/install.sh"  -o m3_install.sh
    curl -sL "${GITHUB}/agent/agent.py"    -o agent.py
    [ ! -s m3_install.sh ] && quitter "Impossible de télécharger le script Module 3"
    [ ! -s agent.py ]      && quitter "Impossible de télécharger agent.py"

    log_ok "Tous les fichiers téléchargés"
}

# ── Module 1 ────────────────────────────────────────────────────
installer_module1() {
    debut_etape 1 "Snort IDS + Wazuh Manager"

    log_info "Lancement du script Module 1..."
    echo ""

    # Passer les infos via des variables d'environnement
    export SIEM_LANGUE="$LANGUE"
    export SIEM_ORG="$ORG_NOM"
    export SIEM_SERVER_IP="$SERVER_IP"
    export SIEM_NON_INTERACTIF="1"

    cd "$WORK_DIR"
    bash ./m1_install.sh
    local EXIT_CODE=$?
    cd /tmp

    if [ $EXIT_CODE -ne 0 ]; then
        quitter "Le Module 1 a échoué (code $EXIT_CODE). Voir $LOG_FILE"
    fi

    # Vérifier que les services tournent
    sleep 5
    if ! systemctl is-active wazuh-manager > /dev/null 2>&1; then
        quitter "wazuh-manager n'est pas actif après l'installation"
    fi
    log_ok "wazuh-manager actif ✓"

    if ! systemctl is-active snort > /dev/null 2>&1; then
        log_warn "snort n'est pas actif — vérifier la configuration"
    else
        log_ok "snort actif ✓"
    fi

    log_ok "Module 1 installé avec succès"
}

# ── Module 2 ────────────────────────────────────────────────────
installer_module2() {
    debut_etape 2 "Base de données SQLite"

    log_info "Lancement du script Module 2..."
    echo ""

    export SIEM_LANGUE="$LANGUE"
    export SIEM_ORG="$ORG_NOM"
    export SIEM_NON_INTERACTIF="1"
    export SIEM_SCHEMA_PATH="$WORK_DIR/schema.sql"
    export SIEM_ATTACKS_PATH="$WORK_DIR/attacks.sql"

    cd "$WORK_DIR"
    bash ./m2_install.sh
    local EXIT_CODE=$?
    cd /tmp

    if [ $EXIT_CODE -ne 0 ]; then
        quitter "Le Module 2 a échoué (code $EXIT_CODE). Voir $LOG_FILE"
    fi

    # Vérifier la base
    DB_PATH="/opt/siem-africa/siem_africa.db"
    if [ ! -f "$DB_PATH" ]; then
        quitter "La base de données n'a pas été créée : $DB_PATH"
    fi

    NB_SIG=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM attaques;" 2>/dev/null)
    if [ "$NB_SIG" -lt 300 ]; then
        quitter "Base incomplète : seulement $NB_SIG signatures (attendu : 380)"
    fi

    log_ok "Base de données créée : $NB_SIG signatures chargées ✓"
    log_ok "Module 2 installé avec succès"
}

# ── Module 3 ────────────────────────────────────────────────────
installer_module3() {
    debut_etape 3 "Agent intelligent Python + Honeypots"

    cp "$WORK_DIR/agent.py" /tmp/agent.py

    cd "$WORK_DIR"
    bash ./m3_install.sh
    local EXIT_CODE=$?
    cd /tmp

    if [ $EXIT_CODE -ne 0 ]; then
        quitter "Le Module 3 a échoué (code $EXIT_CODE). Voir $LOG_FILE"
    fi

    # Vérifier que le service tourne
    sleep 5
    if ! systemctl is-active siem-agent > /dev/null 2>&1; then
        quitter "siem-agent n'est pas actif après l'installation"
    fi

    log_ok "siem-agent actif ✓"
    log_ok "Module 3 installé avec succès"
}

# ── Configuration SMTP optionnelle ──────────────────────────────
configurer_smtp() {
    echo ""
    echo -e "${BOLD}  Configuration SMTP (emails d'alerte) :${NC}"
    echo ""
    echo -e "  Les alertes critiques seront envoyées à : ${GREEN}$ALERT_EMAIL${NC}"
    echo ""
    read -p "  Configurer le SMTP maintenant ? [O/n] : " CONF_SMTP
    CONF_SMTP=${CONF_SMTP:-O}

    case "$CONF_SMTP" in
        [nN])
            log_warn "SMTP non configuré — vous pouvez le faire plus tard avec :"
            log_warn "sudo bash /opt/siem-africa/install-smtp.sh"
            ;;
        *)
            log_info "Téléchargement du script SMTP..."
            curl -sL "${GITHUB}/agent/install-smtp.sh" -o /tmp/install-smtp.sh
            if [ -s /tmp/install-smtp.sh ]; then
                bash /tmp/install-smtp.sh
            else
                log_warn "Impossible de télécharger le script SMTP"
                log_warn "Configurer manuellement : sudo bash install-smtp.sh"
            fi
            ;;
    esac
}

# ── Résumé final ────────────────────────────────────────────────
afficher_resume() {
    ETAPE_ACTUELLE=4
    local FIN=$(date +%s)
    local DUREE=$(( (FIN - DEBUT) / 60 ))

    echo ""
    log "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    log "${GREEN}${BOLD}║         INSTALLATION TERMINÉE AVEC SUCCÈS !              ║${NC}"
    log "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    afficher_progression
    echo ""

    log "${BOLD}  Durée totale : ${DUREE} minutes${NC}"
    echo ""
    log "${BOLD}  Services actifs :${NC}"

    for svc in snort wazuh-manager siem-agent; do
        if systemctl is-active "$svc" > /dev/null 2>&1; then
            log_ok "$svc"
        else
            log_warn "$svc — inactif (vérifier avec : sudo systemctl status $svc)"
        fi
    done

    echo ""
    log "${BOLD}  Informations importantes :${NC}"
    log "  Organisation  : ${GREEN}$ORG_NOM${NC}"
    log "  IP serveur    : ${GREEN}$SERVER_IP${NC}"
    log "  Email alertes : ${GREEN}$ALERT_EMAIL${NC}"
    log "  Honeypots     : ${GREEN}SSH:2222 | HTTP:8888 | MySQL:3307${NC}"
    echo ""
    log "  Credentials   : ${YELLOW}sudo cat /opt/siem-africa/credentials.txt${NC}"
    log "  Logs agent    : ${YELLOW}sudo tail -f /var/log/siem-africa/agent.log${NC}"
    log "  Logs install  : ${YELLOW}$LOG_FILE${NC}"
    echo ""
    log "${BOLD}  Prochaines étapes :${NC}"
    log "  ${CYAN}1.${NC} Installer le Module 4 (Dashboard) :"
    log "     ${YELLOW}curl -sL ${GITHUB}/dashboard/install.sh | sudo bash${NC}"
    echo ""
    log "  ${CYAN}2.${NC} Tester les honeypots depuis un autre PC :"
    log "     ${YELLOW}ssh -p 2222 test@$SERVER_IP${NC}"
    log "     ${YELLOW}curl http://$SERVER_IP:8888${NC}"
    echo ""
    log "  ${CYAN}3.${NC} Vérifier les alertes en temps réel :"
    log "     ${YELLOW}sudo tail -f /var/log/siem-africa/agent.log${NC}"
    echo ""
    log "${GREEN}${BOLD}  SIEM Africa est opérationnel. Bonne surveillance !${NC}"
    echo ""
}

# ════════════════════════════════════════════════════════════════
#  POINT D'ENTRÉE PRINCIPAL
# ════════════════════════════════════════════════════════════════
main() {
    # Créer le répertoire de log
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"

    log "================================================================"
    log "  SIEM Africa — Installation Globale — $(date)"
    log "================================================================"

    show_banner
    verifications
    choisir_langue
    saisir_infos
    telecharger_fichiers

    echo ""
    echo -e "${BOLD}  L'installation va commencer dans 3 secondes...${NC}"
    sleep 3

    installer_module1
    installer_module2
    installer_module3
    configurer_smtp
    afficher_resume

    # Sauvegarder le script SMTP pour usage futur
    curl -sL "${GITHUB}/agent/install-smtp.sh" \
        -o /opt/siem-africa/install-smtp.sh 2>/dev/null
    chmod +x /opt/siem-africa/install-smtp.sh 2>/dev/null

    exit 0
}

main "$@"
