#!/bin/bash

#===============================================================================
#
#          FILE: install.sh
#
#         USAGE: curl -sL https://raw.githubusercontent.com/luciesys/siem-africa/main/install.sh | sudo bash
#
#   DESCRIPTION: Installation COMPLÈTE de SIEM Africa en UNE commande
#
#        AUTHOR: SIEM Africa Team
#       VERSION: 1.0
#
#===============================================================================

set -e

#---------------------------------------
# CONFIGURATION
#---------------------------------------
GITHUB_REPO="luciesys/siem-africa"
GITHUB_BRANCH="main"
INSTALL_DIR="/opt/siem-africa"
GITHUB_RAW="https://raw.githubusercontent.com/$GITHUB_REPO/$GITHUB_BRANCH"

#---------------------------------------
# COULEURS
#---------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

#---------------------------------------
# FONCTIONS D'AFFICHAGE
#---------------------------------------
print_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                      ║"
    echo "║     ███████╗██╗███████╗███╗   ███╗     █████╗ ███████╗██████╗       ║"
    echo "║     ██╔════╝██║██╔════╝████╗ ████║    ██╔══██╗██╔════╝██╔══██╗      ║"
    echo "║     ███████╗██║█████╗  ██╔████╔██║    ███████║█████╗  ██████╔╝      ║"
    echo "║     ╚════██║██║██╔══╝  ██║╚██╔╝██║    ██╔══██║██╔══╝  ██╔══██╗      ║"
    echo "║     ███████║██║███████╗██║ ╚═╝ ██║    ██║  ██║██║     ██║  ██║      ║"
    echo "║     ╚══════╝╚═╝╚══════╝╚═╝     ╚═╝    ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝      ║"
    echo "║                                                                      ║"
    echo "║              🛡️  SIEM AFRICA - Installation Complète                 ║"
    echo "║                                                                      ║"
    echo "║     Snort (IDS) + Wazuh (SIEM) + Analyse Intelligente               ║"
    echo "║                                                                      ║"
    echo "╚══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() {
    echo -e "\n${CYAN}══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}\n"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[i]${NC} $1"
}

#---------------------------------------
# VÉRIFICATION ROOT
#---------------------------------------
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Ce script doit être exécuté en tant que root"
        echo ""
        echo "Utilisez : curl -sL $GITHUB_RAW/install.sh | sudo bash"
        exit 1
    fi
    print_success "Droits root confirmés"
}

#---------------------------------------
# VÉRIFICATION SYSTÈME
#---------------------------------------
check_system() {
    print_step "ÉTAPE 1/6 : VÉRIFICATION DU SYSTÈME"
    
    # OS
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
            print_error "Système non supporté : $ID"
            print_info "Seuls Ubuntu et Debian sont supportés"
            exit 1
        fi
        print_success "Système : $PRETTY_NAME"
    fi
    
    # RAM (minimum 4 Go)
    TOTAL_RAM=$(free -m | awk '/^Mem:/{print $2}')
    if [ "$TOTAL_RAM" -lt 3800 ]; then
        print_error "RAM insuffisante : ${TOTAL_RAM} Mo (minimum 4 Go)"
        exit 1
    fi
    print_success "RAM : ${TOTAL_RAM} Mo"
    
    # Stockage (minimum 50 Go)
    AVAILABLE_DISK=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ "$AVAILABLE_DISK" -lt 50 ]; then
        print_error "Stockage insuffisant : ${AVAILABLE_DISK} Go (minimum 50 Go)"
        exit 1
    fi
    print_success "Stockage : ${AVAILABLE_DISK} Go disponibles"
    
    # Internet
    if ! ping -c 1 github.com &> /dev/null; then
        print_error "Pas de connexion Internet"
        exit 1
    fi
    print_success "Connexion Internet : OK"
}

#---------------------------------------
# TÉLÉCHARGEMENT DU PROJET
#---------------------------------------
download_project() {
    print_step "ÉTAPE 2/6 : TÉLÉCHARGEMENT DE SIEM AFRICA"
    
    # Installer les dépendances
    apt-get update > /dev/null 2>&1
    apt-get install -y curl wget unzip jq > /dev/null 2>&1
    
    # Créer le répertoire d'installation
    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR"
    
    print_info "Téléchargement depuis GitHub..."
    
    # Télécharger le repo en ZIP
    curl -sL "https://github.com/$GITHUB_REPO/archive/$GITHUB_BRANCH.zip" -o siem-africa.zip
    
    # Extraire
    unzip -q siem-africa.zip
    mv siem-africa-$GITHUB_BRANCH/* .
    rm -rf siem-africa-$GITHUB_BRANCH siem-africa.zip
    
    # Rendre les scripts exécutables
    find . -name "*.sh" -exec chmod +x {} \;
    
    print_success "Projet téléchargé dans $INSTALL_DIR"
}

#---------------------------------------
# INSTALLATION SNORT + WAZUH
#---------------------------------------
install_siem() {
    print_step "ÉTAPE 3/6 : INSTALLATION SNORT + WAZUH"
    
    print_info "Cette étape peut prendre 20-30 minutes..."
    
    if [ -f "$INSTALL_DIR/installation/install_siem.sh" ]; then
        chmod +x "$INSTALL_DIR/installation/install_siem.sh"
        bash "$INSTALL_DIR/installation/install_siem.sh"
    else
        print_error "Script d'installation non trouvé"
        exit 1
    fi
}

#---------------------------------------
# INSTALLATION BASE DE CONNAISSANCES
#---------------------------------------
install_knowledge_base() {
    print_step "ÉTAPE 4/6 : INSTALLATION BASE DE CONNAISSANCES"
    
    # Créer le répertoire
    mkdir -p /var/ossec/etc/knowledge_base
    
    # Copier la base de données
    if [ -f "$INSTALL_DIR/knowledge_base/attacks.json" ]; then
        cp "$INSTALL_DIR/knowledge_base/attacks.json" /var/ossec/etc/knowledge_base/
        print_success "Base de données (100 attaques) installée"
    fi
    
    if [ -f "$INSTALL_DIR/knowledge_base/severity_levels.json" ]; then
        cp "$INSTALL_DIR/knowledge_base/severity_levels.json" /var/ossec/etc/knowledge_base/
        print_success "Niveaux de gravité installés"
    fi
    
    # Copier l'analyseur
    if [ -f "$INSTALL_DIR/analyzer/alert_analyzer.sh" ]; then
        cp "$INSTALL_DIR/analyzer/alert_analyzer.sh" /var/ossec/integrations/
        chmod +x /var/ossec/integrations/alert_analyzer.sh
        print_success "Analyseur intelligent installé"
    fi
}

#---------------------------------------
# CRÉATION DES COMMANDES UTILITAIRES
#---------------------------------------
create_utilities() {
    print_step "ÉTAPE 5/6 : CRÉATION DES COMMANDES UTILITAIRES"
    
    # Copier les outils
    cp "$INSTALL_DIR/tools/check_status.sh" /usr/local/bin/siem-status
    cp "$INSTALL_DIR/tools/view_alerts.sh" /usr/local/bin/siem-alerts
    chmod +x /usr/local/bin/siem-status
    chmod +x /usr/local/bin/siem-alerts
    
    # Commande de mise à jour
    cat > /usr/local/bin/siem-update << 'EOF'
#!/bin/bash
GITHUB_RAW="https://raw.githubusercontent.com/luciesys/siem-africa/main"
KB_DIR="/var/ossec/etc/knowledge_base"
echo "Mise à jour de la base de données..."
curl -sL "$GITHUB_RAW/knowledge_base/attacks.json" -o /tmp/attacks_new.json
if jq empty /tmp/attacks_new.json 2>/dev/null; then
    cp "$KB_DIR/attacks.json" "$KB_DIR/attacks.json.backup"
    mv /tmp/attacks_new.json "$KB_DIR/attacks.json"
    echo "[✓] Mise à jour effectuée"
else
    echo "[✗] Échec de la mise à jour"
fi
EOF
    chmod +x /usr/local/bin/siem-update
    
    print_success "Commandes créées : siem-status, siem-alerts, siem-update"
}

#---------------------------------------
# CONFIGURATION MISE À JOUR AUTO
#---------------------------------------
setup_auto_update() {
    print_step "ÉTAPE 6/6 : CONFIGURATION MISE À JOUR AUTOMATIQUE"
    
    # Ajouter au cron (tous les jours à 3h du matin)
    (crontab -l 2>/dev/null | grep -v "siem-update"; echo "0 3 * * * /usr/local/bin/siem-update >> /var/log/siem-update.log 2>&1") | crontab -
    
    print_success "Mise à jour automatique configurée (tous les jours à 3h)"
}

#---------------------------------------
# RÉSUMÉ FINAL
#---------------------------------------
print_summary() {
    # Récupérer l'IP
    IP_ADDR=$(hostname -I | awk '{print $1}')
    
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                                      ║${NC}"
    echo -e "${GREEN}║         ✓ SIEM AFRICA INSTALLÉ AVEC SUCCÈS !                        ║${NC}"
    echo -e "${GREEN}║                                                                      ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  ACCÈS${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}Dashboard Wazuh :${NC} https://$IP_ADDR"
    echo -e "${YELLOW}Utilisateur     :${NC} admin"
    echo -e "${YELLOW}Mot de passe    :${NC} Voir /root/wazuh-credentials.txt"
    
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  COMMANDES UTILES${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}siem-status${NC}  - Voir l'état des services"
    echo -e "${YELLOW}siem-alerts${NC}  - Voir les dernières alertes"
    echo -e "${YELLOW}siem-update${NC}  - Mettre à jour la base de données"
    
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  INSTALLATION AGENTS${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}Linux :${NC}"
    echo "curl -sL $GITHUB_RAW/installation/agents/install_agent_universal.sh | sudo bash -s $IP_ADDR"
    echo ""
    echo -e "${YELLOW}Windows (PowerShell Admin) :${NC}"
    echo "iwr -Uri '$GITHUB_RAW/installation/agents/install_agent.ps1' -OutFile 'install.ps1'; .\\install.ps1 -ServerIP $IP_ADDR"
    
    echo ""
}

#---------------------------------------
# MAIN
#---------------------------------------
main() {
    print_banner
    
    echo -e "${YELLOW}Ce script va installer :${NC}"
    echo "  • Snort (IDS - Détection d'intrusions)"
    echo "  • Wazuh (SIEM - Centralisation des logs)"
    echo "  • Analyseur Intelligent (100 attaques)"
    echo "  • Commandes utilitaires"
    echo "  • Mise à jour automatique"
    echo ""
    echo -e "${YELLOW}Durée estimée : 30-45 minutes${NC}"
    echo ""
    
    read -p "Continuer ? (O/n) : " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        echo "Installation annulée."
        exit 0
    fi
    
    check_root
    check_system
    download_project
    install_siem
    install_knowledge_base
    create_utilities
    setup_auto_update
    print_summary
}

main "$@"
