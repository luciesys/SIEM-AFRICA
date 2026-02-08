#!/bin/bash

#===============================================================================
#
#          FILE: install_agent_universal.sh
#
#         USAGE: sudo bash install_agent_universal.sh <WAZUH_SERVER_IP>
#
#   DESCRIPTION: Installation universelle de l'agent Wazuh
#                Détecte automatiquement le système d'exploitation
#                Supporte: Ubuntu, Debian, CentOS, Rocky, AlmaLinux, Fedora
#
#        AUTHOR: SIEM Africa Team
#       VERSION: 1.0
#       CREATED: Février 2026
#
#===============================================================================

#---------------------------------------
# COULEURS
#---------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

#---------------------------------------
# VARIABLES
#---------------------------------------
WAZUH_VERSION="4.7.0"
WAZUH_MANAGER=""
AGENT_NAME=""
OS_TYPE=""
OS_NAME=""
PKG_MANAGER=""

#---------------------------------------
# FONCTIONS D'AFFICHAGE
#---------------------------------------
print_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                  ║"
    echo "║        INSTALLATION UNIVERSELLE AGENT WAZUH                      ║"
    echo "║                                                                  ║"
    echo "║        Détection automatique du système d'exploitation          ║"
    echo "║                                                                  ║"
    echo "║        Supporte:                                                 ║"
    echo "║          • Ubuntu / Debian                                       ║"
    echo "║          • CentOS / Rocky / AlmaLinux / Fedora                  ║"
    echo "║          • Windows (via script PowerShell)                       ║"
    echo "║                                                                  ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
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

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

#---------------------------------------
# DÉTECTION DU SYSTÈME D'EXPLOITATION
#---------------------------------------
detect_os() {
    print_step "ÉTAPE 1/5 : DÉTECTION DU SYSTÈME D'EXPLOITATION"
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS_TYPE="linux"
        
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            OS_NAME=$PRETTY_NAME
            
            case $ID in
                ubuntu)
                    PKG_MANAGER="apt"
                    print_success "Système détecté : $OS_NAME"
                    print_info "Type : Ubuntu (famille Debian)"
                    ;;
                debian)
                    PKG_MANAGER="apt"
                    print_success "Système détecté : $OS_NAME"
                    print_info "Type : Debian"
                    ;;
                centos)
                    PKG_MANAGER="yum"
                    print_success "Système détecté : $OS_NAME"
                    print_info "Type : CentOS (famille RedHat)"
                    ;;
                rocky)
                    PKG_MANAGER="dnf"
                    print_success "Système détecté : $OS_NAME"
                    print_info "Type : Rocky Linux (famille RedHat)"
                    ;;
                almalinux)
                    PKG_MANAGER="dnf"
                    print_success "Système détecté : $OS_NAME"
                    print_info "Type : AlmaLinux (famille RedHat)"
                    ;;
                fedora)
                    PKG_MANAGER="dnf"
                    print_success "Système détecté : $OS_NAME"
                    print_info "Type : Fedora (famille RedHat)"
                    ;;
                rhel)
                    PKG_MANAGER="yum"
                    print_success "Système détecté : $OS_NAME"
                    print_info "Type : Red Hat Enterprise Linux"
                    ;;
                *)
                    print_error "Distribution Linux non supportée : $ID"
                    print_info "Distributions supportées :"
                    print_info "  • Ubuntu / Debian"
                    print_info "  • CentOS / Rocky / AlmaLinux / Fedora / RHEL"
                    exit 1
                    ;;
            esac
        else
            print_error "Impossible de détecter la distribution Linux"
            exit 1
        fi
        
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS_TYPE="macos"
        OS_NAME="macOS"
        print_success "Système détecté : macOS"
        print_warning "macOS détecté - Installation manuelle recommandée"
        print_info "Téléchargez l'agent depuis : https://packages.wazuh.com/4.x/macos/"
        exit 0
        
    elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        OS_TYPE="windows"
        OS_NAME="Windows"
        print_success "Système détecté : Windows"
        print_warning "Pour Windows, utilisez le script PowerShell :"
        echo ""
        echo -e "${CYAN}# Ouvrez PowerShell en tant qu'Administrateur et exécutez :${NC}"
        echo ""
        echo 'Invoke-WebRequest -Uri "https://raw.githubusercontent.com/luciesys/siem-africa/main/installation/agents/install_agent.ps1" -OutFile "install_agent.ps1"'
        echo '.\install_agent.ps1 -ServerIP <IP_SERVEUR_WAZUH>'
        echo ""
        exit 0
    else
        print_error "Système d'exploitation non reconnu : $OSTYPE"
        exit 1
    fi
}

#---------------------------------------
# VÉRIFICATION ROOT
#---------------------------------------
check_root() {
    print_step "ÉTAPE 2/5 : VÉRIFICATION DES DROITS"
    
    if [ "$EUID" -ne 0 ]; then
        print_error "Ce script doit être exécuté en tant que root"
        print_info "Utilisez : sudo bash $0"
        exit 1
    fi
    print_success "Droits root confirmés"
}

#---------------------------------------
# CONFIGURATION DU SERVEUR WAZUH
#---------------------------------------
configure_server() {
    print_step "ÉTAPE 3/5 : CONFIGURATION DU SERVEUR WAZUH"
    
    if [ -n "$1" ]; then
        WAZUH_MANAGER=$1
        print_info "IP du serveur Wazuh : $WAZUH_MANAGER"
    else
        echo -e "${YELLOW}Entrez l'adresse IP du serveur Wazuh :${NC}"
        read -p "> " WAZUH_MANAGER
    fi
    
    if [[ ! $WAZUH_MANAGER =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        print_error "Adresse IP invalide : $WAZUH_MANAGER"
        print_info "Format attendu : 192.168.1.100"
        exit 1
    fi
    print_success "Adresse IP valide : $WAZUH_MANAGER"
    
    print_info "Test de connexion vers $WAZUH_MANAGER..."
    if ping -c 1 -W 3 $WAZUH_MANAGER &> /dev/null; then
        print_success "Serveur Wazuh accessible"
    else
        print_warning "Impossible de contacter le serveur $WAZUH_MANAGER"
        read -p "Continuer quand même ? (o/N) : " confirm
        if [[ ! "$confirm" =~ ^[Oo]$ ]]; then
            print_info "Installation annulée"
            exit 1
        fi
    fi
    
    AGENT_NAME=$(hostname)
    print_info "Nom de l'agent détecté : $AGENT_NAME"
    
    read -p "Modifier le nom ? (laisser vide pour garder '$AGENT_NAME') : " new_name
    if [ -n "$new_name" ]; then
        AGENT_NAME=$new_name
    fi
    print_success "Nom de l'agent : $AGENT_NAME"
}

#---------------------------------------
# INSTALLATION SELON LE SYSTÈME
#---------------------------------------
install_agent() {
    print_step "ÉTAPE 4/5 : INSTALLATION DE L'AGENT WAZUH"
    
    case $PKG_MANAGER in
        apt)
            install_debian_ubuntu
            ;;
        yum)
            install_redhat_yum
            ;;
        dnf)
            install_redhat_dnf
            ;;
        *)
            print_error "Gestionnaire de paquets non supporté"
            exit 1
            ;;
    esac
}

#---------------------------------------
# Installation Debian/Ubuntu
#---------------------------------------
install_debian_ubuntu() {
    print_info "Installation pour Debian/Ubuntu..."
    
    print_info "Ajout de la clé GPG Wazuh..."
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg 2>/dev/null
    
    if [ $? -ne 0 ]; then
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - 2>/dev/null
    fi
    print_success "Clé GPG ajoutée"
    
    print_info "Ajout du repository Wazuh..."
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
    print_success "Repository ajouté"
    
    print_info "Mise à jour des paquets..."
    apt-get update > /dev/null 2>&1
    
    print_info "Installation de l'agent Wazuh..."
    WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" apt-get install -y wazuh-agent > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        print_success "Agent Wazuh installé avec succès"
    else
        print_error "Échec de l'installation de l'agent"
        exit 1
    fi
}

#---------------------------------------
# Installation RedHat/CentOS (yum)
#---------------------------------------
install_redhat_yum() {
    print_info "Installation pour CentOS/RHEL (yum)..."
    
    print_info "Ajout du repository Wazuh..."
    cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
    print_success "Repository ajouté"
    
    print_info "Installation de l'agent Wazuh..."
    WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" yum install -y wazuh-agent > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        print_success "Agent Wazuh installé avec succès"
    else
        print_error "Échec de l'installation de l'agent"
        exit 1
    fi
}

#---------------------------------------
# Installation Rocky/AlmaLinux/Fedora (dnf)
#---------------------------------------
install_redhat_dnf() {
    print_info "Installation pour Rocky/AlmaLinux/Fedora (dnf)..."
    
    print_info "Ajout du repository Wazuh..."
    cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
    print_success "Repository ajouté"
    
    print_info "Installation de l'agent Wazuh..."
    WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" dnf install -y wazuh-agent > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        print_success "Agent Wazuh installé avec succès"
    else
        print_error "Échec de l'installation de l'agent"
        exit 1
    fi
}

#---------------------------------------
# CONFIGURATION ET DÉMARRAGE
#---------------------------------------
configure_and_start() {
    print_step "ÉTAPE 5/5 : CONFIGURATION ET DÉMARRAGE"
    
    AGENT_CONF="/var/ossec/etc/ossec.conf"
    
    if [ -f "$AGENT_CONF" ]; then
        print_info "Configuration de l'adresse du manager..."
        sed -i "s/<address>.*<\/address>/<address>$WAZUH_MANAGER<\/address>/g" "$AGENT_CONF"
        print_success "Adresse du manager configurée"
    else
        print_warning "Fichier de configuration non trouvé, configuration par défaut utilisée"
    fi
    
    print_info "Activation du service..."
    systemctl daemon-reload
    systemctl enable wazuh-agent > /dev/null 2>&1
    print_success "Service activé au démarrage"
    
    print_info "Démarrage du service..."
    systemctl start wazuh-agent
    
    sleep 3
    
    if systemctl is-active --quiet wazuh-agent; then
        print_success "Service wazuh-agent : ACTIF"
    else
        print_warning "Le service n'a pas démarré correctement"
        print_info "Vérifiez les logs : journalctl -u wazuh-agent -n 50"
    fi
}

#---------------------------------------
# RÉSUMÉ FINAL
#---------------------------------------
print_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                                  ║${NC}"
    echo -e "${GREEN}║        ✓ AGENT WAZUH INSTALLÉ AVEC SUCCÈS !                     ║${NC}"
    echo -e "${GREEN}║                                                                  ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  INFORMATIONS DE L'AGENT${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}Système           :${NC} $OS_NAME"
    echo -e "${YELLOW}Nom de l'agent    :${NC} $AGENT_NAME"
    echo -e "${YELLOW}Serveur Wazuh     :${NC} $WAZUH_MANAGER"
    echo -e "${YELLOW}Statut du service :${NC} $(systemctl is-active wazuh-agent 2>/dev/null || echo 'inconnu')"
    
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  COMMANDES UTILES${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "# Vérifier le statut de l'agent"
    echo "sudo systemctl status wazuh-agent"
    echo ""
    echo "# Redémarrer l'agent"
    echo "sudo systemctl restart wazuh-agent"
    echo ""
    echo "# Voir les logs de l'agent"
    echo "sudo tail -f /var/ossec/logs/ossec.log"
    
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  PROCHAINE ÉTAPE${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Vérifiez que l'agent apparaît dans le Dashboard Wazuh :"
    echo "  1. Ouvrez https://$WAZUH_MANAGER"
    echo "  2. Connectez-vous avec vos identifiants"
    echo "  3. Allez dans 'Agents' → L'agent '$AGENT_NAME' devrait apparaître"
    echo ""
}

#---------------------------------------
# MAIN
#---------------------------------------
main() {
    print_banner
    detect_os
    check_root
    configure_server "$1"
    install_agent
    configure_and_start
    print_summary
}

main "$1"
