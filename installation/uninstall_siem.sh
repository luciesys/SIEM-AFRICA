#!/bin/bash

#===============================================================================
#
#          FILE: uninstall_siem.sh
#
#         USAGE: sudo bash uninstall_siem.sh
#
#   DESCRIPTION: Désinstallation complète de SIEM Africa (Snort + Wazuh)
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
# FONCTIONS D'AFFICHAGE
#---------------------------------------
print_banner() {
    clear
    echo -e "${RED}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                  ║"
    echo "║             DÉSINSTALLATION SIEM AFRICA                          ║"
    echo "║                                                                  ║"
    echo "║             ⚠️  ATTENTION : Action irréversible                  ║"
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
# VÉRIFICATION ROOT
#---------------------------------------
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Ce script doit être exécuté en tant que root"
        exit 1
    fi
}

#---------------------------------------
# CONFIRMATION
#---------------------------------------
confirm_uninstall() {
    print_banner
    
    echo -e "${RED}⚠️  ATTENTION ⚠️${NC}"
    echo ""
    echo "Cette action va supprimer :"
    echo "  • Snort et toutes ses configurations"
    echo "  • Wazuh Manager, Indexer et Dashboard"
    echo "  • Toutes les alertes et logs"
    echo "  • La base de données des attaques"
    echo "  • Les configurations de notifications"
    echo ""
    echo -e "${YELLOW}Cette action est IRRÉVERSIBLE !${NC}"
    echo ""
    
    read -p "Êtes-vous sûr de vouloir continuer ? (tapez 'OUI' pour confirmer) : " confirm
    
    if [ "$confirm" != "OUI" ]; then
        echo ""
        print_info "Désinstallation annulée."
        exit 0
    fi
}

#---------------------------------------
# ARRÊT DES SERVICES
#---------------------------------------
stop_services() {
    print_step "ÉTAPE 1/5 : ARRÊT DES SERVICES"
    
    services=("snort" "wazuh-manager" "wazuh-indexer" "wazuh-dashboard" "filebeat")
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            systemctl stop "$service" 2>/dev/null
            systemctl disable "$service" 2>/dev/null
            print_success "Service $service arrêté"
        else
            print_info "Service $service non actif"
        fi
    done
}

#---------------------------------------
# DÉSINSTALLATION SNORT
#---------------------------------------
uninstall_snort() {
    print_step "ÉTAPE 2/5 : DÉSINSTALLATION DE SNORT"
    
    # Supprimer le paquet
    if dpkg -l | grep -q snort; then
        apt-get remove --purge -y snort snort-common snort-common-libraries 2>/dev/null
        print_success "Paquet Snort supprimé"
    else
        print_info "Snort n'était pas installé via apt"
    fi
    
    # Supprimer les fichiers de configuration
    if [ -d "/etc/snort" ]; then
        rm -rf /etc/snort
        print_success "Configuration Snort supprimée (/etc/snort)"
    fi
    
    # Supprimer les logs
    if [ -d "/var/log/snort" ]; then
        rm -rf /var/log/snort
        print_success "Logs Snort supprimés (/var/log/snort)"
    fi
    
    # Supprimer le service systemd personnalisé
    if [ -f "/etc/systemd/system/snort.service" ]; then
        rm -f /etc/systemd/system/snort.service
        systemctl daemon-reload
        print_success "Service systemd Snort supprimé"
    fi
    
    # Supprimer l'utilisateur snort
    if id "snort" &>/dev/null; then
        userdel -r snort 2>/dev/null
        print_success "Utilisateur snort supprimé"
    fi
}

#---------------------------------------
# DÉSINSTALLATION WAZUH
#---------------------------------------
uninstall_wazuh() {
    print_step "ÉTAPE 3/5 : DÉSINSTALLATION DE WAZUH"
    
    # Supprimer les paquets Wazuh
    apt-get remove --purge -y wazuh-manager wazuh-indexer wazuh-dashboard 2>/dev/null
    print_success "Paquets Wazuh supprimés"
    
    # Supprimer Filebeat
    apt-get remove --purge -y filebeat 2>/dev/null
    print_success "Filebeat supprimé"
    
    # Supprimer les répertoires Wazuh
    directories=(
        "/var/ossec"
        "/etc/wazuh-indexer"
        "/etc/wazuh-dashboard"
        "/var/lib/wazuh-indexer"
        "/var/lib/wazuh-dashboard"
        "/usr/share/wazuh-indexer"
        "/usr/share/wazuh-dashboard"
        "/etc/filebeat"
        "/var/lib/filebeat"
    )
    
    for dir in "${directories[@]}"; do
        if [ -d "$dir" ]; then
            rm -rf "$dir"
            print_success "Répertoire supprimé : $dir"
        fi
    done
    
    # Supprimer le repository Wazuh
    rm -f /etc/apt/sources.list.d/wazuh.list 2>/dev/null
    print_success "Repository Wazuh supprimé"
    
    # Supprimer l'utilisateur wazuh
    if id "wazuh" &>/dev/null; then
        userdel -r wazuh 2>/dev/null
        print_success "Utilisateur wazuh supprimé"
    fi
}

#---------------------------------------
# DÉSINSTALLATION SIEM AFRICA
#---------------------------------------
uninstall_siem_africa() {
    print_step "ÉTAPE 4/5 : DÉSINSTALLATION DE SIEM AFRICA"
    
    # Supprimer le répertoire d'installation
    if [ -d "/opt/siem-africa" ]; then
        rm -rf /opt/siem-africa
        print_success "Répertoire /opt/siem-africa supprimé"
    fi
    
    # Supprimer la base de connaissances
    if [ -d "/var/ossec/etc/knowledge_base" ]; then
        rm -rf /var/ossec/etc/knowledge_base
        print_success "Base de connaissances supprimée"
    fi
    
    # Supprimer les commandes utilitaires
    commands=("siem-status" "siem-alerts" "siem-update")
    for cmd in "${commands[@]}"; do
        if [ -f "/usr/local/bin/$cmd" ]; then
            rm -f "/usr/local/bin/$cmd"
            print_success "Commande $cmd supprimée"
        fi
    done
    
    # Supprimer le cron de mise à jour
    crontab -l 2>/dev/null | grep -v "siem-update" | crontab -
    print_success "Tâche cron de mise à jour supprimée"
    
    # Supprimer les fichiers de credentials
    if [ -f "/root/credentials.txt" ]; then
        rm -f /root/credentials.txt
        print_success "Fichier credentials.txt supprimé"
    fi
    
    # Supprimer les logs SIEM Africa
    rm -f /var/log/siem-*.log 2>/dev/null
    rm -f /var/log/install_siem.log 2>/dev/null
    print_success "Logs SIEM Africa supprimés"
}

#---------------------------------------
# NETTOYAGE FINAL
#---------------------------------------
cleanup() {
    print_step "ÉTAPE 5/5 : NETTOYAGE FINAL"
    
    # Nettoyer les paquets orphelins
    apt-get autoremove -y 2>/dev/null
    apt-get autoclean -y 2>/dev/null
    print_success "Paquets orphelins supprimés"
    
    # Recharger systemd
    systemctl daemon-reload
    print_success "Systemd rechargé"
}

#---------------------------------------
# RÉSUMÉ FINAL
#---------------------------------------
print_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                                  ║${NC}"
    echo -e "${GREEN}║         ✓ SIEM AFRICA DÉSINSTALLÉ AVEC SUCCÈS                   ║${NC}"
    echo -e "${GREEN}║                                                                  ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  COMPOSANTS SUPPRIMÉS${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "  ✓ Snort (IDS)"
    echo "  ✓ Wazuh Manager"
    echo "  ✓ Wazuh Indexer"
    echo "  ✓ Wazuh Dashboard"
    echo "  ✓ Filebeat"
    echo "  ✓ Base de connaissances"
    echo "  ✓ Configurations et logs"
    echo "  ✓ Commandes utilitaires"
    
    echo ""
    echo -e "${YELLOW}Pour réinstaller SIEM Africa :${NC}"
    echo "curl -sL https://raw.githubusercontent.com/luciesys/siem-africa/main/install.sh | sudo bash"
    echo ""
}

#---------------------------------------
# MAIN
#---------------------------------------
main() {
    check_root
    confirm_uninstall
    stop_services
    uninstall_snort
    uninstall_wazuh
    uninstall_siem_africa
    cleanup
    print_summary
}

main "$@"
