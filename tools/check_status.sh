#!/bin/bash

#===============================================================================
#
#          FILE: check_status.sh
#
#   DESCRIPTION: Vérifie l'état de tous les services SIEM Africa
#
#        AUTHOR: SIEM Africa Team
#       VERSION: 1.0
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
# BANNIÈRE
#---------------------------------------
print_banner() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                                  ║${NC}"
    echo -e "${CYAN}║              🛡️  SIEM AFRICA - ÉTAT DU SYSTÈME                   ║${NC}"
    echo -e "${CYAN}║                                                                  ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

#---------------------------------------
# VÉRIFIER UN SERVICE
#---------------------------------------
check_service() {
    local service_name=$1
    local display_name=$2
    
    if systemctl is-active --quiet "$service_name" 2>/dev/null; then
        echo -e "  ${GREEN}●${NC} $display_name : ${GREEN}ACTIF${NC}"
        return 0
    else
        echo -e "  ${RED}●${NC} $display_name : ${RED}INACTIF${NC}"
        return 1
    fi
}

#---------------------------------------
# VÉRIFIER LES SERVICES
#---------------------------------------
check_services() {
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  SERVICES${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    local all_ok=true
    
    check_service "snort" "Snort (IDS)" || all_ok=false
    check_service "wazuh-manager" "Wazuh Manager" || all_ok=false
    check_service "wazuh-indexer" "Wazuh Indexer" || all_ok=false
    check_service "wazuh-dashboard" "Wazuh Dashboard" || all_ok=false
    check_service "filebeat" "Filebeat" || all_ok=false
    
    echo ""
    
    if $all_ok; then
        echo -e "  ${GREEN}✓ Tous les services sont actifs${NC}"
    else
        echo -e "  ${YELLOW}⚠ Certains services sont inactifs${NC}"
    fi
    echo ""
}

#---------------------------------------
# VÉRIFIER L'ESPACE DISQUE
#---------------------------------------
check_disk() {
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  ESPACE DISQUE${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    local usage=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    local available=$(df -h / | awk 'NR==2 {print $4}')
    
    if [ "$usage" -lt 70 ]; then
        echo -e "  ${GREEN}●${NC} Utilisation : ${usage}% (${available} disponible)"
    elif [ "$usage" -lt 90 ]; then
        echo -e "  ${YELLOW}●${NC} Utilisation : ${usage}% (${available} disponible) - ${YELLOW}Attention${NC}"
    else
        echo -e "  ${RED}●${NC} Utilisation : ${usage}% (${available} disponible) - ${RED}Critique !${NC}"
    fi
    echo ""
}

#---------------------------------------
# VÉRIFIER LA RAM
#---------------------------------------
check_memory() {
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  MÉMOIRE RAM${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    local total=$(free -h | awk '/^Mem:/ {print $2}')
    local used=$(free -h | awk '/^Mem:/ {print $3}')
    local usage=$(free | awk '/^Mem:/ {printf("%.0f", $3/$2 * 100)}')
    
    if [ "$usage" -lt 70 ]; then
        echo -e "  ${GREEN}●${NC} Utilisation : ${used} / ${total} (${usage}%)"
    elif [ "$usage" -lt 90 ]; then
        echo -e "  ${YELLOW}●${NC} Utilisation : ${used} / ${total} (${usage}%) - ${YELLOW}Attention${NC}"
    else
        echo -e "  ${RED}●${NC} Utilisation : ${used} / ${total} (${usage}%) - ${RED}Critique !${NC}"
    fi
    echo ""
}

#---------------------------------------
# VÉRIFIER LES ALERTES RÉCENTES
#---------------------------------------
check_alerts() {
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  ALERTES RÉCENTES (24h)${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    local alert_file="/var/log/snort/snort.alert.fast"
    
    if [ -f "$alert_file" ]; then
        local today=$(date +%m/%d)
        local count=$(grep -c "$today" "$alert_file" 2>/dev/null || echo "0")
        
        if [ "$count" -eq 0 ]; then
            echo -e "  ${GREEN}●${NC} Aucune alerte aujourd'hui"
        elif [ "$count" -lt 10 ]; then
            echo -e "  ${YELLOW}●${NC} $count alertes aujourd'hui"
        else
            echo -e "  ${RED}●${NC} $count alertes aujourd'hui - ${RED}Vérifiez !${NC}"
        fi
    else
        echo -e "  ${YELLOW}●${NC} Fichier d'alertes non trouvé"
    fi
    echo ""
}

#---------------------------------------
# VÉRIFIER LA BASE DE CONNAISSANCES
#---------------------------------------
check_knowledge_base() {
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  BASE DE CONNAISSANCES${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    local kb_file="/var/ossec/etc/knowledge_base/attacks.json"
    
    if [ -f "$kb_file" ]; then
        local version=$(jq -r '.metadata.version' "$kb_file" 2>/dev/null || echo "?")
        local count=$(jq '.attacks | length' "$kb_file" 2>/dev/null || echo "?")
        local last_update=$(jq -r '.metadata.last_update' "$kb_file" 2>/dev/null || echo "?")
        
        echo -e "  ${GREEN}●${NC} Version : $version"
        echo -e "  ${GREEN}●${NC} Attaques : $count"
        echo -e "  ${GREEN}●${NC} Dernière MAJ : $last_update"
    else
        echo -e "  ${RED}●${NC} Base de connaissances non trouvée"
    fi
    echo ""
}

#---------------------------------------
# AFFICHER LES INFOS RÉSEAU
#---------------------------------------
show_network_info() {
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  INFORMATIONS RÉSEAU${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    local ip=$(hostname -I | awk '{print $1}')
    echo -e "  ${GREEN}●${NC} Adresse IP : $ip"
    echo -e "  ${GREEN}●${NC} Dashboard : https://$ip"
    echo ""
}

#---------------------------------------
# MAIN
#---------------------------------------
main() {
    print_banner
    check_services
    check_disk
    check_memory
    check_alerts
    check_knowledge_base
    show_network_info
    
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "  Rapport généré le $(date '+%Y-%m-%d à %H:%M:%S')"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

main
