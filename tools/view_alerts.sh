#!/bin/bash

#===============================================================================
#
#          FILE: view_alerts.sh
#
#   DESCRIPTION: Affiche les dernières alertes SIEM Africa
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
# CONFIGURATION
#---------------------------------------
SNORT_ALERTS="/var/log/snort/snort.alert.fast"
WAZUH_ALERTS="/var/ossec/logs/alerts/alerts.json"
DEFAULT_LINES=20

#---------------------------------------
# BANNIÈRE
#---------------------------------------
print_banner() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                                  ║${NC}"
    echo -e "${CYAN}║              🛡️  SIEM AFRICA - DERNIÈRES ALERTES                 ║${NC}"
    echo -e "${CYAN}║                                                                  ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

#---------------------------------------
# AFFICHER ALERTES SNORT
#---------------------------------------
show_snort_alerts() {
    local lines=${1:-$DEFAULT_LINES}
    
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  ALERTES SNORT (dernières $lines)${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    if [ -f "$SNORT_ALERTS" ]; then
        tail -n "$lines" "$SNORT_ALERTS" | while read line; do
            # Colorier selon le type
            if echo "$line" | grep -qi "CRITICAL\|ATTACK\|EXPLOIT"; then
                echo -e "  ${RED}●${NC} $line"
            elif echo "$line" | grep -qi "WARNING\|SCAN\|BRUTE"; then
                echo -e "  ${YELLOW}●${NC} $line"
            else
                echo -e "  ${GREEN}●${NC} $line"
            fi
        done
    else
        echo -e "  ${YELLOW}Aucune alerte Snort trouvée${NC}"
    fi
    echo ""
}

#---------------------------------------
# AFFICHER ALERTES WAZUH
#---------------------------------------
show_wazuh_alerts() {
    local lines=${1:-$DEFAULT_LINES}
    
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  ALERTES WAZUH (dernières $lines)${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    if [ -f "$WAZUH_ALERTS" ]; then
        tail -n "$lines" "$WAZUH_ALERTS" | while read line; do
            local level=$(echo "$line" | jq -r '.rule.level' 2>/dev/null)
            local desc=$(echo "$line" | jq -r '.rule.description' 2>/dev/null)
            local time=$(echo "$line" | jq -r '.timestamp' 2>/dev/null)
            
            if [ "$level" != "null" ] && [ -n "$level" ]; then
                if [ "$level" -ge 12 ]; then
                    echo -e "  ${RED}●${NC} [$level] $desc"
                elif [ "$level" -ge 8 ]; then
                    echo -e "  ${YELLOW}●${NC} [$level] $desc"
                else
                    echo -e "  ${GREEN}●${NC} [$level] $desc"
                fi
            fi
        done
    else
        echo -e "  ${YELLOW}Aucune alerte Wazuh trouvée${NC}"
    fi
    echo ""
}

#---------------------------------------
# STATISTIQUES
#---------------------------------------
show_stats() {
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  STATISTIQUES${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    if [ -f "$SNORT_ALERTS" ]; then
        local total=$(wc -l < "$SNORT_ALERTS")
        local today=$(grep -c "$(date +%m/%d)" "$SNORT_ALERTS" 2>/dev/null || echo "0")
        
        echo -e "  ${GREEN}●${NC} Total alertes Snort : $total"
        echo -e "  ${GREEN}●${NC} Alertes aujourd'hui : $today"
    fi
    echo ""
}

#---------------------------------------
# AIDE
#---------------------------------------
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -n, --lines NUM    Nombre de lignes à afficher (défaut: 20)"
    echo "  -s, --snort        Afficher seulement Snort"
    echo "  -w, --wazuh        Afficher seulement Wazuh"
    echo "  -f, --follow       Suivre en temps réel (Ctrl+C pour quitter)"
    echo "  -h, --help         Afficher cette aide"
    echo ""
    echo "Exemples:"
    echo "  $0                 Afficher les 20 dernières alertes"
    echo "  $0 -n 50           Afficher les 50 dernières alertes"
    echo "  $0 -f              Suivre les alertes en temps réel"
    echo ""
}

#---------------------------------------
# SUIVRE EN TEMPS RÉEL
#---------------------------------------
follow_alerts() {
    echo -e "${CYAN}Suivi des alertes en temps réel... (Ctrl+C pour quitter)${NC}"
    echo ""
    
    if [ -f "$SNORT_ALERTS" ]; then
        tail -f "$SNORT_ALERTS"
    else
        echo "Fichier d'alertes non trouvé"
    fi
}

#---------------------------------------
# MAIN
#---------------------------------------
main() {
    local lines=$DEFAULT_LINES
    local show_snort=true
    local show_wazuh=true
    local follow=false
    
    # Parser les arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -n|--lines)
                lines=$2
                shift 2
                ;;
            -s|--snort)
                show_wazuh=false
                shift
                ;;
            -w|--wazuh)
                show_snort=false
                shift
                ;;
            -f|--follow)
                follow=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                shift
                ;;
        esac
    done
    
    print_banner
    
    if $follow; then
        follow_alerts
    else
        $show_snort && show_snort_alerts "$lines"
        $show_wazuh && show_wazuh_alerts "$lines"
        show_stats
    fi
}

main "$@"
