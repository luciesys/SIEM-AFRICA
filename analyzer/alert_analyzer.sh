#!/bin/bash

#===============================================================================
#
#          FILE: alert_analyzer.sh
#
#   DESCRIPTION: Analyse les alertes Snort/Wazuh et les enrichit avec
#                la base de connaissances (attacks.json)
#
#        AUTHOR: SIEM Africa Team
#       VERSION: 1.0
#
#===============================================================================

#---------------------------------------
# CONFIGURATION
#---------------------------------------
KNOWLEDGE_BASE="/var/ossec/etc/knowledge_base/attacks.json"
LOG_FILE="/var/log/siem-africa/analyzer.log"

#---------------------------------------
# FONCTIONS UTILITAIRES
#---------------------------------------
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

#---------------------------------------
# RECHERCHE DANS LA BASE DE CONNAISSANCES
#---------------------------------------
search_attack() {
    local sid=$1
    
    if [ ! -f "$KNOWLEDGE_BASE" ]; then
        log_message "ERROR" "Base de connaissances non trouvée"
        return 1
    fi
    
    local attack=$(jq -r --arg sid "$sid" '.attacks[] | select(.sid == $sid)' "$KNOWLEDGE_BASE" 2>/dev/null)
    
    if [ -z "$attack" ] || [ "$attack" == "null" ]; then
        log_message "WARNING" "SID $sid non trouvé"
        return 1
    fi
    
    echo "$attack"
    return 0
}

#---------------------------------------
# DÉTERMINER L'EMOJI DE GRAVITÉ
#---------------------------------------
get_severity_emoji() {
    local severity=$1
    
    if [ "$severity" -le 3 ]; then
        echo "🟢"
    elif [ "$severity" -le 5 ]; then
        echo "🟡"
    elif [ "$severity" -le 7 ]; then
        echo "🟠"
    elif [ "$severity" -le 9 ]; then
        echo "🔴"
    else
        echo "⚫"
    fi
}

get_severity_name() {
    local severity=$1
    
    if [ "$severity" -le 3 ]; then
        echo "FAIBLE"
    elif [ "$severity" -le 5 ]; then
        echo "MODÉRÉ"
    elif [ "$severity" -le 7 ]; then
        echo "ÉLEVÉ"
    elif [ "$severity" -le 9 ]; then
        echo "CRITIQUE"
    else
        echo "URGENT"
    fi
}

#---------------------------------------
# CONSTRUIRE LE MESSAGE D'ALERTE
#---------------------------------------
build_alert_message() {
    local attack_json=$1
    local source_ip=$2
    local dest_ip=$3
    local timestamp=$4
    
    local name=$(echo "$attack_json" | jq -r '.name')
    local severity=$(echo "$attack_json" | jq -r '.severity')
    local category=$(echo "$attack_json" | jq -r '.category')
    local description=$(echo "$attack_json" | jq -r '.description.fr // .description.en')
    local risk=$(echo "$attack_json" | jq -r '.risk.fr // .risk.en')
    
    local emoji=$(get_severity_emoji "$severity")
    local severity_name=$(get_severity_name "$severity")
    
    # Actions avec IP remplacée
    local actions=$(echo "$attack_json" | jq -r '.actions[] | "  \(.order). \(.description): \(.command)"' | sed "s/{IP}/$source_ip/g")
    
    cat << EOF
$emoji ALERTE $severity_name

📋 Type: $name
📁 Catégorie: $category
📊 Gravité: $severity/10

🔍 DÉTAILS:
  Source: $source_ip
  Destination: $dest_ip
  Heure: $timestamp

📝 DESCRIPTION:
$description

⚠️ RISQUE:
$risk

✅ ACTIONS RECOMMANDÉES:
$actions
EOF
}

#---------------------------------------
# ANALYSER UNE ALERTE
#---------------------------------------
analyze_alert() {
    local sid=$1
    local source_ip=$2
    local dest_ip=${3:-"N/A"}
    local timestamp=${4:-$(date '+%Y-%m-%d %H:%M:%S')}
    
    log_message "INFO" "Analyse SID: $sid, Source: $source_ip"
    
    local attack=$(search_attack "$sid")
    
    if [ $? -ne 0 ]; then
        cat << EOF
⚠️ ALERTE DÉTECTÉE

📋 SID: $sid
🔍 Source: $source_ip
🎯 Destination: $dest_ip
🕐 Heure: $timestamp

ℹ️ Cette alerte n'est pas dans la base de connaissances.
EOF
        return 1
    fi
    
    build_alert_message "$attack" "$source_ip" "$dest_ip" "$timestamp"
    
    local severity=$(echo "$attack" | jq -r '.severity')
    return "$severity"
}

#---------------------------------------
# MAIN
#---------------------------------------
main() {
    if [ $# -lt 2 ]; then
        echo "Usage: $0 <SID> <SOURCE_IP> [DEST_IP]"
        echo ""
        echo "Exemple:"
        echo "  $0 2001219 41.204.92.15 192.168.1.10"
        exit 1
    fi
    
    analyze_alert "$1" "$2" "$3" "$4"
}

if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi
