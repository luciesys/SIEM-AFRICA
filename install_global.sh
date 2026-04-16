#!/bin/bash
# SIEM Africa — Installation Globale v3.1
# Usage : sudo bash install_global.sh

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
GITHUB="https://raw.githubusercontent.com/luciesys/SIEM-AFRICA/main"
LOG_FILE="/var/log/siem-africa-install.log"
DEBUT=$(date +%s)

mkdir -p "$(dirname "$LOG_FILE")" && touch "$LOG_FILE"
log()      { echo -e "$1" | tee -a "$LOG_FILE"; }
log_ok()   { log "${GREEN}  [✓]${NC} $1"; }
log_info() { log "${CYAN}  [→]${NC} $1"; }
log_err()  { log "${RED}  [✗]${NC} $1"; }
quitter()  { log_err "$1"; log "${YELLOW}  Journal : $LOG_FILE${NC}"; exit 1; }

[ "$EUID" -ne 0 ] && quitter "Lancer avec : sudo bash install_global.sh"
ping -c1 -W5 8.8.8.8 > /dev/null 2>&1 || quitter "Pas de connexion internet"

clear
echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║   SIEM AFRICA — Installation Globale v3.1   ║"
echo "  ║   Modules 1 + 2 + 3                         ║"
echo "  ╚══════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  ${GREEN}[1]${NC} Snort IDS + Wazuh Manager"
echo -e "  ${GREEN}[2]${NC} Base SQLite (380 signatures MITRE ATT&CK)"
echo -e "  ${GREEN}[3]${NC} Agent Python + Honeypots"
echo ""
echo -e "  ${YELLOW}Durée estimée : 20 à 45 minutes${NC}"
echo ""
read -p "  Appuyer sur Entrée pour commencer..." dummy

# ── MODULE 1 ─────────────────────────────────────────────────
echo ""
log "${BLUE}${BOLD}━━━ MODULE 1/3 — Snort IDS + Wazuh Manager ━━━${NC}"
echo ""
log_info "Téléchargement script Module 1..."
curl -sL "${GITHUB}/installation/install.sh" -o /tmp/m1_install.sh
[ ! -s /tmp/m1_install.sh ] && quitter "Téléchargement Module 1 échoué"
log_ok "Téléchargé"
echo ""
bash /tmp/m1_install.sh
[ $? -ne 0 ] && quitter "Module 1 échoué"
sleep 5
systemctl is-active wazuh-manager > /dev/null 2>&1 && log_ok "wazuh-manager ACTIF" || log "${YELLOW}  [!] wazuh-manager inactif${NC}"
systemctl is-active snort > /dev/null 2>&1 && log_ok "snort ACTIF" || log "${YELLOW}  [!] snort inactif (non bloquant)${NC}"
log_ok "MODULE 1 TERMINÉ"

# ── MODULE 2 ─────────────────────────────────────────────────
echo ""
log "${BLUE}${BOLD}━━━ MODULE 2/3 — Base SQLite ━━━${NC}"
echo ""
log_info "Téléchargement fichiers Module 2..."
mkdir -p /tmp/siem-m2 && cd /tmp/siem-m2
curl -sL "${GITHUB}/database/install.sh"  -o install.sh
curl -sL "${GITHUB}/database/schema.sql"  -o schema.sql
curl -sL "${GITHUB}/database/attacks.sql" -o attacks.sql
[ ! -s install.sh ]  && quitter "Téléchargement install.sh (M2) échoué"
[ ! -s schema.sql ]  && quitter "Téléchargement schema.sql échoué"
[ ! -s attacks.sql ] && quitter "Téléchargement attacks.sql échoué"
log_ok "Téléchargé"
echo ""
bash /tmp/siem-m2/install.sh
[ $? -ne 0 ] && quitter "Module 2 échoué"
cd /tmp
NB=$(sqlite3 /opt/siem-africa/siem_africa.db "SELECT COUNT(*) FROM attaques;" 2>/dev/null || echo 0)
log_ok "Base créée — $NB signatures chargées"
log_ok "MODULE 2 TERMINÉ"

# ── MODULE 3 ─────────────────────────────────────────────────
echo ""
log "${BLUE}${BOLD}━━━ MODULE 3/3 — Agent Python + Honeypots ━━━${NC}"
echo ""
log_info "Téléchargement fichiers Module 3..."
curl -sL "${GITHUB}/agent/agent.py"   -o /tmp/agent.py
curl -sL "${GITHUB}/agent/install.sh" -o /tmp/m3_install.sh
[ ! -s /tmp/agent.py ]      && quitter "Téléchargement agent.py échoué"
[ ! -s /tmp/m3_install.sh ] && quitter "Téléchargement install.sh (M3) échoué"
log_ok "Téléchargé"
echo ""
cd /tmp && bash /tmp/m3_install.sh
[ $? -ne 0 ] && quitter "Module 3 échoué"
sleep 5
systemctl is-active siem-agent > /dev/null 2>&1 && log_ok "siem-agent ACTIF" || quitter "siem-agent non actif"
log_ok "MODULE 3 TERMINÉ"

# ── SMTP ──────────────────────────────────────────────────────
echo ""
read -p "  Configurer le SMTP (emails d'alerte) maintenant ? [O/n] : " SR
SR=${SR:-O}
if [[ ! "$SR" =~ ^[nN]$ ]]; then
    curl -sL "${GITHUB}/agent/install-smtp.sh" -o /tmp/install-smtp.sh
    [ -s /tmp/install-smtp.sh ] && bash /tmp/install-smtp.sh
fi

# ── RÉSUMÉ ────────────────────────────────────────────────────
FIN=$(date +%s)
DUREE=$(( (FIN - DEBUT) / 60 ))
echo ""
log "${GREEN}${BOLD}╔══════════════════════════════════════╗${NC}"
log "${GREEN}${BOLD}║  INSTALLATION TERMINÉE ! (${DUREE} min)  ║${NC}"
log "${GREEN}${BOLD}╚══════════════════════════════════════╝${NC}"
echo ""
for svc in snort wazuh-manager siem-agent; do
    systemctl is-active "$svc" > /dev/null 2>&1 && log_ok "$svc" || log "${YELLOW}  [!] $svc inactif${NC}"
done
echo ""
log "  ${CYAN}Credentials  :${NC} sudo cat /opt/siem-africa/credentials.txt"
log "  ${CYAN}Logs agent   :${NC} sudo tail -f /var/log/siem-africa/agent.log"
log "  ${CYAN}Test honeypot:${NC} ssh -p 2222 test@127.0.0.1"
echo ""
log "  ${BOLD}Module 4 Dashboard :${NC}"
log "  ${YELLOW}curl -sL ${GITHUB}/dashboard/install.sh | sudo bash${NC}"
echo ""
