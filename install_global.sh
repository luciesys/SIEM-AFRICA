#!/bin/bash
# ================================================================
#  SIEM Africa — Installation Globale v3.2
#  Usage : sudo bash install_global.sh
# ================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
GITHUB="https://raw.githubusercontent.com/luciesys/SIEM-AFRICA/main"
LOG="/var/log/siem-africa-install.log"

mkdir -p /var/log && touch "$LOG"
log()  { echo -e "$1" | tee -a "$LOG"; }
ok()   { log "${GREEN}  [✓]${NC} $1"; }
info() { log "${CYAN}  [→]${NC} $1"; }
err()  { log "${RED}  [✗]${NC} $1"; }
stop() { err "$1"; log "  Journal : ${YELLOW}$LOG${NC}"; exit 1; }

[ "$EUID" -ne 0 ] && stop "Lancer avec : sudo bash install_global.sh"
ping -c1 -W5 8.8.8.8 >/dev/null 2>&1 || stop "Pas de connexion internet"

clear
echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║   SIEM AFRICA — Installation Globale v3.2   ║"
echo "  ║   Modules 1 + 2 + 3                         ║"
echo "  ╚══════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  ${GREEN}[1]${NC} Snort IDS + Wazuh Manager"
echo -e "  ${GREEN}[2]${NC} Base SQLite — 380 signatures MITRE ATT&CK"
echo -e "  ${GREEN}[3]${NC} Agent Python + Honeypots"
echo ""
echo -e "  ${YELLOW}Durée estimée : 20 à 45 minutes${NC}"
echo ""
read -p "  Appuyer sur Entrée pour commencer..." _

# ════════════════════════════════════════════════════════════════
#  MODULE 1
# ════════════════════════════════════════════════════════════════
echo ""
log "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
log "${BLUE}${BOLD}  MODULE 1/3 — Snort IDS + Wazuh Manager ${NC}"
log "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

info "Téléchargement script Module 1..."
curl -fsSL "${GITHUB}/installation/install.sh" -o /tmp/m1.sh \
    || stop "Impossible de télécharger le script Module 1"
[ ! -s /tmp/m1.sh ] && stop "Script Module 1 vide"
ok "Script Module 1 prêt"
echo ""

# Attendre que apt soit libre
while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
    info "En attente que apt se libère..."
    sleep 5
done

bash /tmp/m1.sh
M1=$?
echo ""

[ $M1 -ne 0 ] && stop "Module 1 échoué (code $M1)"

# Attendre que les services démarrent
info "Attente démarrage des services (15s)..."
sleep 15

if systemctl is-active wazuh-manager >/dev/null 2>&1; then
    ok "wazuh-manager : ACTIF"
else
    log "${YELLOW}  [!] wazuh-manager inactif — continuer ? [O/n]${NC}"
    read -p "  " R; R=${R:-O}
    [[ "$R" =~ ^[nN]$ ]] && stop "Arrêté par l'utilisateur"
fi

systemctl is-active snort >/dev/null 2>&1 \
    && ok "snort : ACTIF" \
    || log "${YELLOW}  [!] snort inactif (non bloquant)${NC}"

ok "MODULE 1 TERMINÉ"

# ════════════════════════════════════════════════════════════════
#  MODULE 2
# ════════════════════════════════════════════════════════════════
echo ""
log "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
log "${BLUE}${BOLD}  MODULE 2/3 — Base SQLite             ${NC}"
log "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

info "Téléchargement fichiers Module 2..."
rm -rf /tmp/siem-m2 && mkdir -p /tmp/siem-m2
cd /tmp/siem-m2

curl -fsSL "${GITHUB}/database/install.sh"  -o install.sh  || stop "Erreur téléchargement install.sh"
curl -fsSL "${GITHUB}/database/schema.sql"  -o schema.sql  || stop "Erreur téléchargement schema.sql"
curl -fsSL "${GITHUB}/database/attacks.sql" -o attacks.sql || stop "Erreur téléchargement attacks.sql"

[ ! -s install.sh ]  && stop "install.sh vide"
[ ! -s schema.sql ]  && stop "schema.sql vide"
[ ! -s attacks.sql ] && stop "attacks.sql vide"
ok "Fichiers Module 2 prêts"
echo ""

bash /tmp/siem-m2/install.sh
M2=$?
echo ""

[ $M2 -ne 0 ] && stop "Module 2 échoué (code $M2)"

cd /tmp
NB=$(sqlite3 /opt/siem-africa/siem_africa.db \
    "SELECT COUNT(*) FROM attaques;" 2>/dev/null || echo 0)
[ "$NB" -lt 300 ] && stop "Base incomplète : $NB signatures seulement"
ok "Base créée — $NB signatures MITRE ATT&CK chargées"
ok "MODULE 2 TERMINÉ"

# ════════════════════════════════════════════════════════════════
#  MODULE 3
# ════════════════════════════════════════════════════════════════
echo ""
log "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
log "${BLUE}${BOLD}  MODULE 3/3 — Agent Python + Honeypots        ${NC}"
log "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

info "Téléchargement fichiers Module 3..."
cd /tmp
curl -fsSL "${GITHUB}/agent/agent.py"   -o /tmp/agent.py   || stop "Erreur téléchargement agent.py"
curl -fsSL "${GITHUB}/agent/install.sh" -o /tmp/m3.sh      || stop "Erreur téléchargement install.sh (M3)"

[ ! -s /tmp/agent.py ] && stop "agent.py vide"
[ ! -s /tmp/m3.sh ]    && stop "Script Module 3 vide"
ok "Fichiers Module 3 prêts"
echo ""

bash /tmp/m3.sh
M3=$?
echo ""

[ $M3 -ne 0 ] && stop "Module 3 échoué (code $M3)"

info "Attente démarrage siem-agent (10s)..."
sleep 10

systemctl is-active siem-agent >/dev/null 2>&1 \
    && ok "siem-agent : ACTIF" \
    || stop "siem-agent non actif après installation"

ok "MODULE 3 TERMINÉ"

# ════════════════════════════════════════════════════════════════
#  SMTP
# ════════════════════════════════════════════════════════════════
echo ""
read -p "  Configurer le SMTP (emails d'alerte) maintenant ? [O/n] : " SR
SR=${SR:-O}
if [[ ! "$SR" =~ ^[nN]$ ]]; then
    info "Téléchargement script SMTP..."
    curl -fsSL "${GITHUB}/agent/install-smtp.sh" -o /tmp/smtp.sh
    [ -s /tmp/smtp.sh ] && bash /tmp/smtp.sh
fi

# ════════════════════════════════════════════════════════════════
#  RÉSUMÉ FINAL
# ════════════════════════════════════════════════════════════════
echo ""
log "${GREEN}${BOLD}╔══════════════════════════════════════════╗${NC}"
log "${GREEN}${BOLD}║   INSTALLATION TERMINÉE AVEC SUCCÈS !   ║${NC}"
log "${GREEN}${BOLD}╚══════════════════════════════════════════╝${NC}"
echo ""
log "${BOLD}  Services actifs :${NC}"
for svc in snort wazuh-manager siem-agent; do
    systemctl is-active "$svc" >/dev/null 2>&1 \
        && ok "$svc" \
        || log "${YELLOW}  [!] $svc — inactif${NC}"
done
echo ""
log "${BOLD}  Commandes utiles :${NC}"
log "  ${CYAN}Credentials  :${NC} sudo cat /opt/siem-africa/credentials.txt"
log "  ${CYAN}Logs agent   :${NC} sudo tail -f /var/log/siem-africa/agent.log"
log "  ${CYAN}Test honeypot:${NC} ssh -p 2222 test@127.0.0.1"
echo ""
log "${BOLD}  Module 4 — Dashboard :${NC}"
log "  ${YELLOW}curl -sL ${GITHUB}/dashboard/install.sh | sudo bash${NC}"
echo ""
