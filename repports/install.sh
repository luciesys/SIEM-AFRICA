#!/bin/bash
# ================================================================
#  SIEM Africa — Module 6 : Rapports automatiques
#  Fichier  : reports/install.sh
#  Usage    : sudo bash install.sh
#  Version  : 2.0
# ================================================================
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

LOG_FILE="/var/log/siem-africa-install.log"
REPORTS_DIR="/opt/siem-africa/rapports"
SCRIPT_DIR="/opt/siem-africa/scripts/reports"
ENV_FILE="/opt/siem-africa/.env"
CRED_FILE="/opt/siem-africa/credentials.txt"
USER_REPORTS="siem-reports"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()       { echo -e "$1" | tee -a "$LOG_FILE"; }
log_ok()    { log "${GREEN}[OK]${NC} $1"; }
log_info()  { log "${CYAN}[INFO]${NC} $1"; }
log_warn()  { log "${YELLOW}[ATTENTION]${NC} $1"; }
log_etape() { log "${BLUE}[ETAPE $1]${NC} $2"; }
quitter()   { echo -e "\n${RED}ARRETE : $1${NC}"; exit 1; }

show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║       SIEM Africa — Module 6                        ║"
    echo "║       Rapports automatiques PDF + Excel             ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ── Etape 1 : Verifications ───────────────────────────────────────
check_all() {
    log_etape "1/5" "VERIFICATIONS"
    [ "$EUID" -ne 0 ] && quitter "sudo requis"
    log_ok "Root"
    [ ! -f "$ENV_FILE" ] && quitter "Module 1 non installe"
    log_ok "Module 1 present"
    DB_PATH=$(grep "^DB_PATH=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 | tr -d '"' || echo "/opt/siem-africa/siem_africa.db")
    [ ! -f "$DB_PATH" ] && quitter "Base SQLite non trouvee"
    log_ok "Base SQLite : $DB_PATH"
    for f in report_generator.py scheduler.py; do
        [ ! -f "${SRC_DIR}/${f}" ] && quitter "$f introuvable dans $SRC_DIR"
    done
    log_ok "Scripts Python presents"
}

# ── Etape 2 : Utilisateur systeme ────────────────────────────────
create_user() {
    log_etape "2/5" "UTILISATEUR SYSTEME"
    if id "$USER_REPORTS" > /dev/null 2>&1; then
        log_info "Utilisateur $USER_REPORTS existe"
    else
        useradd --system --no-create-home --shell /sbin/nologin \
                --comment "SIEM Africa - Rapports" "$USER_REPORTS"
        log_ok "Utilisateur $USER_REPORTS cree"
    fi
}

# ── Etape 3 : Dependances Python ─────────────────────────────────
install_deps() {
    log_etape "3/5" "DEPENDANCES PYTHON"

    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        python3-pip python3-dev > /dev/null 2>&1

    log_info "Installation ReportLab (PDF)..."
    pip3 install --quiet reportlab --break-system-packages 2>/dev/null || \
    pip3 install --quiet reportlab 2>/dev/null || \
        log_warn "ReportLab non installe — rapports PDF desactives"

    log_info "Installation OpenPyXL (Excel)..."
    pip3 install --quiet openpyxl --break-system-packages 2>/dev/null || \
    pip3 install --quiet openpyxl 2>/dev/null || \
        log_warn "OpenPyXL non installe — rapports Excel desactives"

    python3 -c "from reportlab.lib.pagesizes import A4" 2>/dev/null && \
        log_ok "ReportLab OK — PDF actif" || log_warn "ReportLab indisponible"

    python3 -c "from openpyxl import Workbook" 2>/dev/null && \
        log_ok "OpenPyXL OK — Excel actif" || log_warn "OpenPyXL indisponible"
}

# ── Etape 4 : Installation ────────────────────────────────────────
install_reports() {
    log_etape "4/5" "INSTALLATION"

    mkdir -p "$SCRIPT_DIR"
    mkdir -p "$REPORTS_DIR"
    mkdir -p /var/log/siem-africa

    cp "${SRC_DIR}/report_generator.py" "${SCRIPT_DIR}/"
    cp "${SRC_DIR}/scheduler.py"        "${SCRIPT_DIR}/"
    log_ok "Scripts copies dans $SCRIPT_DIR"

    # Droits
    chown -R "${USER_REPORTS}:${USER_REPORTS}" "$SCRIPT_DIR" "$REPORTS_DIR"
    chmod 750 "$SCRIPT_DIR"
    chmod 755 "$REPORTS_DIR"
    chmod 640 "${SCRIPT_DIR}/report_generator.py"
    chmod 640 "${SCRIPT_DIR}/scheduler.py"

    # Acces base SQLite
    DB_PATH=$(grep "^DB_PATH=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 | tr -d '"' || echo "/opt/siem-africa/siem_africa.db")
    if [ -f "$DB_PATH" ]; then
        OWNER=$(stat -c '%U' "$DB_PATH")
        chown "${OWNER}:${USER_REPORTS}" "$DB_PATH"
        chmod 664 "$DB_PATH"
        log_ok "Acces SQLite configure"
    fi

    # Acces .env
    chown root:"${USER_REPORTS}" "$ENV_FILE"
    chmod 640 "$ENV_FILE"

    # Acces logs
    touch /var/log/siem-africa/reports.log
    chown "${USER_REPORTS}:${USER_REPORTS}" /var/log/siem-africa/reports.log
    chmod 640 /var/log/siem-africa/reports.log
    log_ok "Droits configures"

    # Mettre a jour .env avec le chemin des rapports
    if ! grep -q "^REPORTS_DIR=" "$ENV_FILE"; then
        echo "REPORTS_DIR=${REPORTS_DIR}" >> "$ENV_FILE"
    fi

    # Service systemd
    cat > /etc/systemd/system/siem-reports.service << SYSTEMD
[Unit]
Description=SIEM Africa Rapports automatiques v2.0
Documentation=https://github.com/luciesys/SIEM-AFRICA
After=network.target siem-agent.service

[Service]
Type=simple
User=${USER_REPORTS}
Group=${USER_REPORTS}
WorkingDirectory=${SCRIPT_DIR}
ExecStart=/usr/bin/python3 ${SCRIPT_DIR}/scheduler.py
Restart=on-failure
RestartSec=30
StandardOutput=append:/var/log/siem-africa/reports.log
StandardError=append:/var/log/siem-africa/reports.log
Environment=PYTHONUNBUFFERED=1

# Securite
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
SYSTEMD

    systemctl daemon-reload
    systemctl enable siem-reports
    systemctl restart siem-reports 2>/dev/null || true
    sleep 2

    if systemctl is-active --quiet siem-reports; then
        log_ok "Service siem-reports ACTIF"
    else
        log_warn "Service non actif — voir : journalctl -u siem-reports -n 20"
    fi
}

# ── Etape 5 : Credentials + test ─────────────────────────────────
finalize() {
    log_etape "5/5" "FINALISATION"

    # Test de generation
    log_info "Test de generation d'un rapport hebdomadaire..."
    DB_PATH=$(grep "^DB_PATH=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 | tr -d '"' || echo "/opt/siem-africa/siem_africa.db")
    TEST_OK=$(sudo -u "$USER_REPORTS" python3 "${SCRIPT_DIR}/report_generator.py" hebdomadaire 2>/dev/null && echo "oui" || echo "non")
    if [ "$TEST_OK" = "oui" ]; then
        log_ok "Generation de rapport fonctionnelle"
    else
        log_warn "Test echoue — les rapports seront generes quand des alertes existent"
    fi

    cat >> "$CRED_FILE" << CREDS

── MODULE 6 — RAPPORTS AUTOMATIQUES ────────────────────────
  Installe le : $(date '+%d/%m/%Y a %H:%M')

  Utilisateur sys : ${USER_REPORTS} (shell: /sbin/nologin)
  Scripts         : ${SCRIPT_DIR}
  Rapports        : ${REPORTS_DIR}
  Logs            : /var/log/siem-africa/reports.log
  Service         : siem-reports.service

── PLANNING DES RAPPORTS ─────────────────────────────────────
  Hebdomadaire : chaque lundi a 08h00
  Trimestriel  : 1er janvier, avril, juillet, octobre a 07h00
  Annuel       : 1er janvier a 07h00
  Incident     : automatique apres chaque alerte critique/haute resolue

── COMMANDES MANUELLES ───────────────────────────────────────
  Rapport hebdo  : python3 ${SCRIPT_DIR}/report_generator.py hebdomadaire
  Rapport trim.  : python3 ${SCRIPT_DIR}/report_generator.py trimestriel
  Rapport annuel : python3 ${SCRIPT_DIR}/report_generator.py annuel
  Rapport incident (ID=5) :
    python3 ${SCRIPT_DIR}/report_generator.py incident --alerte-id 5
  Rapport manuel (periode) :
    python3 ${SCRIPT_DIR}/report_generator.py manuel \\
      --debut "2026-01-01 00:00:00" --fin "2026-01-31 23:59:59"

── PROCHAINE ETAPE ───────────────────────────────────────────
  install.sh global — installe tout en une commande
  Commande : cd .. && sudo bash install_global.sh

CREDS

    chmod 600 "$CRED_FILE"
    log_ok "credentials.txt mis a jour"
}

show_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     MODULE 6 — INSTALLATION TERMINEE                ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}── SERVICES ACTIFS ──────────────────────────────────${NC}"
    for svc in siem-agent siem-dashboard siem-reports siem-tunnel; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            echo -e "  ${GREEN}[ACTIF]${NC}   $svc"
        else
            echo -e "  ${YELLOW}[INACTIF]${NC} $svc"
        fi
    done
    echo ""
    echo -e "${CYAN}── RAPPORTS ─────────────────────────────────────────${NC}"
    echo -e "  Dossier      : $REPORTS_DIR"
    echo -e "  Hebdomadaire : chaque lundi 08h00"
    echo -e "  Incident     : automatique apres resolution"
    echo ""
    echo -e "${CYAN}── GENERATION MANUELLE ──────────────────────────────${NC}"
    echo -e "  python3 ${SCRIPT_DIR}/report_generator.py hebdomadaire"
    echo ""
    echo -e "${CYAN}── PROCHAINE ETAPE ──────────────────────────────────${NC}"
    echo -e "  ${YELLOW}install.sh global — installe tout en 1 commande${NC}"
    echo ""
}

main() {
    echo "=== SIEM Africa Module 6 - $(date) ===" >> "$LOG_FILE"
    show_banner
    check_all
    create_user
    install_deps
    install_reports
    finalize
    show_summary
}

main "$@"
