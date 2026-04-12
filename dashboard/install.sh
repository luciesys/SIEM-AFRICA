#!/bin/bash
# ================================================================
#  SIEM Africa — Module 4 : Dashboard Django
#  Fichier  : dashboard/install.sh
#  Version  : 3.0
#  Usage    : sudo bash install.sh
#
#  Corrections v3.0 (problemes precedents) :
#  - Desinstallation automatique si installation existante
#  - WorkingDirectory correct dans systemd
#  - Droits fichiers corrects des le depart
#  - PID dans /var/log (pas /var/run)
#  - Logs : Python ecrit directement, systemd n'interfere pas
# ================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

LOG_FILE="/var/log/siem-africa-install.log"
OPT_DIR="/opt/siem-africa"
DASH_DIR="/opt/siem-africa/dashboard"
ENV_FILE="/opt/siem-africa/.env"
CRED_FILE="/opt/siem-africa/credentials.txt"
GROUPE="siem-africa"
USER_DASH="siem-dashboard"
SERVICE="siem-dashboard"
GITHUB_BASE="https://raw.githubusercontent.com/luciesys/SIEM-AFRICA/main"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT=8000

log()       { echo -e "$1" | tee -a "$LOG_FILE"; }
log_ok()    { log "${GREEN}[OK]${NC} $1"; }
log_info()  { log "${CYAN}[INFO]${NC} $1"; }
log_warn()  { log "${YELLOW}[ATTENTION]${NC} $1"; }
log_err()   { log "${RED}[ERREUR]${NC} $1"; }
log_etape() {
    log ""
    log "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log "${BLUE}${BOLD}  ETAPE $1${NC}"
    log "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

quitter() {
    log_err "$1"
    echo -e "\n${RED}Installation arretee. Journal : $LOG_FILE${NC}"
    exit 1
}

show_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║       SIEM Africa — Module 4 v3.0                   ║"
    echo "  ║       Dashboard Web Django                          ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ================================================================
# DESINSTALLATION SI INSTALLATION EXISTANTE
# ================================================================
desinstaller_si_present() {
    local deja=0
    [ -d "$DASH_DIR" ] && deja=1
    [ -f "/etc/systemd/system/${SERVICE}.service" ] && deja=1

    [ "$deja" -eq 0 ] && return 0

    echo ""
    echo -e "${YELLOW}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║   Installation anterieure detectee — suppression... ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    systemctl stop "$SERVICE" 2>/dev/null || true
    systemctl disable "$SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SERVICE}.service"
    systemctl daemon-reload 2>/dev/null || true
    log_ok "Service $SERVICE arrete et supprime"

    rm -rf "$DASH_DIR"
    log_ok "Dossier $DASH_DIR supprime"

    id "$USER_DASH" &>/dev/null && userdel "$USER_DASH" 2>/dev/null && \
        log_ok "Utilisateur $USER_DASH supprime" || true

    rm -f /var/log/siem-africa/dashboard.log
    rm -f /var/log/siem-africa/siem-dashboard.pid

    log_ok "Ancienne installation supprimee"
    echo ""
    sleep 1
}

# ================================================================
# ETAPE 1 : Verifications
# ================================================================
check_all() {
    log_etape "1/5 — VERIFICATIONS"

    [ "$EUID" -ne 0 ] && quitter "sudo requis — lancez : sudo bash install.sh"
    log_ok "Root confirme"

    [ ! -f "$ENV_FILE" ] && quitter "Module 1 non installe"
    log_ok "Module 1 detecte"

    [ ! -f "$OPT_DIR/siem_africa.db" ] && quitter "Module 2 non installe"
    log_ok "Module 2 detecte (base SQLite)"

    # Python3
    command -v python3 > /dev/null 2>&1 || quitter "Python3 non installe"
    PY_VER=$(python3 --version 2>&1 | cut -d' ' -f2)
    log_ok "Python3 : $PY_VER"

    # pip3
    command -v pip3 > /dev/null 2>&1 || \
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-pip > /dev/null 2>&1
    log_ok "pip3 disponible"

    # Port 8000 disponible
    if ss -tlnp 2>/dev/null | grep -q ":${PORT} "; then
        log_warn "Port $PORT deja utilise — le dashboard remplacera le service existant"
    fi
}

# ================================================================
# ETAPE 2 : Installation Django et dependances
# ================================================================
install_deps() {
    log_etape "2/5 — DEPENDANCES PYTHON"

    log_info "Installation des packages Python necessaires..."
    pip3 install --quiet \
        django==4.2.* \
        whitenoise \
        gunicorn 2>&1 | grep -E "Successfully|already|error" || true

    # Verifier Django
    python3 -c "import django; print(f'Django {django.__version__}')" 2>/dev/null && \
        log_ok "Django installe : $(python3 -c 'import django; print(django.__version__)')" || \
        quitter "Django non installe"

    log_ok "gunicorn installe"
    log_ok "whitenoise installe"
}

# ================================================================
# ETAPE 3 : Installation des fichiers
# ================================================================
installer_dashboard() {
    log_etape "3/5 — INSTALLATION DASHBOARD"

    # Creer l'utilisateur
    if id "$USER_DASH" > /dev/null 2>&1; then
        log_info "Utilisateur $USER_DASH existe deja"
    else
        useradd --system --no-create-home \
                --shell /sbin/nologin \
                --gid "$GROUPE" \
                --comment "SIEM Africa Dashboard" \
                "$USER_DASH"
        log_ok "Utilisateur $USER_DASH cree"
    fi
    usermod -aG "$GROUPE" "$USER_DASH" 2>/dev/null || true

    # Creer le dossier DASH_DIR avec droits corrects DES LE DEBUT
    mkdir -p "$DASH_DIR"
    chown "${USER_DASH}:${GROUPE}" "$DASH_DIR"
    chmod 750 "$DASH_DIR"
    log_ok "Dossier $DASH_DIR cree"

    # Telecharger ou copier les fichiers Django
    log_info "Installation des fichiers Django..."

    # Fonction de telechargement
    dl_file() {
        local src="$1" dest="$2"
        if [ -f "${SCRIPT_DIR}/${src}" ]; then
            cp "${SCRIPT_DIR}/${src}" "$dest"
        else
            curl -sL "${GITHUB_BASE}/dashboard/${src}" -o "$dest" 2>/dev/null || \
            wget -q   "${GITHUB_BASE}/dashboard/${src}" -O "$dest" 2>/dev/null || true
        fi
    }

    # Creer la structure Django
    mkdir -p "$DASH_DIR/siem_africa"
    mkdir -p "$DASH_DIR/core"
    mkdir -p "$DASH_DIR/templates"
    mkdir -p "$DASH_DIR/static/css"
    mkdir -p "$DASH_DIR/static/js"
    mkdir -p "$DASH_DIR/staticfiles"

    # Telecharger les fichiers
    for f in manage.py requirements.txt; do
        dl_file "$f" "${DASH_DIR}/${f}"
    done
    for f in __init__.py settings.py urls.py wsgi.py; do
        dl_file "siem_africa/${f}" "${DASH_DIR}/siem_africa/${f}"
    done
    for f in __init__.py views.py urls.py db.py middleware.py i18n.py; do
        dl_file "core/${f}" "${DASH_DIR}/core/${f}"
    done
    for f in base.html login.html premiere_connexion.html dashboard.html \
              alertes.html alerte_detail.html ips_bloquees.html ips_whitelist.html \
              inconnues.html parametres.html; do
        dl_file "templates/${f}" "${DASH_DIR}/templates/${f}"
    done
    dl_file "static/css/style.css" "${DASH_DIR}/static/css/style.css"
    dl_file "static/js/dashboard.js" "${DASH_DIR}/static/js/dashboard.js"

    # Verifier les fichiers essentiels
    for f in "${DASH_DIR}/manage.py" \
              "${DASH_DIR}/siem_africa/settings.py" \
              "${DASH_DIR}/core/views.py"; do
        if [ ! -f "$f" ] || [ ! -s "$f" ]; then
            log_warn "Fichier manquant ou vide : $f"
        fi
    done

    # Configurer settings.py avec les vraies valeurs
    SERVER_IP=$(grep "^SERVER_IP=" "$ENV_FILE" | cut -d'=' -f2 || hostname -I | awk '{print $1}')
    SECRET_KEY=$(grep "^SECRET_KEY=" "$ENV_FILE" | cut -d'=' -f2)
    [ -z "$SECRET_KEY" ] && SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")

    sed -i "s|SERVER_IP_PLACEHOLDER|${SERVER_IP}|g" \
        "${DASH_DIR}/siem_africa/settings.py" 2>/dev/null || true
    sed -i "s|SECRET_KEY_PLACEHOLDER|${SECRET_KEY}|g" \
        "${DASH_DIR}/siem_africa/settings.py" 2>/dev/null || true
    sed -i "s|DB_PATH_PLACEHOLDER|${OPT_DIR}/siem_africa.db|g" \
        "${DASH_DIR}/siem_africa/settings.py" 2>/dev/null || true

    log_ok "Fichiers Django installes"

    # Collecter les fichiers statiques
    cd "$DASH_DIR"
    python3 manage.py collectstatic --noinput > /dev/null 2>&1 || true
    log_ok "Fichiers statiques collectes"

    # Permissions finales
    chown -R "${USER_DASH}:${GROUPE}" "$DASH_DIR"
    chmod -R 750 "$DASH_DIR"
    chmod -R 755 "${DASH_DIR}/staticfiles"
    chmod -R 755 "${DASH_DIR}/static"

    # Droits sur la base SQLite
    chown "${GROUPE}:${GROUPE}" "${OPT_DIR}/siem_africa.db" 2>/dev/null || true
    chmod 664 "${OPT_DIR}/siem_africa.db" 2>/dev/null || true
    log_ok "Droits base SQLite configures"

    # Droits sur .env
    setfacl -m u:"${USER_DASH}":r "$ENV_FILE" 2>/dev/null || \
        chmod o+r "$ENV_FILE" 2>/dev/null || true

    # Logs
    touch /var/log/siem-africa/dashboard.log
    chown "${USER_DASH}:${GROUPE}" /var/log/siem-africa/dashboard.log
    chmod 664 /var/log/siem-africa/dashboard.log
    log_ok "Fichier log cree avec droits corrects"
}

# ================================================================
# ETAPE 4 : Service systemd
# ================================================================
creer_service() {
    log_etape "4/5 — SERVICE SYSTEMD"

    cat > /etc/systemd/system/${SERVICE}.service << SRVSVC
[Unit]
Description=SIEM Africa Dashboard Django v3.0
Documentation=https://github.com/luciesys/SIEM-AFRICA
After=network.target siem-agent.service
Wants=siem-agent.service

[Service]
Type=simple
User=${USER_DASH}
Group=${GROUPE}
WorkingDirectory=${DASH_DIR}
ExecStart=/usr/local/bin/gunicorn \
    --bind 0.0.0.0:${PORT} \
    --workers 2 \
    --timeout 120 \
    --access-logfile /var/log/siem-africa/dashboard.log \
    --error-logfile /var/log/siem-africa/dashboard.log \
    siem_africa.wsgi:application
Restart=always
RestartSec=10
StandardOutput=null
StandardError=null
Environment=DJANGO_SETTINGS_MODULE=siem_africa.settings
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
SRVSVC

    systemctl daemon-reload
    systemctl enable "$SERVICE" 2>/dev/null || true
    systemctl start "$SERVICE" 2>/dev/null || true
    sleep 4

    if systemctl is-active --quiet "$SERVICE"; then
        log_ok "Service $SERVICE : ACTIF"
    else
        log_warn "Dashboard non actif — diagnostic :"
        journalctl -u "$SERVICE" -n 5 --no-pager 2>/dev/null | \
            grep -v "^--" | tail -5 | while read line; do
                log_warn "  $line"
            done
    fi
}

# ================================================================
# ETAPE 5 : Finalisation
# ================================================================
finaliser() {
    log_etape "5/5 — FINALISATION"

    SERVER_IP=$(grep "^SERVER_IP=" "$ENV_FILE" | cut -d'=' -f2 || hostname -I | awk '{print $1}')

    # Lire les credentials admin du Module 2
    ADMIN_USERNAME=$(grep "^  Username" "$CRED_FILE" 2>/dev/null | \
        grep -v "IMPORTANT" | tail -1 | awk '{print $NF}' || echo "siem-admin")
    ADMIN_PASSWORD=$(grep "^  Password" "$CRED_FILE" 2>/dev/null | \
        tail -1 | awk '{print $NF}' || echo "voir credentials.txt")

    cat >> "$CRED_FILE" << CREDS

── MODULE 4 — DASHBOARD DJANGO ──────────────────────────────
  Installe le : $(date '+%d/%m/%Y a %H:%M')
  URL         : http://${SERVER_IP}:${PORT}
  Utilisateur : $USER_DASH
  Dossier     : $DASH_DIR
  Service     : $SERVICE.service

── PREMIERE CONNEXION ────────────────────────────────────────
  URL         : http://${SERVER_IP}:${PORT}
  Username    : $ADMIN_USERNAME
  Password    : $ADMIN_PASSWORD
  IMPORTANT   : Changer username et password a la 1ere connexion

── COMMANDES UTILES ──────────────────────────────────────────
  Status   : systemctl status siem-dashboard
  Logs     : tail -f /var/log/siem-africa/dashboard.log
  Restart  : sudo systemctl restart siem-dashboard

CREDS

    chmod 640 "$CRED_FILE"
    log_ok "credentials.txt mis a jour"

    # Resume
    echo ""
    echo -e "${GREEN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║     MODULE 4 — INSTALLATION TERMINEE                ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "${CYAN}── SERVICES ─────────────────────────────────────────${NC}"
    for svc in snort wazuh-manager siem-agent siem-dashboard; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            echo -e "  ${GREEN}[ACTIF]${NC}    $svc"
        else
            echo -e "  ${YELLOW}[INACTIF]${NC}  $svc"
        fi
    done

    echo ""
    echo -e "${CYAN}── ACCES DASHBOARD ──────────────────────────────────${NC}"
    echo -e "  URL      : ${GREEN}http://${SERVER_IP}:${PORT}${NC}"
    echo -e "  Username : ${GREEN}$ADMIN_USERNAME${NC}"
    echo -e "  Password : ${GREEN}$ADMIN_PASSWORD${NC}"
    echo -e "  ${YELLOW}Changer ces identifiants a la premiere connexion !${NC}"
    echo ""
}

# ================================================================
# MAIN
# ================================================================
main() {
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    echo "" >> "$LOG_FILE"
    echo "=== SIEM Africa Module 4 v3.0 - $(date) ===" >> "$LOG_FILE"

    show_banner
    desinstaller_si_present
    check_all
    install_deps
    installer_dashboard
    creer_service
    finaliser

    log_info "Module 4 termine — $(date)"
}

main "$@"
