#!/bin/bash
# ================================================================
#  SIEM Africa — Module 4 : Dashboard Django
#  Fichier  : dashboard/install.sh
#  Version  : 2.1 — set -e supprime + commandes securisees
# ================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

LOG_FILE="/var/log/siem-africa-install.log"
DASH_DIR="/opt/siem-africa/dashboard"
ENV_FILE="/opt/siem-africa/.env"
CRED_FILE="/opt/siem-africa/credentials.txt"
USER_DASH="siem-dashboard"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="8000"
ADMIN_EMAIL=""
ADMIN_PASSWORD=""
DIRIGEANT_EMAIL=""
ORG_NOM="Mon Entreprise"

log()       { echo -e "$1" | tee -a "$LOG_FILE"; }
log_ok()    { log "${GREEN}[OK]${NC} $1"; }
log_info()  { log "${CYAN}[INFO]${NC} $1"; }
log_warn()  { log "${YELLOW}[ATTENTION]${NC} $1"; }
log_etape() { log "${BLUE}[ETAPE $1]${NC} $2"; }
log_err()   { log "${RED}[ERREUR]${NC} $1"; }

quitter() {
    echo -e "\n${RED}ARRETE : $1${NC}"
    echo "Journal : $LOG_FILE"
    exit 1
}

show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║       SIEM Africa — Module 4                        ║"
    echo "║       Dashboard Django v2.1                         ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ── Desinstallation si deja installe ─────────────────────────────
desinstaller_si_present() {
    local deja=0
    systemctl list-unit-files siem-dashboard.service &>/dev/null && deja=1
    [ -d "$DASH_DIR" ] && deja=1
    [ "$deja" -eq 0 ] && return 0

    echo -e "${YELLOW}  Installation precedente detectee — suppression...${NC}"
    systemctl stop siem-dashboard 2>/dev/null || true
    systemctl disable siem-dashboard 2>/dev/null || true
    rm -f /etc/systemd/system/siem-dashboard.service
    systemctl daemon-reload 2>/dev/null || true
    rm -rf "$DASH_DIR"
    id "$USER_DASH" &>/dev/null && userdel "$USER_DASH" 2>/dev/null || true
    log_ok "Ancienne installation supprimee"
    sleep 1
}

# ── Etape 1 : Verifications ───────────────────────────────────────
check_all() {
    log_etape "1/6" "VERIFICATIONS"
    [ "$EUID" -ne 0 ] && quitter "sudo requis"
    log_ok "Root confirme"

    [ ! -f "$ENV_FILE" ] && quitter "Module 1 non installe"
    log_ok "Module 1 detecte"

    DB_PATH=$(grep "^DB_PATH=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 | tr -d '"' | xargs)
    [ -z "$DB_PATH" ] && DB_PATH="/opt/siem-africa/siem_africa.db"
    [ ! -f "$DB_PATH" ] && quitter "Base SQLite non trouvee"
    log_ok "Base SQLite : $DB_PATH"

    python3 --version > /dev/null 2>&1 || quitter "Python3 non installe"
    log_ok "Python3 disponible"

    for f in manage.py requirements.txt siem_africa/settings.py core/views.py; do
        [ ! -f "${SCRIPT_DIR}/${f}" ] && quitter "$f introuvable dans $SCRIPT_DIR"
    done
    log_ok "Fichiers Django presents"
}

# ── Etape 2 : Utilisateur systeme ────────────────────────────────
create_user() {
    log_etape "2/6" "CREATION UTILISATEUR"
    if id "$USER_DASH" > /dev/null 2>&1; then
        log_info "Utilisateur $USER_DASH existe deja"
    else
        useradd --system --no-create-home --shell /sbin/nologin \
                --comment "SIEM Africa Dashboard" "$USER_DASH"
        log_ok "Utilisateur $USER_DASH cree"
    fi
}

# ── Etape 3 : Installation Django ────────────────────────────────
install_django() {
    log_etape "3/6" "INSTALLATION DJANGO"
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-pip > /dev/null 2>&1
    log_ok "Dependances systeme OK"

    pip3 install --quiet "django>=4.2" bcrypt gunicorn \
        --break-system-packages 2>/dev/null || \
    pip3 install --quiet "django>=4.2" bcrypt gunicorn 2>/dev/null || \
        log_warn "Certaines dependances non installees"

    python3 -c "import django" 2>/dev/null && \
        log_ok "Django disponible" || quitter "Django non installe"
    python3 -c "import bcrypt" 2>/dev/null && \
        log_ok "bcrypt disponible" || log_warn "bcrypt absent — hash SHA256 utilise"
}

# ── Configuration admin ───────────────────────────────────────────
collect_admin_info() {
    log_etape "3b/6" "CONFIGURATION ADMINISTRATEUR"
    echo ""

    # Email admin
    while true; do
        echo -n "  Email administrateur : "
        read ADMIN_EMAIL
        ADMIN_EMAIL=$(echo "$ADMIN_EMAIL" | tr '[:upper:]' '[:lower:]' | xargs)
        echo "$ADMIN_EMAIL" | grep -qE '^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$' && break
        echo -e "  ${RED}Email invalide. Exemple : admin@entreprise.com${NC}"
    done
    log_ok "Email admin : $ADMIN_EMAIL"

    # Mot de passe
    while true; do
        echo -n "  Mot de passe (minimum 8 caracteres) : "
        read -s ADMIN_PASSWORD
        echo ""
        if [ "${#ADMIN_PASSWORD}" -ge 8 ]; then
            echo -n "  Confirmer : "
            read -s CONFIRM
            echo ""
            [ "$ADMIN_PASSWORD" = "$CONFIRM" ] && break
            echo -e "  ${RED}Mots de passe differents.${NC}"
        else
            echo -e "  ${RED}Trop court.${NC}"
        fi
    done
    log_ok "Mot de passe configure"

    echo -n "  Email dirigeant (optionnel — Entree pour ignorer) : "
    read DIRIGEANT_EMAIL
    DIRIGEANT_EMAIL=$(echo "$DIRIGEANT_EMAIL" | tr '[:upper:]' '[:lower:]' | xargs)

    echo -n "  Nom de l'organisation : "
    read ORG_NOM
    [ -z "$ORG_NOM" ] && ORG_NOM="Mon Entreprise"
    log_ok "Organisation : $ORG_NOM"

    echo ""
    echo -e "  ${YELLOW}Recapitulatif :${NC}"
    echo -e "  Email admin     : ${CYAN}$ADMIN_EMAIL${NC}"
    echo -e "  Dirigeant       : ${CYAN}${DIRIGEANT_EMAIL:-Non configure}${NC}"
    echo -e "  Organisation    : ${CYAN}$ORG_NOM${NC}"
    echo ""
    echo -n "  Confirmer ? (oui/non) : "
    read CONF
    [ "$CONF" != "oui" ] && quitter "Annule"
}

# ── Etape 4 : Deploiement ─────────────────────────────────────────
deploy() {
    log_etape "4/6" "DEPLOIEMENT"
    DB_PATH=$(grep "^DB_PATH=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 | tr -d '"' | xargs)
    [ -z "$DB_PATH" ] && DB_PATH="/opt/siem-africa/siem_africa.db"

    mkdir -p "$DASH_DIR"
    cp -r "${SCRIPT_DIR}"/* "$DASH_DIR/" 2>/dev/null || true
    log_ok "Fichiers copies dans $DASH_DIR"

    # CORRECTION : 755 au lieu de 750 pour eviter CHDIR systemd
    chmod 755 /opt/siem-africa/
    chown -R "${USER_DASH}:${USER_DASH}" "$DASH_DIR"
    chmod -R 755 "$DASH_DIR"
    log_ok "Permissions configurees (755)"

    # Acces SQLite
    if [ -f "$DB_PATH" ]; then
        OWNER=$(stat -c '%U' "$DB_PATH")
        chown "${OWNER}:${USER_DASH}" "$DB_PATH"
        chmod 664 "$DB_PATH"
        # Dossier parent aussi
        DB_DIR=$(dirname "$DB_PATH")
        chmod 775 "$DB_DIR"
        chown root:"${USER_DASH}" "$DB_DIR"
        log_ok "Acces SQLite configure"
    fi

    # Acces .env
    chown "root:${USER_DASH}" "$ENV_FILE"
    chmod 640 "$ENV_FILE"

    # Logs
    mkdir -p /var/log/siem-africa
    touch /var/log/siem-africa/dashboard.log /var/log/siem-africa/dashboard-access.log
    chown "${USER_DASH}:${USER_DASH}" /var/log/siem-africa/dashboard.log \
                                      /var/log/siem-africa/dashboard-access.log

    # Migrations Django
    cd "$DASH_DIR"
    python3 manage.py migrate --run-syncdb > /dev/null 2>&1 && \
        log_ok "Sessions Django initialisees" || \
        log_warn "Migrations echouees (non fatal)"

    # Collectstatic
    python3 manage.py collectstatic --noinput > /dev/null 2>&1 && \
        log_ok "Fichiers statiques collectes" || \
        log_warn "Collectstatic echoue (non fatal)"

    # Creer les comptes
    _create_admin
}

_create_admin() {
    DB_PATH=$(grep "^DB_PATH=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 | tr -d '"' | xargs)
    [ -z "$DB_PATH" ] && DB_PATH="/opt/siem-africa/siem_africa.db"

    NB_USERS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM utilisateurs;" 2>/dev/null || echo "0")
    NB_USERS=$(echo "$NB_USERS" | tr -d '[:space:]')

    if [ "${NB_USERS:-0}" -gt 0 ]; then
        log_info "$NB_USERS utilisateur(s) existant(s)"
        return
    fi

    # Hasher le mot de passe
    HASH=$(python3 -c "
import sys
try:
    import bcrypt
    h = bcrypt.hashpw(sys.argv[1].encode(), bcrypt.gensalt(rounds=12)).decode()
    print(h)
except:
    import hashlib
    print(hashlib.sha256(sys.argv[1].encode()).hexdigest())
" "$ADMIN_PASSWORD" 2>/dev/null)

    [ -z "$HASH" ] && { log_warn "Hash MDP echoue"; return; }

    # Creer admin
    sqlite3 "$DB_PATH" "
INSERT INTO utilisateurs
    (username, email, password_hash, role, langue,
     premiere_connexion, est_actif, pwd_expire_le, tentatives_echec, cree_le)
VALUES
    ('admin', '${ADMIN_EMAIL}', '${HASH}', 'admin_securite', 'fr',
     1, 1, datetime('now', '+90 days'), 0, datetime('now'));
" 2>/dev/null && log_ok "Compte admin cree : $ADMIN_EMAIL" || \
    log_warn "Creation compte admin echouee"

    # Mettre a jour les parametres
    sqlite3 "$DB_PATH" "
UPDATE parametres SET valeur='${ORG_NOM}' WHERE cle='organisation_nom';
UPDATE parametres SET valeur='${ADMIN_EMAIL}' WHERE cle='alert_email';
" 2>/dev/null || true

    # Mettre a jour .env
    grep -q "^ORG_NOM=" "$ENV_FILE" && \
        sed -i "s|^ORG_NOM=.*|ORG_NOM=${ORG_NOM}|" "$ENV_FILE" || \
        echo "ORG_NOM=${ORG_NOM}" >> "$ENV_FILE"
    grep -q "^ALERT_EMAIL=" "$ENV_FILE" && \
        sed -i "s|^ALERT_EMAIL=.*|ALERT_EMAIL=${ADMIN_EMAIL}|" "$ENV_FILE" || \
        echo "ALERT_EMAIL=${ADMIN_EMAIL}" >> "$ENV_FILE"

    # Creer dirigeant si email fourni
    if [ -n "$DIRIGEANT_EMAIL" ]; then
        HASH2=$(python3 -c "
import sys
try:
    import bcrypt
    h = bcrypt.hashpw(sys.argv[1].encode(), bcrypt.gensalt(rounds=12)).decode()
    print(h)
except:
    import hashlib
    print(hashlib.sha256(sys.argv[1].encode()).hexdigest())
" "$ADMIN_PASSWORD" 2>/dev/null)
        sqlite3 "$DB_PATH" "
INSERT INTO utilisateurs
    (username, email, password_hash, role, langue,
     premiere_connexion, est_actif, pwd_expire_le, tentatives_echec, cree_le)
VALUES
    ('dirigeant', '${DIRIGEANT_EMAIL}', '${HASH2}', 'dirigeant', 'fr',
     1, 1, datetime('now', '+90 days'), 0, datetime('now'));
" 2>/dev/null && log_ok "Compte dirigeant cree : $DIRIGEANT_EMAIL" || \
        log_warn "Creation compte dirigeant echouee"
    fi
}

# ── Etape 5 : Service systemd ─────────────────────────────────────
setup_service() {
    log_etape "5/6" "SERVICE SYSTEMD"

    cat > /etc/systemd/system/siem-dashboard.service << SYSTEMD
[Unit]
Description=SIEM Africa Dashboard Django v2.1
Documentation=https://github.com/luciesys/SIEM-AFRICA
After=network.target

[Service]
Type=simple
User=${USER_DASH}
Group=${USER_DASH}
WorkingDirectory=${DASH_DIR}
ExecStart=/usr/local/bin/gunicorn siem_africa.wsgi:application \
    --bind 0.0.0.0:${PORT} \
    --workers 2 \
    --timeout 60 \
    --log-file /var/log/siem-africa/dashboard.log \
    --access-logfile /var/log/siem-africa/dashboard-access.log
Restart=on-failure
RestartSec=10
Environment=DJANGO_SETTINGS_MODULE=siem_africa.settings

[Install]
WantedBy=multi-user.target
SYSTEMD

    systemctl daemon-reload
    systemctl enable siem-dashboard
    systemctl restart siem-dashboard 2>/dev/null || true
    sleep 4

    if systemctl is-active --quiet siem-dashboard; then
        log_ok "Service siem-dashboard ACTIF sur le port $PORT"
    else
        log_warn "Service non actif — verifier : journalctl -u siem-dashboard -n 20"
        # Diagnostic
        log_info "Tentative de lancement direct :"
        cd "$DASH_DIR"
        timeout 5 sudo -u "$USER_DASH" \
            python3 manage.py check 2>&1 | tail -5 | tee -a "$LOG_FILE" || true
    fi
}

# ── Etape 6 : Credentials ─────────────────────────────────────────
update_credentials() {
    log_etape "6/6" "CREDENTIALS"
    SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")

    cat >> "$CRED_FILE" << CREDS

── MODULE 4 — DASHBOARD DJANGO (v2.1) ───────────────────────
  Installe le  : $(date '+%d/%m/%Y a %H:%M')
  URL          : http://${SERVER_IP}:${PORT}
  Service      : siem-dashboard.service
  Logs         : /var/log/siem-africa/dashboard.log

  Admin email  : ${ADMIN_EMAIL}
  Dirigeant    : ${DIRIGEANT_EMAIL:-Non configure}
  Organisation : ${ORG_NOM}
  IMPORTANT    : Changer le MDP a la premiere connexion

  Etat service : systemctl status siem-dashboard
  Redemarrer   : systemctl restart siem-dashboard
CREDS

    chmod 600 "$CRED_FILE"
    log_ok "credentials.txt mis a jour"
}

show_summary() {
    SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     MODULE 4 — INSTALLATION TERMINEE                ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    if systemctl is-active --quiet siem-dashboard; then
        echo -e "  ${GREEN}[ACTIF]${NC}  siem-dashboard"
        echo -e "  URL : ${GREEN}http://${SERVER_IP}:${PORT}${NC}"
    else
        echo -e "  ${RED}[INACTIF]${NC} siem-dashboard"
        echo -e "  journalctl -u siem-dashboard -n 30"
    fi
    echo ""
    echo -e "  Login : ${CYAN}${ADMIN_EMAIL}${NC}"
    echo -e "  MDP   : celui configure a l'installation"
    echo ""
}

main() {
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    echo "=== SIEM Africa Module 4 v2.1 - $(date) ===" >> "$LOG_FILE"
    show_banner
    desinstaller_si_present
    check_all
    create_user
    install_django
    collect_admin_info
    deploy
    setup_service
    update_credentials
    show_summary
    log_info "Module 4 termine — $(date)"
}

main "$@"
