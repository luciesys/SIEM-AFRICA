#!/bin/bash
# ================================================================
#  SIEM Africa — Module 4 : Dashboard Django
#  Fichier  : dashboard/install.sh
#  Usage    : sudo bash install.sh
#  Version  : 2.0
# ================================================================
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

LOG_FILE="/var/log/siem-africa-install.log"
DASH_DIR="/opt/siem-africa/dashboard"
ENV_FILE="/opt/siem-africa/.env"
CRED_FILE="/opt/siem-africa/credentials.txt"
USER_DASH="siem-dashboard"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="8000"

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
    echo "║       SIEM Africa — Module 4                        ║"
    echo "║       Dashboard Django v2.0                         ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ── Etape 1 : Verifications ───────────────────────────────────────
check_all() {
    log_etape "1/6" "VERIFICATIONS"
    [ "$EUID" -ne 0 ] && quitter "sudo requis"
    log_ok "Root confirme"
    [ ! -f "$ENV_FILE" ] && quitter "Module 1 non installe"
    log_ok "Module 1 detecte"
    DB_PATH=$(grep "^DB_PATH=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 | tr -d '"' || echo "/opt/siem-africa/siem_africa.db")
    [ ! -f "$DB_PATH" ] && quitter "Base SQLite non trouvee — lancez le module 2"
    log_ok "Base SQLite : $DB_PATH"
    python3 --version > /dev/null 2>&1 || quitter "Python3 non installe"
    log_ok "Python3 disponible"
    # Verifier que les fichiers Django sont presents
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
                --comment "SIEM Africa - Dashboard Django" "$USER_DASH"
        log_ok "Utilisateur $USER_DASH cree (shell: /sbin/nologin)"
    fi
}

# ── Etape 3 : Installation Django ────────────────────────────────
install_django() {
    log_etape "3/6" "INSTALLATION DJANGO + DEPENDANCES"
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-pip > /dev/null 2>&1
    pip3 install --quiet django>=4.2 bcrypt gunicorn --break-system-packages 2>/dev/null || \
    pip3 install --quiet django>=4.2 bcrypt gunicorn 2>/dev/null || \
        quitter "Echec installation Django"

    python3 -c "import django; print(f'Django {django.__version__}')" 2>/dev/null && \
        log_ok "Django installe" || quitter "Django non fonctionnel"

    python3 -c "import bcrypt" 2>/dev/null && \
        log_ok "bcrypt installe" || log_warn "bcrypt non disponible — hash MD5 en fallback"
}

# ── Etape 4 : Deploiement ─────────────────────────────────────────
deploy() {
    log_etape "4/6" "DEPLOIEMENT"

    mkdir -p "$DASH_DIR"
    cp -r "${SCRIPT_DIR}"/* "$DASH_DIR/"
    log_ok "Fichiers copies dans $DASH_DIR"

    # Droits
    chown -R "${USER_DASH}:${USER_DASH}" "$DASH_DIR"
    chmod -R 750 "$DASH_DIR"

    # Donner acces a la base SQLite
    DB_PATH=$(grep "^DB_PATH=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 | tr -d '"' || echo "/opt/siem-africa/siem_africa.db")
    if [ -f "$DB_PATH" ]; then
        OWNER=$(stat -c '%U' "$DB_PATH")
        chown "${OWNER}:${USER_DASH}" "$DB_PATH"
        chmod 664 "$DB_PATH"
        log_ok "Acces base SQLite configure"
    fi

    # Acces .env
    chown root:"${USER_DASH}" "$ENV_FILE"
    chmod 640 "$ENV_FILE"
    log_ok "Acces .env configure"

    # Migrations Django (pour les sessions)
    cd "$DASH_DIR"
    sudo -u "$USER_DASH" python3 manage.py migrate --run-syncdb > /dev/null 2>&1 || \
        python3 manage.py migrate --run-syncdb > /dev/null 2>&1 || true
    log_ok "Base de sessions Django initialisee"

    # Collecte des fichiers statiques
    sudo -u "$USER_DASH" python3 manage.py collectstatic --noinput > /dev/null 2>&1 || \
        python3 manage.py collectstatic --noinput > /dev/null 2>&1 || true
    log_ok "Fichiers statiques collectes"

    # Creer le premier admin dans la base SQLite si necessaire
    _create_default_admin
}

_collect_admin_info() {
    log_etape "3b/6" "CONFIGURATION ADMINISTRATEUR"
    echo ""
    echo -e "  ${CYAN}Configuration du compte administrateur${NC}"
    echo "  ────────────────────────────────────────"
    echo ""

    # Email admin
    while true; do
        echo -n "  Email de l'administrateur : "
        read ADMIN_EMAIL
        ADMIN_EMAIL=$(echo "$ADMIN_EMAIL" | tr '[:upper:]' '[:lower:]' | xargs)
        if echo "$ADMIN_EMAIL" | grep -qE '^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'; then
            break
        fi
        echo -e "  ${RED}Email invalide. Exemple : admin@entreprise.com${NC}"
    done
    log_ok "Email admin : $ADMIN_EMAIL"

    # Mot de passe
    while true; do
        echo -n "  Mot de passe (minimum 8 caracteres) : "
        read -s ADMIN_PASSWORD
        echo ""
        if [ "${#ADMIN_PASSWORD}" -ge 8 ]; then
            echo -n "  Confirmer le mot de passe : "
            read -s ADMIN_CONFIRM
            echo ""
            if [ "$ADMIN_PASSWORD" = "$ADMIN_CONFIRM" ]; then
                break
            else
                echo -e "  ${RED}Les mots de passe ne correspondent pas.${NC}"
            fi
        else
            echo -e "  ${RED}Mot de passe trop court (minimum 8 caracteres).${NC}"
        fi
    done
    log_ok "Mot de passe configure"

    # Email dirigeant (optionnel)
    echo ""
    echo -n "  Email du dirigeant (lecture seule, optionnel — appuyez Entree pour ignorer) : "
    read DIRIGEANT_EMAIL
    DIRIGEANT_EMAIL=$(echo "$DIRIGEANT_EMAIL" | tr '[:upper:]' '[:lower:]' | xargs)

    # Nom organisation
    echo ""
    echo -n "  Nom de l'organisation : "
    read ORG_NOM
    ORG_NOM=$(echo "$ORG_NOM" | xargs)
    [ -z "$ORG_NOM" ] && ORG_NOM="Mon Entreprise"
    log_ok "Organisation : $ORG_NOM"

    echo ""
    echo -e "  ${YELLOW}Recapitulatif :${NC}"
    echo -e "  Email admin      : ${CYAN}$ADMIN_EMAIL${NC}"
    echo -e "  Email dirigeant  : ${CYAN}${DIRIGEANT_EMAIL:-Non configure}${NC}"
    echo -e "  Organisation     : ${CYAN}$ORG_NOM${NC}"
    echo ""
    echo -n "  Confirmer ? (oui/non) : "
    read CONFIRMER
    [ "$CONFIRMER" != "oui" ] && quitter "Annule par l'utilisateur"
}

_create_default_admin() {
    DB_PATH=$(grep "^DB_PATH=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 | tr -d '"' || echo "/opt/siem-africa/siem_africa.db")

    # Verifier si des utilisateurs existent
    NB_USERS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM utilisateurs;" 2>/dev/null || echo "0")

    if [ "$NB_USERS" -gt 0 ]; then
        log_info "$NB_USERS utilisateur(s) existant(s) — pas de creation"
        return
    fi

    # Hasher le mot de passe
    HASH=$(python3 -c "
import sys
password = sys.argv[1]
try:
    import bcrypt
    h = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    print(h)
except ImportError:
    import hashlib
    print(hashlib.sha256(password.encode()).hexdigest())
" "$ADMIN_PASSWORD" 2>/dev/null)

    if [ -z "$HASH" ]; then
        log_warn "Impossible de hasher le mot de passe"
        return
    fi

    # Creer le compte admin
    sqlite3 "$DB_PATH" "
    INSERT INTO utilisateurs
        (username, email, password_hash, role, langue, premiere_connexion,
         est_actif, pwd_expire_le, tentatives_echec, cree_le)
    VALUES
        ('admin', '${ADMIN_EMAIL}', '${HASH}', 'admin_securite', 'fr', 1, 1,
         datetime('now', '+90 days'), 0, datetime('now'));
    " 2>/dev/null && log_ok "Compte admin cree : $ADMIN_EMAIL"

    # Mettre a jour les parametres
    sqlite3 "$DB_PATH" "
    UPDATE parametres SET valeur='${ORG_NOM}' WHERE cle='organisation_nom';
    UPDATE parametres SET valeur='${ADMIN_EMAIL}' WHERE cle='alert_email';
    " 2>/dev/null || true

    # Mettre a jour .env
    _update_env "ALERT_EMAIL" "$ADMIN_EMAIL"
    _update_env "ORG_NOM" "$ORG_NOM"

    # Creer le compte dirigeant si email fourni
    if [ -n "$DIRIGEANT_EMAIL" ]; then
        HASH2=$(python3 -c "
import sys, secrets
password = sys.argv[1]
try:
    import bcrypt
    h = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    print(h)
except ImportError:
    import hashlib
    print(hashlib.sha256(password.encode()).hexdigest())
" "$ADMIN_PASSWORD" 2>/dev/null)

        sqlite3 "$DB_PATH" "
        INSERT INTO utilisateurs
            (username, email, password_hash, role, langue, premiere_connexion,
             est_actif, pwd_expire_le, tentatives_echec, cree_le)
        VALUES
            ('dirigeant', '${DIRIGEANT_EMAIL}', '${HASH2}', 'dirigeant', 'fr', 1, 1,
             datetime('now', '+90 days'), 0, datetime('now'));
        " 2>/dev/null && log_ok "Compte dirigeant cree : $DIRIGEANT_EMAIL"
    fi
}

_update_env() {
    local cle="$1" valeur="$2"
    if grep -q "^${cle}=" "$ENV_FILE"; then
        sed -i "s|^${cle}=.*|${cle}=${valeur}|" "$ENV_FILE"
    else
        echo "${cle}=${valeur}" >> "$ENV_FILE"
    fi
}

# ── Etape 5 : Service systemd ─────────────────────────────────────
setup_service() {
    log_etape "5/6" "CONFIGURATION SERVICE SYSTEMD"

    cat > /etc/systemd/system/siem-dashboard.service << SYSTEMD
[Unit]
Description=SIEM Africa Dashboard Django v2.0
Documentation=https://github.com/luciesys/SIEM-AFRICA
After=network.target siem-agent.service

[Service]
Type=simple
User=${USER_DASH}
Group=${USER_DASH}
WorkingDirectory=${DASH_DIR}
ExecStart=/usr/local/bin/gunicorn siem_africa.wsgi:application \\
    --bind 0.0.0.0:${PORT} \\
    --workers 2 \\
    --timeout 60 \\
    --log-file /var/log/siem-africa/dashboard.log \\
    --access-logfile /var/log/siem-africa/dashboard-access.log
Restart=on-failure
RestartSec=10
Environment=DJANGO_SETTINGS_MODULE=siem_africa.settings

# Securite
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
SYSTEMD

    mkdir -p /var/log/siem-africa
    touch /var/log/siem-africa/dashboard.log /var/log/siem-africa/dashboard-access.log
    chown "${USER_DASH}:${USER_DASH}" /var/log/siem-africa/dashboard.log \
                                        /var/log/siem-africa/dashboard-access.log

    systemctl daemon-reload
    systemctl enable siem-dashboard
    systemctl restart siem-dashboard 2>/dev/null || true
    sleep 3

    if systemctl is-active --quiet siem-dashboard; then
        log_ok "Service siem-dashboard ACTIF sur le port $PORT"
    else
        log_warn "Service non actif — verifier : journalctl -u siem-dashboard -n 30"
    fi
}

# ── Etape 6 : Credentials ─────────────────────────────────────────
update_credentials() {
    log_etape "6/6" "MISE A JOUR CREDENTIALS"
    SERVER_IP=$(grep "^SERVER_IP=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || hostname -I | awk '{print $1}')

    cat >> "$CRED_FILE" << CREDS

── MODULE 4 — DASHBOARD DJANGO ──────────────────────────────
  Installe le : $(date '+%d/%m/%Y a %H:%M')

  URL Dashboard   : http://${SERVER_IP}:${PORT}
  Utilisateur sys : ${USER_DASH} (shell: /sbin/nologin)
  Dossier         : ${DASH_DIR}
  Service         : siem-dashboard.service

── COMPTES CONFIGURES ────────────────────────────────────────
  Admin      : ${ADMIN_EMAIL}
  Dirigeant  : ${DIRIGEANT_EMAIL:-Non configure}
  IMPORTANT  : Changer le MDP obligatoire a la 1ere connexion

── CONNEXION ─────────────────────────────────────────────────
  Identifiant : votre EMAIL (ex: ${ADMIN_EMAIL})
  MDP         : celui choisi a l'installation
  URL         : http://${SERVER_IP}:${PORT}

── COMMANDES UTILES ──────────────────────────────────────────
  Etat service   : systemctl status siem-dashboard
  Logs           : tail -f /var/log/siem-africa/dashboard.log
  Redemarrer     : systemctl restart siem-dashboard

── PROCHAINE ETAPE ───────────────────────────────────────────
  Module 5 — Application mobile PWA
  Commande : cd ../mobile && sudo bash install.sh

CREDS

    chmod 600 "$CRED_FILE"
    log_ok "credentials.txt mis a jour"
}

# ── Resume ────────────────────────────────────────────────────────
show_summary() {
    SERVER_IP=$(grep "^SERVER_IP=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || hostname -I | awk '{print $1}')
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     MODULE 4 — INSTALLATION TERMINEE                ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}── ACCES DASHBOARD ──────────────────────────────────${NC}"
    echo -e "  URL   : ${GREEN}http://${SERVER_IP}:${PORT}${NC}"
    echo -e "  Login : ${YELLOW}${ADMIN_EMAIL}${NC}"
    echo -e "  MDP   : celui que vous avez configure"
    echo -e "  IMPORTANT : Changer le MDP a la 1ere connexion"
    echo ""
    echo -e "${CYAN}── ETAT DU SERVICE ──────────────────────────────────${NC}"
    if systemctl is-active --quiet siem-dashboard; then
        echo -e "  ${GREEN}[ACTIF]${NC}  siem-dashboard (port $PORT)"
    else
        echo -e "  ${RED}[INACTIF]${NC} siem-dashboard"
        echo -e "  Verifier : journalctl -u siem-dashboard -n 30"
    fi
    echo ""
    echo -e "${CYAN}── PROCHAINE ETAPE ──────────────────────────────────${NC}"
    echo -e "  ${YELLOW}cd ../mobile && sudo bash install.sh${NC}"
    echo ""
}

main() {
    echo "=== SIEM Africa Module 4 - $(date) ===" >> "$LOG_FILE"
    show_banner
    check_all
    create_user
    install_django
    _collect_admin_info
    deploy
    setup_service
    update_credentials
    show_summary
}

main "$@"
