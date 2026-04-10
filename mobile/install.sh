#!/bin/bash
# ================================================================
#  SIEM Africa — Module 5 : Application mobile PWA
#  Fichier  : mobile/install.sh
#  Usage    : sudo bash install.sh
#  Version  : 2.0
# ================================================================
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

LOG_FILE="/var/log/siem-africa-install.log"
MOBILE_DIR="/opt/siem-africa/mobile"
DASH_DIR="/opt/siem-africa/dashboard"
ENV_FILE="/opt/siem-africa/.env"
CRED_FILE="/opt/siem-africa/credentials.txt"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_DASH="siem-dashboard"

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
    echo "║       SIEM Africa — Module 5                        ║"
    echo "║       Application mobile PWA + Cloudflare Tunnel    ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ── Etape 1 : Verifications ───────────────────────────────────────
check_all() {
    log_etape "1/4" "VERIFICATIONS"
    [ "$EUID" -ne 0 ] && quitter "sudo requis"
    log_ok "Root"
    [ ! -f "$ENV_FILE" ] && quitter "Module 1 non installe"
    log_ok "Module 1 present"
    [ ! -d "$DASH_DIR" ] && quitter "Module 4 non installe — lancez dashboard/install.sh"
    log_ok "Module 4 present"
    # Verifier les fichiers PWA
    for f in index.html app.js style.css sw.js manifest.json; do
        [ ! -f "${SCRIPT_DIR}/${f}" ] && quitter "$f introuvable dans $SCRIPT_DIR"
    done
    log_ok "Fichiers PWA presents"
}

# ── Etape 2 : Deploiement PWA ─────────────────────────────────────
deploy_pwa() {
    log_etape "2/4" "DEPLOIEMENT PWA"

    mkdir -p "$MOBILE_DIR"
    cp -r "${SCRIPT_DIR}"/*.html \
          "${SCRIPT_DIR}"/*.js \
          "${SCRIPT_DIR}"/*.css \
          "${SCRIPT_DIR}"/*.json \
          "$MOBILE_DIR/" 2>/dev/null || true

    # Generer des icones PWA simples (PNG via Python si disponible)
    _generer_icones

    # Droits
    chown -R "${USER_DASH}:${USER_DASH}" "$MOBILE_DIR"
    chmod -R 750 "$MOBILE_DIR"
    log_ok "Fichiers PWA deployes dans $MOBILE_DIR"

    # Ajouter la route /mobile/ dans le dashboard Django
    _configurer_route_django
}

_generer_icones() {
    # Generer des icones simples via Python
    python3 -c "
import struct, zlib, os

def create_simple_png(size, output_path):
    # PNG simple en couleur sombre (logo SIEM Africa)
    def write_chunk(chunk_type, data):
        chunk = struct.pack('>I', len(data)) + chunk_type + data
        chunk += struct.pack('>I', zlib.crc32(chunk_type + data) & 0xffffffff)
        return chunk

    # Header PNG
    header = b'\\x89PNG\\r\\n\\x1a\\n'
    # IHDR
    ihdr_data = struct.pack('>IIBBBBB', size, size, 8, 2, 0, 0, 0)
    ihdr = write_chunk(b'IHDR', ihdr_data)
    # IDAT — image sombre avec texte
    rows = []
    for y in range(size):
        row = [0]  # filter byte
        for x in range(size):
            # Cercle bleu marine avec bouclier
            cx, cy = size//2, size//2
            r = size//2 - 4
            if (x-cx)**2 + (y-cy)**2 <= r**2:
                row += [26, 26, 46]  # couleur dark
            else:
                row += [255, 255, 255]  # blanc
        rows.append(bytes(row))
    raw = b''.join(rows)
    compressed = zlib.compress(raw)
    idat = write_chunk(b'IDAT', compressed)
    iend = write_chunk(b'IEND', b'')
    with open(output_path, 'wb') as f:
        f.write(header + ihdr + idat + iend)

create_simple_png(192, '${MOBILE_DIR}/icon-192.png')
create_simple_png(512, '${MOBILE_DIR}/icon-512.png')
print('Icones generees')
" 2>/dev/null && log_ok "Icones PWA generees" || log_warn "Icones non generees — ajoutez icon-192.png et icon-512.png manuellement"
}

_configurer_route_django() {
    # Ajouter la route statique pour /mobile/ dans Django si pas deja presente
    URLS_FILE="${DASH_DIR}/siem_africa/urls.py"
    if [ -f "$URLS_FILE" ] && ! grep -q "mobile" "$URLS_FILE"; then
        # Ajouter un TemplateView pour /mobile/
        cat >> "$URLS_FILE" << 'DJURLS'

# Route PWA mobile
from django.views.generic import TemplateView
from django.urls import re_path
urlpatterns += [
    re_path(r'^mobile/.*$', TemplateView.as_view(template_name='mobile/index.html')),
]
DJURLS

        # Copier les templates mobile dans le dashboard
        mkdir -p "${DASH_DIR}/templates/mobile"
        cp "${MOBILE_DIR}/index.html" "${DASH_DIR}/templates/mobile/"

        # Copier les assets dans static
        mkdir -p "${DASH_DIR}/static/mobile"
        cp "${MOBILE_DIR}"/*.js "${DASH_DIR}/static/mobile/" 2>/dev/null || true
        cp "${MOBILE_DIR}"/*.css "${DASH_DIR}/static/mobile/" 2>/dev/null || true
        cp "${MOBILE_DIR}"/*.json "${DASH_DIR}/static/mobile/" 2>/dev/null || true
        cp "${MOBILE_DIR}"/*.png "${DASH_DIR}/static/mobile/" 2>/dev/null || true

        chown -R "${USER_DASH}:${USER_DASH}" "${DASH_DIR}/templates/mobile" "${DASH_DIR}/static/mobile"

        # Collecte statiques
        cd "$DASH_DIR"
        sudo -u "$USER_DASH" python3 manage.py collectstatic --noinput > /dev/null 2>&1 || true

        systemctl restart siem-dashboard 2>/dev/null || true
        log_ok "Route /mobile/ configuree dans Django"
    else
        log_info "Route /mobile/ deja configuree ou Django non disponible"
    fi
}

# ── Etape 3 : Cloudflare Tunnel ───────────────────────────────────
setup_cloudflare() {
    log_etape "3/4" "CLOUDFLARE TUNNEL"

    # Installer cloudflared
    if ! command -v cloudflared > /dev/null 2>&1; then
        log_info "Installation de cloudflared..."
        curl -sL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
             -o /usr/local/bin/cloudflared 2>/dev/null || \
        wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
             -O /usr/local/bin/cloudflared 2>/dev/null || true

        if [ -f /usr/local/bin/cloudflared ]; then
            chmod +x /usr/local/bin/cloudflared
            log_ok "cloudflared installe"
        else
            log_warn "Impossible d'installer cloudflared — acces distant non disponible"
            return
        fi
    else
        log_ok "cloudflared deja present"
    fi

    SERVER_PORT=$(grep "^FLASK_PORT=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || echo "8000")

    # Creer le service Cloudflare Tunnel (mode quick tunnel — gratuit)
    cat > /etc/systemd/system/siem-tunnel.service << TUNNEL
[Unit]
Description=SIEM Africa Cloudflare Tunnel
After=network.target siem-dashboard.service

[Service]
Type=simple
User=nobody
ExecStart=/usr/local/bin/cloudflared tunnel --no-autoupdate run --url http://localhost:${SERVER_PORT}
Restart=on-failure
RestartSec=10
StandardOutput=append:/var/log/siem-africa/tunnel.log
StandardError=append:/var/log/siem-africa/tunnel.log

[Install]
WantedBy=multi-user.target
TUNNEL

    touch /var/log/siem-africa/tunnel.log
    chmod 666 /var/log/siem-africa/tunnel.log

    systemctl daemon-reload
    systemctl enable siem-tunnel
    systemctl restart siem-tunnel 2>/dev/null || true
    sleep 5

    # Recuperer l'URL du tunnel
    TUNNEL_URL=$(grep -oP 'https://[a-z0-9\-]+\.trycloudflare\.com' /var/log/siem-africa/tunnel.log 2>/dev/null | head -1)

    if [ -n "$TUNNEL_URL" ]; then
        log_ok "Tunnel actif : $TUNNEL_URL"
        # Sauvegarder l'URL
        if grep -q "^CLOUDFLARE_URL=" "$ENV_FILE"; then
            sed -i "s|^CLOUDFLARE_URL=.*|CLOUDFLARE_URL=${TUNNEL_URL}|" "$ENV_FILE"
        else
            echo "CLOUDFLARE_URL=${TUNNEL_URL}" >> "$ENV_FILE"
        fi
    else
        log_warn "URL du tunnel non encore disponible — attendez 30 secondes puis :"
        log_warn "  grep trycloudflare /var/log/siem-africa/tunnel.log"
    fi
}

# ── Etape 4 : Credentials ─────────────────────────────────────────
update_credentials() {
    log_etape "4/4" "MISE A JOUR CREDENTIALS"
    SERVER_IP=$(grep "^SERVER_IP=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || hostname -I | awk '{print $1}')
    TUNNEL_URL=$(grep "^CLOUDFLARE_URL=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || echo "En attente...")

    cat >> "$CRED_FILE" << CREDS

── MODULE 5 — APPLICATION MOBILE PWA ────────────────────────
  Installe le : $(date '+%d/%m/%Y a %H:%M')

── ACCES ─────────────────────────────────────────────────────
  Reseau local    : http://${SERVER_IP}:8000/mobile/
  Acces distant   : ${TUNNEL_URL}/mobile/

── INSTALLATION SUR LE TELEPHONE ────────────────────────────
  1. Ouvrir Chrome sur le telephone
  2. Aller sur ${TUNNEL_URL}/mobile/
  3. Menu Chrome (3 points) → "Ajouter a l'ecran d'accueil"
  4. L'application apparait comme une vraie app

── CONNEXION APP MOBILE ──────────────────────────────────────
  Identifiant : votre EMAIL
  MDP         : choisi a l'installation du module 4
  Politique   : meme regles que le dashboard

── COMMANDES UTILES ──────────────────────────────────────────
  URL tunnel      : grep trycloudflare /var/log/siem-africa/tunnel.log
  Etat tunnel     : systemctl status siem-tunnel
  Logs tunnel     : tail -f /var/log/siem-africa/tunnel.log
  Redemarrer      : systemctl restart siem-tunnel

── PROCHAINE ETAPE ───────────────────────────────────────────
  Module 6 — Rapports automatiques PDF + Excel
  Commande : cd ../reports && sudo bash install.sh

CREDS

    chmod 600 "$CRED_FILE"
    log_ok "credentials.txt mis a jour"
}

show_summary() {
    SERVER_IP=$(grep "^SERVER_IP=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || hostname -I | awk '{print $1}')
    TUNNEL_URL=$(grep "^CLOUDFLARE_URL=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || "En attente...")

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     MODULE 5 — INSTALLATION TERMINEE                ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}── ACCES APPLICATION MOBILE ─────────────────────────${NC}"
    echo -e "  Local   : ${GREEN}http://${SERVER_IP}:8000/mobile/${NC}"
    echo -e "  Distant : ${GREEN}${TUNNEL_URL}/mobile/${NC}"
    echo ""
    echo -e "${CYAN}── INSTALLATION SUR TELEPHONE ───────────────────────${NC}"
    echo -e "  1. Ouvrir Chrome"
    echo -e "  2. Aller sur l'URL distante ci-dessus"
    echo -e "  3. Menu (3 points) → 'Ajouter a l'ecran d'accueil'"
    echo ""
    echo -e "${CYAN}── CONNEXION ────────────────────────────────────────${NC}"
    echo -e "  Identifiant : votre EMAIL"
    echo -e "  Meme MDP que le dashboard"
    echo ""
    echo -e "${CYAN}── PROCHAINE ETAPE ──────────────────────────────────${NC}"
    echo -e "  ${YELLOW}cd ../reports && sudo bash install.sh${NC}"
    echo ""
}

main() {
    echo "=== SIEM Africa Module 5 - $(date) ===" >> "$LOG_FILE"
    show_banner
    check_all
    deploy_pwa
    setup_cloudflare
    update_credentials
    show_summary
}

main "$@"
