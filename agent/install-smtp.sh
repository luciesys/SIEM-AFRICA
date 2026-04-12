#!/bin/bash
# ================================================================
#  SIEM Africa — Configuration SMTP
#  Fichier  : configure_smtp.sh
#  Usage    : sudo bash configure_smtp.sh
#
#  Ce script configure l'envoi d'emails pour les alertes.
#  Il pose 3 questions et envoie un email de test.
# ================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ENV_FILE="/opt/siem-africa/.env"

log_ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
log_info() { echo -e "${CYAN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[ATTENTION]${NC} $1"; }
log_err()  { echo -e "${RED}[ERREUR]${NC} $1"; }

# ── Verification ──────────────────────────────────────────────────
[ "$EUID" -ne 0 ] && echo "Lancez avec : sudo bash configure_smtp.sh" && exit 1
[ ! -f "$ENV_FILE" ] && echo "Module 1 non installe" && exit 1

clear
echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║       SIEM Africa — Configuration Email             ║"
echo "  ║       Alertes de securite par Gmail                 ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "  Ce script configure l'envoi d'emails pour les alertes."
echo ""
echo -e "${YELLOW}${BOLD}  PROCEDURE — Obtenir le mot de passe Gmail${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}Etape 1${NC} — Connectez-vous sur Gmail"
echo -e "    Ouvrez : https://gmail.com"
echo -e "    Utilisez l'email qui va ENVOYER les alertes"
echo ""
echo -e "  ${BOLD}Etape 2${NC} — Activez la validation en 2 etapes"
echo -e "    1. Cliquez sur votre photo en haut a droite"
echo -e "    2. Cliquez 'Gerer votre compte Google'"
echo -e "    3. Menu gauche → cliquez 'Securite'"
echo -e "    4. Cherchez 'Validation en 2 etapes' → Activez-la"
echo ""
echo -e "  ${BOLD}Etape 3${NC} — Creez le mot de passe application"
echo -e "    1. Toujours dans 'Securite'"
echo -e "    2. Cherchez 'Mots de passe des applications'"
echo -e "       Ou allez directement sur :"
echo -e "       ${YELLOW}https://myaccount.google.com/apppasswords${NC}"
echo -e "    3. Dans le champ Nom → tapez : SIEM Africa"
echo -e "    4. Cliquez 'Creer'"
echo -e "    5. Google affiche un code de 16 caracteres :"
echo -e "       ${GREEN}abcd efgh ijkl mnop${NC}"
echo -e "    ${RED}6. COPIEZ CE CODE — il disparait si vous fermez la fenetre${NC}"
echo ""
echo -e "  ${BOLD}Note${NC} — Le meme email peut envoyer ET recevoir les alertes."
echo -e "  Vous pouvez utiliser une seule adresse Gmail pour les deux."
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  Avez-vous votre code de 16 caracteres ? (oui/non) : "
read PRET
if [ "$PRET" != "oui" ]; then
    echo ""
    echo -e "  Suivez la procedure ci-dessus puis relancez :"
    echo -e "  ${YELLOW}sudo bash configure_smtp.sh${NC}"
    exit 0
fi

# ── Question 1 : Email expediteur ────────────────────────────────
echo ""
echo -e "${BOLD}  Question 1/3 — Email qui ENVOIE les alertes${NC}"
echo -e "  (Votre adresse Gmail)"
echo ""
while true; do
    echo -n "  Gmail : "
    read SMTP_USER
    SMTP_USER=$(echo "$SMTP_USER" | xargs)
    if echo "$SMTP_USER" | grep -qE '^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'; then
        log_ok "Email expediteur : $SMTP_USER"
        break
    fi
    log_err "Email invalide. Exemple : monadresse@gmail.com"
done

# ── Question 2 : Mot de passe application ────────────────────────
echo ""
echo -e "${BOLD}  Question 2/3 — Mot de passe application Gmail${NC}"
echo -e "  C'est le code de 16 caracteres genere par Google."
echo -e "  Pour le creer : https://myaccount.google.com/apppasswords"
echo -e "  ${YELLOW}Il est different de votre mot de passe Gmail normal !${NC}"
echo ""
while true; do
    echo -n "  Mot de passe (16 chars) : "
    read -s SMTP_PASSWORD
    echo ""
    # Retirer les espaces éventuels
    SMTP_PASSWORD=$(echo "$SMTP_PASSWORD" | tr -d ' ')
    if [ ${#SMTP_PASSWORD} -ge 16 ]; then
        log_ok "Mot de passe application recu (${#SMTP_PASSWORD} caracteres)"
        break
    fi
    log_err "Mot de passe trop court (minimum 16 caracteres). Reessayez."
done

# ── Question 3 : Email destinataire ──────────────────────────────
echo ""
echo -e "${BOLD}  Question 3/3 — Email qui RECOIT les alertes${NC}"
echo -e "  (Email du responsable securite de l'entreprise)"
echo -e "  Peut etre le meme que l'email expediteur."
echo ""
while true; do
    echo -n "  Email destinataire : "
    read ALERT_EMAIL
    ALERT_EMAIL=$(echo "$ALERT_EMAIL" | xargs)
    if echo "$ALERT_EMAIL" | grep -qE '^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'; then
        log_ok "Email destinataire : $ALERT_EMAIL"
        break
    fi
    log_err "Email invalide. Reessayez."
done

# ── Confirmer avant de sauvegarder ───────────────────────────────
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  Recapitulatif :"
echo -e "  Email expediteur  : ${GREEN}$SMTP_USER${NC}"
echo -e "  Mot de passe      : ${GREEN}****${NC} (${#SMTP_PASSWORD} caracteres)"
echo -e "  Email destinataire: ${GREEN}$ALERT_EMAIL${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -n "  Confirmer et enregistrer ? (oui/non) : "
read CONFIRM
[ "$CONFIRM" != "oui" ] && echo "Annule." && exit 0

# ── Sauvegarder dans .env ────────────────────────────────────────
echo ""
log_info "Sauvegarde dans $ENV_FILE ..."

# Mettre à jour chaque paramètre SMTP
for KEY in SMTP_HOST SMTP_PORT SMTP_USER SMTP_PASSWORD ALERT_EMAIL; do
    if grep -q "^${KEY}=" "$ENV_FILE"; then
        sed -i "s|^${KEY}=.*|${KEY}=PLACEHOLDER|" "$ENV_FILE"
    else
        echo "${KEY}=PLACEHOLDER" >> "$ENV_FILE"
    fi
done

sed -i "s|^SMTP_HOST=.*|SMTP_HOST=smtp.gmail.com|"   "$ENV_FILE"
sed -i "s|^SMTP_PORT=.*|SMTP_PORT=587|"               "$ENV_FILE"
sed -i "s|^SMTP_USER=.*|SMTP_USER=${SMTP_USER}|"      "$ENV_FILE"
sed -i "s|^SMTP_PASSWORD=.*|SMTP_PASSWORD=${SMTP_PASSWORD}|" "$ENV_FILE"
sed -i "s|^ALERT_EMAIL=.*|ALERT_EMAIL=${ALERT_EMAIL}|" "$ENV_FILE"

log_ok "Configuration sauvegardee dans .env"

# Ajouter aussi dans la table emails_alertes si la DB existe
DB="/opt/siem-africa/siem_africa.db"
if [ -f "$DB" ]; then
    sqlite3 "$DB" "
        INSERT OR IGNORE INTO emails_alertes (email, nom, est_actif, est_principal)
        VALUES ('${ALERT_EMAIL}', 'Email principal', 1, 1);
    " 2>/dev/null || true
    log_ok "Email enregistre dans la base de donnees"
fi

# ── Redémarrer l'agent ───────────────────────────────────────────
log_info "Redemarrage de siem-agent..."
systemctl restart siem-agent 2>/dev/null || true
sleep 3

if systemctl is-active --quiet siem-agent; then
    log_ok "siem-agent redémarre avec la nouvelle configuration"
else
    log_warn "siem-agent non actif — verifier : journalctl -u siem-agent -n 10"
fi

# ── Envoyer un email de test ─────────────────────────────────────
echo ""
log_info "Envoi d'un email de test vers $ALERT_EMAIL ..."

python3 << PYEOF
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

smtp_user = "${SMTP_USER}"
smtp_pass = "${SMTP_PASSWORD}"
alert_email = "${ALERT_EMAIL}"

sujet = "[SIEM Africa] ✅ Test de configuration email"
corps = """
Bonjour,

Ceci est un email de test de SIEM Africa.

Si vous recevez cet email, la configuration SMTP est correcte.
Les alertes de securite seront envoyees a cette adresse.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Serveur   : $(hostname)
  Date      : $(date '+%d/%m/%Y a %H:%M')
  Agent     : SIEM Africa v3.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Types d'alertes que vous recevrez :
  🔴 Critique  — Ransomware, intrusion confirmee
  🟠 Haute     — Brute force reussi, malware
  🟡 Moyenne   — Scan intensif, tentatives multiples
  🟢 Faible    — Scan simple, tentative isolee

— SIEM Africa | github.com/luciesys/SIEM-AFRICA
"""

try:
    msg = MIMEMultipart()
    msg["From"]    = smtp_user
    msg["To"]      = alert_email
    msg["Subject"] = sujet
    msg.attach(MIMEText(corps, "plain", "utf-8"))

    with smtplib.SMTP("smtp.gmail.com", 587, timeout=30) as server:
        server.ehlo()
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(smtp_user, [alert_email], msg.as_string())

    print("EMAIL_OK")

except smtplib.SMTPAuthenticationError:
    print("ERREUR_AUTH")
except smtplib.SMTPException as e:
    print(f"ERREUR_SMTP:{e}")
except Exception as e:
    print(f"ERREUR:{e}")
PYEOF

# Lire le résultat du test
RESULT=$(python3 -c "
import smtplib
from email.mime.text import MIMEText, MIMEMultipart
smtp_user='${SMTP_USER}'; smtp_pass='${SMTP_PASSWORD}'; dest='${ALERT_EMAIL}'
try:
    msg=MIMEText('Test SIEM Africa','plain','utf-8')
    msg['From']=smtp_user; msg['To']=dest; msg['Subject']='[SIEM Africa] Test email'
    with smtplib.SMTP('smtp.gmail.com',587,timeout=20) as s:
        s.ehlo(); s.starttls(); s.login(smtp_user,smtp_pass)
        s.sendmail(smtp_user,[dest],msg.as_string())
    print('OK')
except smtplib.SMTPAuthenticationError:
    print('AUTH_ERROR')
except Exception as e:
    print(f'ERROR:{e}')
" 2>/dev/null)

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
if [ "$RESULT" = "OK" ]; then
    echo -e "  ${GREEN}${BOLD}EMAIL DE TEST ENVOYE AVEC SUCCES !${NC}"
    echo -e "  Verifiez la boite de reception de : ${GREEN}$ALERT_EMAIL${NC}"
    echo ""
    echo -e "  ${GREEN}Configuration SMTP terminee. Les alertes seront"
    echo -e "  envoyees automatiquement lors des incidents.${NC}"
else
    echo -e "  ${RED}Echec de l'envoi de l'email de test.${NC}"
    echo ""
    if echo "$RESULT" | grep -q "AUTH_ERROR"; then
        echo -e "  ${YELLOW}Cause : Mot de passe incorrect.${NC}"
        echo -e "  Verifiez que vous utilisez un mot de passe APPLICATION"
        echo -e "  et non votre mot de passe Gmail normal."
        echo -e "  → https://myaccount.google.com/apppasswords"
    else
        echo -e "  ${YELLOW}Cause : $RESULT${NC}"
    fi
    echo ""
    echo -e "  Relancez : ${YELLOW}sudo bash configure_smtp.sh${NC}"
fi
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
