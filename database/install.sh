#!/bin/bash
# ================================================================
#  SIEM Africa — Module 2 : Base de données SQLite
#  Fichier  : 2-database/install.sh
#  Usage    : sudo ./install.sh
#  Version  : 1.0
# ================================================================

set -euo pipefail

# ── Couleurs ──
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

log_ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
log_info() { echo -e "${CYAN}[i]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_step() {
    echo ""
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}
log_abort() { echo -e "${RED}[✗] ERREUR : $1${NC}"; exit 1; }

# Répertoire du script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Banner ──
clear
echo -e "${CYAN}  SIEM Africa — Module 2 : Base de données SQLite${NC}"
echo -e "  ${YELLOW}Création du schéma + import des 300+ signatures d'attaques${NC}"
echo ""

# ================================================================
# ÉTAPE 1 — VÉRIFICATIONS
# ================================================================
log_step "Étape 1/6 — Vérifications"

# Root requis
[[ $EUID -ne 0 ]] && log_abort "Lancez avec : sudo ./install.sh"
log_ok "Droits root confirmés"

# Vérifier que les fichiers SQL sont présents
[[ ! -f "${SCRIPT_DIR}/schema.sql" ]]  && log_abort "Fichier schema.sql introuvable dans ${SCRIPT_DIR}"
[[ ! -f "${SCRIPT_DIR}/attacks.sql" ]] && log_abort "Fichier attacks.sql introuvable dans ${SCRIPT_DIR}"
log_ok "Fichiers SQL présents"

# Charger le .env si disponible
ENV_FILE="/opt/siem-africa/.env"
if [[ -f "${ENV_FILE}" ]]; then
    # Charger uniquement les variables utiles
    DB_PATH=$(grep "^DB_PATH=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"')
    ADMIN_EMAIL=$(grep "^ADMIN_EMAIL=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"')
    SIEM_LANG=$(grep "^LANG=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"')
    ADMIN_PASS=$(grep "^# Admin pass:" "${ENV_FILE}" | cut -d':' -f2 | tr -d ' ' 2>/dev/null || echo "")
    log_ok "Configuration chargée depuis .env"
else
    log_warn "Fichier .env non trouvé — valeurs par défaut utilisées"
    log_warn "Le module 1 (installation Snort + Wazuh) doit être lancé en premier"
fi

# Valeurs par défaut si non définies
DB_PATH="${DB_PATH:-/opt/siem-africa/siem_africa.db}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@siem-africa.local}"
SIEM_LANG="${SIEM_LANG:-fr}"

log_info "Base de données cible : ${DB_PATH}"

# ================================================================
# ÉTAPE 2 — INSTALLATION SQLITE3 ET PYTHON
# ================================================================
log_step "Étape 2/6 — Installation des dépendances"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

# SQLite3
if ! command -v sqlite3 &>/dev/null; then
    apt-get install -y -qq sqlite3
    log_ok "SQLite3 installé"
else
    log_ok "SQLite3 déjà installé ($(sqlite3 --version | awk '{print $1}'))"
fi

# Python3 et pip
if ! command -v python3 &>/dev/null; then
    apt-get install -y -qq python3 python3-pip
fi

# bcrypt pour le hachage des mots de passe
python3 -c "import bcrypt" 2>/dev/null || {
    pip3 install bcrypt --quiet --break-system-packages 2>/dev/null || \
    pip3 install bcrypt --quiet
}
log_ok "Python3 + bcrypt prêts"

# ================================================================
# ÉTAPE 3 — CRÉATION DE LA BASE DE DONNÉES
# ================================================================
log_step "Étape 3/6 — Création de la base de données"

# Créer les répertoires
mkdir -p "$(dirname "${DB_PATH}")"
mkdir -p /opt/siem-africa/rapports/installation

# Sauvegarder si la base existe déjà
if [[ -f "${DB_PATH}" ]]; then
    BACKUP="${DB_PATH}.backup_$(date +%Y%m%d_%H%M%S)"
    cp "${DB_PATH}" "${BACKUP}"
    log_warn "Base existante sauvegardée : ${BACKUP}"
fi

# Créer la base avec le schéma
log_info "Création de la base SQLite : ${DB_PATH}"
sqlite3 "${DB_PATH}" < "${SCRIPT_DIR}/schema.sql"

# Compter ce qui a été créé
TABLE_COUNT=$(sqlite3 "${DB_PATH}" "SELECT COUNT(*) FROM sqlite_master WHERE type='table';")
VIEW_COUNT=$(sqlite3  "${DB_PATH}" "SELECT COUNT(*) FROM sqlite_master WHERE type='view';")
INDEX_COUNT=$(sqlite3 "${DB_PATH}" "SELECT COUNT(*) FROM sqlite_master WHERE type='index';")

log_ok "Tables créées  : ${TABLE_COUNT}"
log_ok "Vues créées    : ${VIEW_COUNT}"
log_ok "Index créés    : ${INDEX_COUNT}"

# ================================================================
# ÉTAPE 4 — IMPORT DES SIGNATURES D'ATTAQUES
# ================================================================
log_step "Étape 4/6 — Import des signatures d'attaques"

log_info "Import des signatures contextualisées Afrique..."
sqlite3 "${DB_PATH}" < "${SCRIPT_DIR}/attacks.sql"

ATTACK_COUNT=$(sqlite3 "${DB_PATH}" "SELECT COUNT(*) FROM attaques;")
log_ok "Signatures importées : ${ATTACK_COUNT}"

# Affichage par catégorie
echo ""
echo -e "  ${BOLD}Répartition par catégorie :${NC}"
while IFS='|' read -r cat nb; do
    printf "  %-25s : %s signatures\n" "${cat}" "${nb}"
done < <(sqlite3 "${DB_PATH}" \
    "SELECT categorie, COUNT(*) FROM attaques GROUP BY categorie ORDER BY COUNT(*) DESC;")
echo ""

# Répartition par gravité
echo -e "  ${BOLD}Répartition par gravité :${NC}"
while IFS='|' read -r grav nb; do
    case "${grav}" in
        4) label="Critique" color="${RED}" ;;
        3) label="Haute   " color="${YELLOW}" ;;
        2) label="Moyenne " color="${CYAN}" ;;
        1) label="Faible  " color="${GREEN}" ;;
        *) label="Inconnu " color="${NC}" ;;
    esac
    echo -e "  ${color}●${NC} ${label} : ${nb} signatures"
done < <(sqlite3 "${DB_PATH}" \
    "SELECT gravite, COUNT(*) FROM attaques GROUP BY gravite ORDER BY gravite DESC;")
echo ""

# ================================================================
# ÉTAPE 5 — CRÉATION DU COMPTE ADMIN
# ================================================================
log_step "Étape 5/6 — Création des comptes utilisateurs"

# Demander le mot de passe admin si pas disponible
if [[ -z "${ADMIN_PASS:-}" ]]; then
    echo -e "  ${YELLOW}Définissez le mot de passe du compte admin SIEM Africa :${NC}"
    while true; do
        echo -n "  Mot de passe (min. 12 caractères) : "
        read -rs ADMIN_PASS; echo ""
        echo -n "  Confirmez : "
        read -rs ADMIN_PASS2; echo ""
        [[ "${ADMIN_PASS}" == "${ADMIN_PASS2}" && ${#ADMIN_PASS} -ge 12 ]] && break
        [[ ${#ADMIN_PASS} -lt 12 ]] && log_warn "Minimum 12 caractères" \
                                     || log_warn "Mots de passe différents"
    done
fi

# Générer le hash bcrypt
log_info "Génération du hash bcrypt..."
ADMIN_HASH=$(python3 - << PYEOF
import bcrypt, sys
try:
    pwd = "${ADMIN_PASS}".encode()
    salt = bcrypt.gensalt(rounds=12)
    h = bcrypt.hashpw(pwd, salt)
    print(h.decode())
except Exception as e:
    print("ERROR:" + str(e), file=sys.stderr)
    sys.exit(1)
PYEOF
)

[[ "${ADMIN_HASH}" == ERROR* ]] && log_abort "Échec génération hash : ${ADMIN_HASH}"

# Insérer le compte admin
sqlite3 "${DB_PATH}" << SQLEOF
INSERT OR REPLACE INTO utilisateurs
    (username, email, password_hash, role, langue, premiere_connexion)
VALUES
    ('admin',
     '${ADMIN_EMAIL}',
     '${ADMIN_HASH}',
     'admin_securite',
     '${SIEM_LANG}',
     1);
SQLEOF

log_ok "Compte admin créé (première connexion obligatoire pour changer username + MDP)"

# Permissions sur la base
if id "siem-africa" &>/dev/null; then
    chown siem-africa:siem-africa "${DB_PATH}"
    log_ok "Propriétaire : siem-africa"
fi
chmod 640 "${DB_PATH}"
log_ok "Permissions configurées (640)"

# ================================================================
# ÉTAPE 6 — MISE À JOUR CREDENTIALS + RAPPORT
# ================================================================
log_step "Étape 6/6 — Mise à jour du fichier credentials"

CRED_FILE="/opt/siem-africa/credentials.txt"
if [[ -f "${CRED_FILE}" ]]; then
    # Ajouter la section base de données
    cat >> "${CRED_FILE}" << CREDS

── BASE DE DONNÉES (module 2) ────────────────────────────────
  Type                 : SQLite
  Chemin               : ${DB_PATH}
  Tables               : ${TABLE_COUNT}
  Vues                 : ${VIEW_COUNT}
  Signatures attaques  : ${ATTACK_COUNT}
  Propriétaire         : siem-africa
  Permissions          : 640

  Comptes créés :
  ├── admin     (admin_securite) — changer MDP + username à la 1ère connexion
  └── dirigeant (à créer depuis le dashboard)

  Commandes utiles :
  Ouvrir la base     : sqlite3 ${DB_PATH}
  Compter alertes    : sqlite3 ${DB_PATH} "SELECT COUNT(*) FROM alertes;"
  Voir stats         : sqlite3 ${DB_PATH} "SELECT * FROM v_stats_dashboard;"

── PROCHAINE ÉTAPE ───────────────────────────────────────────
  Module 3 — Agent intelligent
  Commande : cd ../3-agent && sudo ./install.sh

CREDS
    log_ok "credentials.txt mis à jour"
else
    log_warn "credentials.txt non trouvé — lancez d abord le module 1"
fi

# Rapport d'installation module 2
REPORT="/opt/siem-africa/rapports/installation/rapport_module2_$(date +%Y%m%d_%H%M%S).txt"
cat > "${REPORT}" << REPORT_CONTENT
================================================================
  SIEM Africa — Rapport d'installation Module 2
  Date         : $(date '+%d/%m/%Y à %H:%M:%S')
================================================================
STATUT : INSTALLATION RÉUSSIE

Base de données : ${DB_PATH}
Version SQLite  : $(sqlite3 --version | awk '{print $1}')

Tables créées   : ${TABLE_COUNT}
  utilisateurs, attaques, alertes, actions_admin,
  ips_bloquees, faux_positifs, attaques_inconnues,
  agents, rapports, parametres, (sqlite_sequence)

Vues créées     : ${VIEW_COUNT}
  v_alertes_recentes, v_stats_dashboard

Index créés     : ${INDEX_COUNT}

Signatures importées : ${ATTACK_COUNT} attaques contextualisées Afrique

Répartition par catégorie :
$(sqlite3 "${DB_PATH}" "SELECT '  ' || categorie || ' : ' || COUNT(*) FROM attaques GROUP BY categorie ORDER BY COUNT(*) DESC;")

Comptes créés :
  admin (admin_securite) — première connexion obligatoire

Prochaine étape :
  cd ../3-agent && sudo ./install.sh
================================================================
REPORT_CONTENT

log_ok "Rapport : ${REPORT}"

# ── RÉSUMÉ FINAL ─────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  ✓  MODULE 2 — BASE DE DONNÉES INSTALLÉE${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}Base de données :${NC}"
echo -e "  ${GREEN}✓${NC} Chemin       : ${CYAN}${DB_PATH}${NC}"
echo -e "  ${GREEN}✓${NC} Tables       : ${CYAN}${TABLE_COUNT}${NC}"
echo -e "  ${GREEN}✓${NC} Vues         : ${CYAN}${VIEW_COUNT}${NC}"
echo -e "  ${GREEN}✓${NC} Signatures   : ${CYAN}${ATTACK_COUNT} attaques contextualisées Afrique${NC}"
echo -e "  ${GREEN}✓${NC} Compte admin : ${CYAN}admin${NC} — changer username + MDP à la 1ère connexion"
echo ""
echo -e "  ${BOLD}Fichiers :${NC}"
echo -e "  ${GREEN}✓${NC} ${CYAN}/opt/siem-africa/credentials.txt${NC} mis à jour"
echo -e "  ${GREEN}✓${NC} ${CYAN}${REPORT}${NC}"
echo ""
echo -e "  ${BOLD}Prochaine étape :${NC}"
echo -e "  ${YELLOW}cd ../3-agent && sudo ./install.sh${NC}"
echo ""
