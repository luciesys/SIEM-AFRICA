# 🛡️ SIEM AFRICA

**Solution SIEM complète pour les entreprises africaines**

Snort (IDS) + Wazuh (SIEM) + Analyse Intelligente des Alertes

---

## ⚡ INSTALLATION DU SERVEUR

Une seule commande pour tout installer :
```bash
curl -sL https://raw.githubusercontent.com/luciesys/siem-africa/main/install.sh | sudo bash
```

### Prérequis

- Ubuntu 20.04 / 22.04 ou Debian 11 / 12
- Minimum 4 Go de RAM
- Minimum 50 Go de disque
- Connexion Internet

### Durée

30 à 45 minutes

---

## 🗑️ DÉSINSTALLATION

Pour supprimer complètement SIEM Africa :
```bash
sudo bash /opt/siem-africa/installation/uninstall_siem.sh
```

---

## 📱 INSTALLATION DES AGENTS

Après avoir installé le serveur, installez les agents sur chaque machine à surveiller.

### Agent Linux (Ubuntu, Debian, CentOS, Rocky, Fedora)
```bash
curl -sL https://raw.githubusercontent.com/luciesys/siem-africa/main/installation/agents/install_agent_universal.sh | sudo bash -s IP_DU_SERVEUR
```

Remplacez `IP_DU_SERVEUR` par l'adresse IP de votre serveur SIEM.

**Exemple :**
```bash
curl -sL https://raw.githubusercontent.com/luciesys/siem-africa/main/installation/agents/install_agent_universal.sh | sudo bash -s 192.168.1.100
```

### Agent Windows

Ouvrez PowerShell en tant qu'Administrateur et exécutez :
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/luciesys/siem-africa/main/installation/agents/install_agent.ps1" -OutFile "install_agent.ps1"
.\install_agent.ps1 -ServerIP IP_DU_SERVEUR
```

Remplacez `IP_DU_SERVEUR` par l'adresse IP de votre serveur SIEM.

**Exemple :**
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/luciesys/siem-africa/main/installation/agents/install_agent.ps1" -OutFile "install_agent.ps1"
.\install_agent.ps1 -ServerIP 192.168.1.100
```

---

## 🖥️ COMMANDES UTILES

Après installation, ces commandes sont disponibles sur le serveur :

| Commande | Description |
|----------|-------------|
| `siem-status` | Voir l'état de tous les services |
| `siem-alerts` | Voir les dernières alertes |
| `siem-update` | Mettre à jour la base de données |

---

## 📊 NIVEAUX D'ALERTE

| Icône | Niveau | Gravité | Action recommandée |
|-------|--------|---------|-------------------|
| 🟢 | 1-3 | Faible | Surveiller |
| 🟡 | 4-5 | Modéré | Vérifier dans la journée |
| 🟠 | 6-7 | Élevé | Action dans l'heure |
| 🔴 | 8-9 | Critique | Action immédiate |
| ⚫ | 10 | Urgent | INTERVENTION IMMÉDIATE |

---

## 📦 CE QUI EST INSTALLÉ

| Composant | Description |
|-----------|-------------|
| **Snort** | Système de détection d'intrusions réseau (IDS) |
| **Wazuh Manager** | Collecte et analyse des alertes |
| **Wazuh Indexer** | Stockage et indexation des données |
| **Wazuh Dashboard** | Interface web de visualisation |
| **Analyseur Intelligent** | Enrichissement des alertes avec actions recommandées |
| **Base de Connaissances** | 100 attaques documentées en français |

---

## 📁 STRUCTURE DU PROJET
```
siem-africa/
├── install.sh                    # Script d'installation principal
├── VERSION                       # Numéro de version
│
├── installation/
│   ├── install_siem.sh           # Installation Snort + Wazuh
│   ├── uninstall_siem.sh         # Désinstallation complète
│   └── agents/
│       ├── install_agent_universal.sh  # Agent Linux
│       └── install_agent.ps1           # Agent Windows
│
├── analyzer/
│   └── alert_analyzer.sh         # Analyse intelligente des alertes
│
├── knowledge_base/
│   ├── attacks.json              # Base de 100 attaques
│   └── severity_levels.json      # Niveaux de gravité
│
└── tools/
    ├── check_status.sh           # Vérification des services
    └── view_alerts.sh            # Affichage des alertes
```

---

## 🔒 ACCÈS AU DASHBOARD

Après installation, accédez au dashboard Wazuh :

- **URL :** `https://IP_DU_SERVEUR`
- **Utilisateur :** `admin`
- **Mot de passe :** Voir le fichier `/root/wazuh-credentials.txt`

---

## 🔄 MISE À JOUR

La base de données des attaques se met à jour automatiquement chaque nuit à 3h.

Pour forcer une mise à jour manuelle :
```bash
siem-update
```

---

## 🆘 EN CAS DE PROBLÈME

### Vérifier l'état des services
```bash
siem-status
```

### Redémarrer les services
```bash
sudo systemctl restart snort
sudo systemctl restart wazuh-manager
sudo systemctl restart wazuh-indexer
sudo systemctl restart wazuh-dashboard
```

### Voir les logs
```bash
sudo tail -f /var/log/snort/snort.alert.fast
sudo tail -f /var/ossec/logs/ossec.log
```

---

## 📞 SUPPORT

**SIEM Africa Team**

Pour toute question ou assistance, contactez-nous.

---

## 📄 LICENCE

Projet propriétaire - Tous droits réservés © 2026

---

*SIEM Africa - Version 1.0 - Février 2026*
