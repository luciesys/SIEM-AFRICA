#===============================================================================
#
#          FILE: install_agent.ps1
#
#         USAGE: .\install_agent.ps1 -ServerIP <WAZUH_SERVER_IP>
#
#   DESCRIPTION: Installation de l'agent Wazuh pour Windows
#
#        AUTHOR: SIEM Africa Team
#       VERSION: 1.0
#       CREATED: Février 2026
#
#===============================================================================

param(
    [Parameter(Mandatory=$false)]
    [string]$ServerIP
)

#---------------------------------------
# VARIABLES
#---------------------------------------
$WAZUH_VERSION = "4.7.0"
$INSTALLER_URL = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WAZUH_VERSION-1.msi"
$INSTALLER_PATH = "$env:TEMP\wazuh-agent.msi"

#---------------------------------------
# FONCTIONS D'AFFICHAGE
#---------------------------------------
function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                                  ║" -ForegroundColor Cyan
    Write-Host "║        INSTALLATION AGENT WAZUH - WINDOWS                        ║" -ForegroundColor Cyan
    Write-Host "║                                                                  ║" -ForegroundColor Cyan
    Write-Host "║        SIEM Africa - Solution de Sécurité                        ║" -ForegroundColor Cyan
    Write-Host "║                                                                  ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  $Message" -ForegroundColor Cyan
    Write-Host "══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Write-Error-Custom {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "[i] $Message" -ForegroundColor Yellow
}

function Write-Warning-Custom {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

#---------------------------------------
# VÉRIFICATION ADMINISTRATEUR
#---------------------------------------
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

#---------------------------------------
# CONFIGURATION DU SERVEUR
#---------------------------------------
function Get-ServerConfiguration {
    Write-Step "ÉTAPE 1/4 : CONFIGURATION DU SERVEUR WAZUH"
    
    if ([string]::IsNullOrEmpty($script:ServerIP)) {
        $script:ServerIP = Read-Host "Entrez l'adresse IP du serveur Wazuh"
    }
    
    # Valider l'IP
    $ipRegex = "^([0-9]{1,3}\.){3}[0-9]{1,3}$"
    if ($script:ServerIP -notmatch $ipRegex) {
        Write-Error-Custom "Adresse IP invalide : $script:ServerIP"
        Write-Info "Format attendu : 192.168.1.100"
        exit 1
    }
    Write-Success "Adresse IP valide : $script:ServerIP"
    
    # Test de connexion
    Write-Info "Test de connexion vers $script:ServerIP..."
    if (Test-Connection -ComputerName $script:ServerIP -Count 1 -Quiet -ErrorAction SilentlyContinue) {
        Write-Success "Serveur Wazuh accessible"
    } else {
        Write-Warning-Custom "Impossible de contacter le serveur $script:ServerIP"
        $confirm = Read-Host "Continuer quand même ? (O/N)"
        if ($confirm -ne "O" -and $confirm -ne "o") {
            Write-Info "Installation annulée"
            exit 1
        }
    }
    
    # Nom de l'agent
    $script:AgentName = $env:COMPUTERNAME
    Write-Info "Nom de l'agent détecté : $script:AgentName"
    
    $newName = Read-Host "Modifier le nom ? (laisser vide pour garder '$script:AgentName')"
    if (-not [string]::IsNullOrEmpty($newName)) {
        $script:AgentName = $newName
    }
    Write-Success "Nom de l'agent : $script:AgentName"
}

#---------------------------------------
# TÉLÉCHARGEMENT DE L'AGENT
#---------------------------------------
function Download-WazuhAgent {
    Write-Step "ÉTAPE 2/4 : TÉLÉCHARGEMENT DE L'AGENT WAZUH"
    
    Write-Info "Téléchargement depuis $INSTALLER_URL..."
    
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $INSTALLER_URL -OutFile $INSTALLER_PATH -UseBasicParsing
        Write-Success "Agent téléchargé : $INSTALLER_PATH"
    } catch {
        Write-Error-Custom "Échec du téléchargement : $_"
        exit 1
    }
}

#---------------------------------------
# INSTALLATION DE L'AGENT
#---------------------------------------
function Install-WazuhAgent {
    Write-Step "ÉTAPE 3/4 : INSTALLATION DE L'AGENT WAZUH"
    
    Write-Info "Installation en cours..."
    
    $msiArgs = @(
        "/i"
        "`"$INSTALLER_PATH`""
        "/q"
        "WAZUH_MANAGER=`"$script:ServerIP`""
        "WAZUH_AGENT_NAME=`"$script:AgentName`""
        "WAZUH_REGISTRATION_SERVER=`"$script:ServerIP`""
    )
    
    try {
        $process = Start-Process "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
        
        if ($process.ExitCode -eq 0) {
            Write-Success "Agent Wazuh installé avec succès"
        } else {
            Write-Error-Custom "Échec de l'installation. Code de sortie : $($process.ExitCode)"
            exit 1
        }
    } catch {
        Write-Error-Custom "Erreur lors de l'installation : $_"
        exit 1
    }
}

#---------------------------------------
# DÉMARRAGE DU SERVICE
#---------------------------------------
function Start-WazuhService {
    Write-Step "ÉTAPE 4/4 : DÉMARRAGE DU SERVICE"
    
    Write-Info "Démarrage du service Wazuh Agent..."
    
    try {
        Start-Service -Name "WazuhSvc" -ErrorAction Stop
        Start-Sleep -Seconds 3
        
        $service = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
        if ($service.Status -eq "Running") {
            Write-Success "Service WazuhSvc : ACTIF"
        } else {
            Write-Warning-Custom "Le service n'a pas démarré correctement"
            Write-Info "Vérifiez les logs dans : C:\Program Files (x86)\ossec-agent\ossec.log"
        }
    } catch {
        Write-Warning-Custom "Erreur lors du démarrage du service : $_"
    }
}

#---------------------------------------
# NETTOYAGE
#---------------------------------------
function Cleanup {
    if (Test-Path $INSTALLER_PATH) {
        Remove-Item $INSTALLER_PATH -Force
        Write-Info "Fichier d'installation temporaire supprimé"
    }
}

#---------------------------------------
# RÉSUMÉ FINAL
#---------------------------------------
function Show-Summary {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                                                                  ║" -ForegroundColor Green
    Write-Host "║        ✓ AGENT WAZUH INSTALLÉ AVEC SUCCÈS !                     ║" -ForegroundColor Green
    Write-Host "║                                                                  ║" -ForegroundColor Green
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  INFORMATIONS DE L'AGENT" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Système           : Windows" -ForegroundColor Yellow
    Write-Host "Nom de l'agent    : $script:AgentName" -ForegroundColor Yellow
    Write-Host "Serveur Wazuh     : $script:ServerIP" -ForegroundColor Yellow
    
    $service = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    if ($service) {
        Write-Host "Statut du service : $($service.Status)" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  COMMANDES UTILES (PowerShell Admin)" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "# Vérifier le statut de l'agent"
    Write-Host "Get-Service WazuhSvc"
    Write-Host ""
    Write-Host "# Redémarrer l'agent"
    Write-Host "Restart-Service WazuhSvc"
    Write-Host ""
    Write-Host "# Voir les logs"
    Write-Host "Get-Content 'C:\Program Files (x86)\ossec-agent\ossec.log' -Tail 50"
    
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  PROCHAINE ÉTAPE" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Vérifiez que l'agent apparaît dans le Dashboard Wazuh :"
    Write-Host "  1. Ouvrez https://$script:ServerIP"
    Write-Host "  2. Connectez-vous avec vos identifiants"
    Write-Host "  3. Allez dans 'Agents' -> L'agent '$script:AgentName' devrait apparaître"
    Write-Host ""
}

#---------------------------------------
# MAIN
#---------------------------------------
function Main {
    Write-Banner
    
    # Vérifier les droits admin
    if (-not (Test-Administrator)) {
        Write-Error-Custom "Ce script doit être exécuté en tant qu'Administrateur"
        Write-Info "Clic droit sur PowerShell -> Exécuter en tant qu'administrateur"
        exit 1
    }
    Write-Success "Droits administrateur confirmés"
    
    Get-ServerConfiguration
    Download-WazuhAgent
    Install-WazuhAgent
    Start-WazuhService
    Cleanup
    Show-Summary
}

# Exécuter
Main
