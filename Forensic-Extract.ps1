
# Récupération d'informations sur un poste compromis/
# Windows vers Windows/Linux
# ATTENTION il est impératif de lancer une écoute Netcat sur un autre poste du même réseau : nc.exe -L -p 4444
#      -L : Lancer une écoute et ouvre une nouvelle connexion quand celle -ci est fermée
#      -p : précise le port d'écoute du server

# ----- Récupération Variables ----- #

# Encodage Français
[Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(437) 

Write-Host "
  ______                       _             ______      _                  _   
 |  ____|                     (_)           |  ____|    | |                | |  
 | |__ ___  _ __ ___ _ __  ___ _  ___ ______| |__  __  _| |_ _ __ __ _  ___| |_ 
 |  __/ _ \| '__/ _ \ '_ \/ __| |/ __|______|  __| \ \/ / __| '__/ _` |/ __| __|
 | | | (_) | | |  __/ | | \__ \ | (__       | |____ >  <| |_| | | (_| | (__| |_ 
 |_|  \___/|_|  \___|_| |_|___/_|\___|      |______/_/\_\\__|_|  \__,_|\___|\__|
                                                                                
                                                                                "

$ErrorActionPreference= 'silentlycontinue' #don't display errors
$path = Read-Host "Chemin absolu vers le programme nc.exe [C:\users\toto\Tools] : "
$ipServ = Read-Host "Entrez l'adresse IP du serveur Netcat : "
$portServ = Read-host "Entrez le port d'écoute du serveur Netcat [Défaut:4444] : "
$timer = Read-host "Entrer le nombre de secondes entre chaque envoie au serveur Netcat : [Défaut:2]"


#################### #################### ----- Début du script ----- #################### #################### 

####################  -- Déplacement dans $path -- #################### 
try {cd $path }
catch {
        Write-Host "Erreur : Impossible d'atteindre le chemin vers les outils Unix"
        Write-Host "Fin du script ..."
        exit
    }

####################  -- Check si nc.exe est dans le bon chemin -- #################### 
if( [System.IO.File]::Exists($path+"\nc.exe"))
{
     Write-Host "[+] nc.exe"
}
else{
        Write-Host "Erreur : Le programme nc.exe est inaccessible"
        Write-Host "Path :"$path"\nc.exe"
        exit
}

Write-Host "[+] Début du script"

## -- Date et nom du poste -- ##
$hostname = (hostname) | Out-String
$date = Get-Date -Format "dddd dd/MM/yyyy HH:mm"
(echo "##########" $hostname "##########" $date "##########" | .\nc.exe $ipServ $portServ -w $timer)
Write-Host "[+] Date et hostname"

## -- Récupération interfaces -- ##
$ipconfig = (ipconfig /all) | Out-String
(echo "########## Interfaces ##########" $ipconfig | .\nc.exe $ipServ $portServ -w $timer)
Write-Host "[+] Récupération des Interfaces"

## -- Récupération connexions -- ##
$netstat = (netstat) | Out-String
(echo "########## Connexions ##########" $netstat | .\nc.exe $ipServ $portServ -w $timer)
Write-Host "[+] Récupération des connexions"

## -- Récupération Historique de connexions -- ##
$netstatPlus = (netstat -abn) | Out-String
(echo "########## Historique de connexions ##########" $netstatPlus | .\nc.exe $ipServ $portServ -w $timer)
Write-Host "[+] Récupération Historique de connexions"

## -- Récupération des users connectés -- ##
$users = (query user) | Out-String
(echo "########## Sessions User ouvertes ##########" $users | .\nc.exe $ipServ $portServ -w $timer)
Write-Host "[+] Récupération des sessions utilisateur"

## -- Récupération liste de processus en execution -- ##
$tasklist = (tasklist) | Out-String
(echo "########## Processus en cours ##########" $tasklist | .\nc.exe $ipServ $portServ -w $timer)
Write-Host "[+] Récupération des processus en cours"

## -- Récupération des services en execution -- ##
$netstart = (net start) | Out-String
(echo "########## Services en cours ##########" $netstart | .\nc.exe $ipServ $portServ -w $timer)
Write-Host "[+] Récupération des services en cours"

## -- Récupération des fichiers ouverts -- ##
$openfiles = (openfiles) | Out-String
(echo "########## Fichiers ouverts ##########" $openfiles | .\nc.exe $ipServ $portServ -w $timer)
Write-Host "[+] Récupération des fichiers ouverts"

## -- Récupération des routes -- ##
$routes = (route print) | Out-String
(echo "########## Routes ##########" $routes | .\nc.exe $ipServ $portServ -w $timer)
Write-Host "[+] Récupération des routes"

## -- Récupération des volumes montés -- ##
$wmic = (wmic logicaldisk list brief) | Out-String
(echo "########## Volumes Montés ##########" $wmic | .\nc.exe $ipServ $portServ -w $timer)
Write-Host "[+] Récupération des volumes montés"

## -- Récupération des crontab -- ##
$crontab = (schtasks /query) | Out-String
(echo "########## Crontab ##########" $crontab | .\nc.exe $ipServ $portServ -w $timer)
Write-Host "[+] Récupération des crontab"

## -- Récupération des Drivers -- ##
$drivers = (DriverQuery) | Out-String
(echo "########## Drivers ##########" $drivers | .\nc.exe $ipServ $portServ -w $timer)
Write-Host "[+] Récupération des drivers installé"

## -- Récupération des volumes partagés -- ##
$netshare = (net share) | Out-String
(echo "########## Volumes partagés ##########"$netshare | .\nc.exe $ipServ $portServ -w $timer)
Write-Host "[+] Récupération des volumes partagés"

## -- Récupération de l'historique CMD -- ##
$history = ("doskey /history" | cmd) | Out-String
(echo "########## Historique CMD ##########" $history | .\nc.exe $ipServ $portServ -w $timer)
Write-Host "[+] Récupération Historique cmd"

## -- Récupération info Firewall -- ##
$firewallProfiles = (netsh advfirewall show allprofiles) | % { $_ -replace “%systemroot%”,$env:systemroot } | Out-String
(echo "########## Firewall Profiles ##########" $firewallProfiles | .\nc.exe $ipServ $portServ -w $timer)
Write-Host "[+] Récupération des profils Firewall"

#################### #################### #################### #################### #################### #################### #################### 
#################### #################### ####################         -- EventsLogs --         #################### #################### #################### 
#################### #################### #################### #################### #################### #################### #################### 
# Suite aux recommandations ANSSI
Write-Host "EventLogs ..."
(echo "########## EventLogs ##########"| .\nc.exe $ipServ $portServ -w $timer)

####################  -- Application Whitelisting -- #################### 
Write-Host "Application Whitelisting ..."
(echo "# Application Whitelisting #"| .\nc.exe $ipServ $portServ -w $timer)

# AppLocker Block
$Error.Clear() #clear error before each eventlogs

$AppBlock = Get-EventLog Application -Source .\AppLocker -InstanceId 8003,8004 -EntryType Error,Warning

if(!$Error){
    (echo "# AppLocker Block" $AppBlock | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] AppLocker Block"
}else{
    Write-Host "[-] AppLocker Block"
}

# Applocker Warning
$Error.Clear()
$AppWarning = Get-EventLog Application -Source .\AppLocker -InstanceId 8006,8007 -EntryType Error,Warning
if(!$Error){
    (echo "# AppLocker Warning" $AppWarning | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] AppLocker Warning"
}else{
    Write-Host "[-] AppLocker Warning"
}

# SRP Block
$Error.Clear()
$srpBlock = Get-EventLog -LogName Application -EntryType Warning -InstanceId 865,866,867,868,882 
if(!$Error){
    (echo "# SRP Block" $srpBlock | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] SRP Block"
}else{
    Write-Host "[-] SRP Block"
}

####################  -- Application crashes -- #################### 

# App Error
$Error.Clear()
$appError = Get-EventLog -LogName Application -EntryType Error -InstanceId 1000
if(!$Error){
    (echo "# Application Error" $appError | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Application Error"
}else{
    Write-Host "[-] Application Error"
}

# App hang
$Error.Clear()
$appHang = Get-EventLog -LogName Application -EntryType Error -InstanceId 1002
if(!$Error){
    (echo "# Application Hang" $appHang | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Application Hang"
}else{
    Write-Host "[-] Application Hang"
}

# WER
$Error.Clear()
$wer = Get-EventLog -LogName Application -EntryType Information -InstanceId 1001
if(!$Error){
    (echo "# WER" $wer | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] WER"
}else{
    Write-Host "[-] WER"
}

# EMET
$Error.Clear()
$emet = Get-EventLog -LogName Application -EntryType Warning,Error -InstanceId 1,2
if(!$Error){
    (echo "# EMET" $emet | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] EMET"
}else{
    Write-Host "[-] EMET"
}

# BSOD
$Error.Clear()
$bsod = Get-EventLog -LogName System -EntryType Error -InstanceId 1001
if(!$Error){
    (echo "# BSOD" $bsod | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] BSOD"
}else{
    Write-Host "[-] BSOD"
}

####################  -- System or Service Failure -- #################### 
Write-Host "System or Service Failure ..."
(echo "# System or Service Failure #"| .\nc.exe $ipServ $portServ -w $timer)

 #Windows services install
$Error.Clear()
$winServInstall = Get-EventLog System -EntryType Information -InstanceId 7045
if(!$Error){
    (echo "# Windows services install" $winServInstall | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Windows services install"
}else{
    Write-Host "[-] Windows services install"
}
 # windows services fails or crashes
$Error.Clear()
$winServFails = Get-EventLog System -EntryType Error -InstanceId 7022,7023,7024,7026,7031,7032,7034
if(!$Error){
    (echo "# Windows services fails or crashes" $winServFails | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Windows services fails or crashes"
}else{
    Write-Host "[-] Windows services fails or crashes"
}

####################  -- Windows Update Errors -- #################### 
Write-Host "Windows Update Errors ..."
(echo "# Windows Update Errors #"| .\nc.exe $ipServ $portServ -w $timer)

# Windows Update Failed
$Error.Clear()
$winUpdateFail = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-WindowsUpdateClient/Operational"; ID="20","24","25","31","34","35"}
if(!$Error){
    (echo "# Windows Update Failed" $winUpdateFail | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Windows Update Failed"
}else{
    Write-Host "[-] Windows Update Failed"
}

# Hotpatching failed
$Error.Clear()
$winHotFail = Get-WinEvent -FilterHashtable @{logname="Setup"; ID="1009"}
if(!$Error){
    (echo "# Hotpatching failed" $winHotFail | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Hotpatching failed"
}else{
    Write-Host "[-] Hotpatching failed"
}

#################### -- Windows Firewall -- #################### 
Write-Host "Windows Firewall ..."
(echo "# Windows Firewall #"| .\nc.exe $ipServ $portServ -w $timer)

#Firewall Rule Add 
$Error.Clear()
$fireRuleAdd = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"; ID="2004"} 
if(!$Error){
    (echo "# Firewall Rule Add " $fireRuleAdd | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Firewall Rule Add "
}else{
    Write-Host "[-] Firewall Rule Add "
}

#Firewall Rule Change
$Error.Clear()
$fireRuleChange = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"; ID="2005"} 
if(!$Error){
    (echo "# Firewall Rule Change " $fireRuleChange | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Firewall Rule Change "
}else{
    Write-Host "[-] Firewall Rule Change "
}

#Firewall Rule Deleted
$Error.Clear()
$fireRuleDel = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"; ID="2006","2033"}
if(!$Error){
    (echo "# Firewall Rule Deleted " $fireRuleDel | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Firewall Rule Deleted "
}else{
    Write-Host "[-] Firewall Rule Deleted "
}

#Firewall failed to load group policy
$Error.Clear()
$fireRuleLoadP = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"; ID="2009"}
if(!$Error){
    (echo "# Firewall failed to load group policy " $fireRuleLoadP | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Firewall failed to load group policy "
}else{
    Write-Host "[-] Firewall failed to load group policy "
}


####################  -- Clearing Event Logs -- #################### 
Write-Host "Clearing Event Logs ..."
(echo "# Clearing Event Logs #"| .\nc.exe $ipServ $portServ -w $timer)

# Event Logs was Cleared
$Error.Clear()
$eventClear = Get-EventLog System -InstanceId 104
if(!$Error){
    (echo "# Event Logs was Cleared " $eventClear | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Event Logs was Cleared "
}else{
    Write-Host "[-] Event Logs was Cleared "
}

# Audit Logs was Cleared
$Error.Clear()
$auditClear = Get-EventLog Security -InstanceId 1102
if(!$Error){
    (echo "# Audit Logs was Cleared " $auditClear | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Audit Logs was Cleared "
}else{
    Write-Host "[-] Audit Logs was Cleared "
}

#################### -- Software and service installation-- ####################
Write-Host "Software and service installation ..."
(echo "# Software and service installation #"| .\nc.exe $ipServ $portServ -w $timer) 

# New Windows Service
$Error.Clear()
$winServiceNew = Get-EventLog System -InstanceId 704,5
if(!$Error){
    (echo "# New Windows Service " $winServiceNew | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] New Windows Service "
}else{
    Write-Host "[-] New Windows Service "
}

# New Application
$Error.Clear()
$winNewApp = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Application-Experience/Program-Inventory"; ID="903","904"}
if(!$Error){
    (echo "# New Application " $winNewApp | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] New Application "
}else{
    Write-Host "[-] New Application "
}

# Updated Application
$Error.Clear()
$winUpApp =Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Application-Experience/Program-Inventory"; ID="905","906"}
if(!$Error){
    (echo "# Updated Application " $winUpApp | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Updated Application "
}else{
    Write-Host "[-] Updated Application "
}

# Removed Application
$Error.Clear()
$winRemvApp =Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Application-Experience/Program-Inventory"; ID="907","908"}
if(!$Error){
    (echo "# Removed Application " $winRemvApp | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Removed Application "
}else{
    Write-Host "[-] Removed Application "
}

# Summary of software activites
$Error.Clear()
$winSumSoft =Get-WinEvent -FilterHashtable @{logname="Setup"; ID="800"}
if(!$Error){
    (echo "# Summary of software activites " $winSumSoft | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Summary of software activites "
}else{
    Write-Host "[-] Summary of software activites "
}

# Update packages installed
$Error.Clear()
$winUpPack =Get-EventLog System -InstanceId 2
if(!$Error){
    (echo "# Update packages installed" $winUpPack | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Update packages installed "
}else{
    Write-Host "[-] Update packages installed "
}

# Windows update installed
$Error.Clear()
$winUpInstall =Get-EventLog System -InstanceId 19
if(!$Error){
    (echo "# Windows update installed" $winUpInstall | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Windows update installed "
}else{
    Write-Host "[-] Windows update installed "
}

####################  -- Account Usage -- #################### 
Write-Host "Account Usage ..."
(echo "# Account Usage #"| .\nc.exe $ipServ $portServ -w $timer) 

# Account Lockouts
# User Add to privileged Group
# Security-enabled local group Modification
# Successful user Account Login
# Failed user Account login
# Account Login with Explicit Credentials
# TGT Request
# TGS Request
# Sepial Privileges assigned to new logon

####################  -- Kernel driver signing -- #################### 
Write-Host "Kernel driver signing ..."
(echo "# Kernel driver signing #"| .\nc.exe $ipServ $portServ -w $timer)
# Detected an invalid image hash of a file
# Code integrity check

####################  -- Windows defender activities -- #################### 
Write-Host "Windows defender activities ..."
(echo "# Windows defender activities #"| .\nc.exe $ipServ $portServ -w $timer)
# Scan Failed
# Detected Malware
# Failed to update signatures
# Failed to update engine
# Reverting to last known good set of signatures
# Real-Time Protection failed
# Unexpected Error

####################  -- Scheduled task -- #################### 
Write-Host "Scheduled task ..."
(echo "# Scheduled task #"| .\nc.exe $ipServ $portServ -w $timer)
# Démarrage de la tâche
# Enregistrement de la tâche
# Lancement de la tâche 
# Fin de la tâche

