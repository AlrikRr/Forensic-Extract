
# Récupération d'informations sur un poste compromis/
# Windows vers Windows/Linux
# ATTENTION il est impératif de lancer une écoute Netcat sur un autre poste du même réseau : nc.exe -L -p 4444
#      -L : Lancer une écoute et ouvre une nouvelle connexion quand celle -ci est fermée
#      -p : précise le port d'écoute du server

# ----- Récupération Variables ----- #

# Encodage Français
#[Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(437) 

Write-Host "
  ______                       _             ______      _                  _   
 |  ____|                     (_)           |  ____|    | |                | |  
 | |__ ___  _ __ ___ _ __  ___ _  ___ ______| |__  __  _| |_ _ __ __ _  ___| |_ 
 |  __/ _ \| '__/ _ \ '_ \/ __| |/ __|______|  __| \ \/ / __| '__/ _` |/ __| __|
 | | | (_) | | |  __/ | | \__ \ | (__       | |____ >  <| |_| | | (_| | (__| |_ 
 |_|  \___/|_|  \___|_| |_|___/_|\___|      |______/_/\_\\__|_|  \__,_|\___|\__|
                                                                                
                                                                                "

$ErrorActionPreference= 'silentlycontinue' #don't display errors
#$ErrorActionPreference='continue'
$path = Read-Host "Chemin absolu vers le programme nc.exe [C:\users\toto\Tools] : "
$ipServ = Read-Host "Entrez l'adresse IP du serveur Netcat : "
$portServ = Read-host "Entrez le port d'écoute du serveur Netcat [Défaut:4444] : "
Write-Host "Option pour Scheduled Task, veuillez saisir une range de date pour y récupérer toutes les tâches effectuées (Attention, cela peut augmenter considérablement la taille du rapport ! )"
Write-Host " Exemple : Récupérer les tâche du 05/02/2020(début) au 07/02/2020(fin)"
$datenow = Read-host "Date de début [jj/mm/yyyy]:"
$dateend = Read-host "Date de fin [jj/mm/yyyy]:"
#$timer = Read-host "Entrer le nombre de secondes entre chaque envoie au serveur Netcat : [Défaut:2]"
$timer = 3

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
$Error.Clear()
$accLock =Get-EventLog Security -InstanceId 4740
if(!$Error){
    (echo "# Account Lockouts" $accLock | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Account Lockouts "
}else{
    Write-Host "[-] Account Lockouts "
}

# User Add to privileged Group
$Error.Clear()
$userAddPriv =Get-EventLog Security -InstanceId 4732
if(!$Error){
    (echo "# User Add to privileged Group" $userAddPriv | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] User Add to privileged Group "
}else{
    Write-Host "[-] User Add to privileged Group "
}

# Security-enabled local group Modification
$Error.Clear()
$securityEnableLocal =Get-EventLog Security -InstanceId 4735
if(!$Error){
    (echo "# Security-enabled local group Modification" $securityEnableLocal | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Security-enabled local group Modification "
}else{
    Write-Host "[-] Security-enabled local group Modification "
}

# Successful user Account Login
$Error.Clear()
$successUserAccLog =Get-EventLog Security -InstanceId 4624
if(!$Error){
    (echo "# Successful user Account Login" $successUserAccLog | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Successful user Account Login "
}else{
    Write-Host "[-] Successful user Account Login "
}

# Failed user Account login
$Error.Clear()
$failUserAccLog =Get-EventLog Security -InstanceId 4625
if(!$Error){
    (echo "# Failed user Account login" $failUserAccLog | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Failed user Account login "
}else{
    Write-Host "[-] Failed user Account login "
}

# Account Login with Explicit Credentials
$Error.Clear()
$accLogExpli =Get-EventLog Security -InstanceId 4648
if(!$Error){
    (echo "# Account Login with Explicit Credentials" $accLogExpli | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Account Login with Explicit Credentials "
}else{
    Write-Host "[-] Account Login with Explicit Credentials "
}

# TGT Request
$Error.Clear()
$TGT =Get-EventLog Security -InstanceId 4768
if(!$Error){
    (echo "# TGT Request" $TGT | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] TGT Request "
}else{
    Write-Host "[-] TGT Request "
}

# TGS Request
$Error.Clear()
$TGS =Get-EventLog Security -InstanceId 4769
if(!$Error){
    (echo "# TGS Request" $TGS | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] TGS Request "
}else{
    Write-Host "[-] TGS Request "
}

# Special Privileges assigned to new logon
$Error.Clear()
$specialPriv =Get-EventLog Security -InstanceId 4672
if(!$Error){
    (echo "# Special Privileges assigned to new logon" $specialPriv | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Special Privileges assigned to new logon "
}else{
    Write-Host "[-] Special Privileges assigned to new logon "
}

####################  -- Kernel driver signing -- #################### 
Write-Host "Kernel driver signing ..."
(echo "# Kernel driver signing #"| .\nc.exe $ipServ $portServ -w $timer)

# Detected an invalid image hash of a file
$Error.Clear()
$detectedHash =Get-EventLog Security -InstanceId 5038
if(!$Error){
    (echo "# Detected an invalid image hash of a file" $detectedHash | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Detected an invalid image hash of a file "
}else{
    Write-Host "[-] Detected an invalid image hash of a file "
}

# Code integrity check 
$Error.Clear()
$codeCheck =Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-CodeIntegrity/Operational"; ID="3001","3002","3003","3004","3010","3023"}
if(!$Error){
    (echo "# Code integrity check " $codeCheck | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Code integrity check  "
}else{
    Write-Host "[-] Code integrity check  "
}

####################  -- Windows defender activities -- #################### 
Write-Host "Windows defender activities ..."
(echo "# Windows defender activities #"| .\nc.exe $ipServ $portServ -w $timer)

# Scan Failed   
$Error.Clear()
$scanFail =Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Windows Defender/Operational"; ID="1005"}
if(!$Error){
    (echo "# Scan Failed    " $scanFail | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Scan Failed     "
}else{
    Write-Host "[-] Scan Failed     "
}

# Detected Malware
$Error.Clear()
$detectMalware =Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Windows Defender/Operational"; ID="1006"}
if(!$Error){
    (echo "# Detected Malware    " $detectMalware | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Detected Malware  "
}else{
    Write-Host "[-] Detected Malware   "
}

# Failed to update signatures
$Error.Clear()
$failSign =Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Windows Defender/Operational"; ID="2001"}
if(!$Error){
    (echo "# Failed to update signatures " $failSign | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Failed to update signatures "
}else{
    Write-Host "[-] Failed to update signatures "
}

# Failed to update engine
$Error.Clear()
$failUp =Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Windows Defender/Operational"; ID="2003"}
if(!$Error){
    (echo "# Failed to update engine " $failUp | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Failed to update engine "
}else{
    Write-Host "[-] Failed to update engine "
}

# Reverting to last known good set of signatures
$Error.Clear()
$revertingSign =Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Windows Defender/Operational"; ID="2004"}
if(!$Error){
    (echo "# Reverting to last known good set of signatures " $revertingSign | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Reverting to last known good set of signatures "
}else{
    Write-Host "[-] Reverting to last known good set of signatures "
}

# Real-Time Protection failed
$Error.Clear()
$realTimeFail =Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Windows Defender/Operational"; ID="3002"}
if(!$Error){
    (echo "# Real-Time Protection failed " $realTimeFail | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Real-Time Protection failed "
}else{
    Write-Host "[-] Real-Time Protection failed "
}

# Unexpected Error
$Error.Clear()
$unexpectedError =Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Windows Defender/Operational"; ID="5008"}
if(!$Error){
    (echo "# Unexpected Error " $unexpectedError | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Unexpected Error "
}else{
    Write-Host "[-] Unexpected Error "
}

####################  -- Remote Desktop Logon Detection -- #################### 
Write-Host " Remote Desktop Logon Detection ..."
(echo "#  Remote Desktop Logon Detection #"| .\nc.exe $ipServ $portServ -w $timer)

# Sucessful User Account Login   (LogonType=10)
$Error.Clear()
$successUserAccLogType =Get-EventLog Security -InstanceId 4624
if(!$Error){
    (echo "# Sucessful User Account Login   (LogonType=10) " $successUserAccLogType | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Sucessful User Account Login   (LogonType=10) "
}else{
    Write-Host "[-] Sucessful User Account Login   (LogonType=10) "
}

# Sucessful User Account Logoff (LogonType=10)
$Error.Clear()
$successUserAccLogOffType =Get-EventLog Security -InstanceId 4634
if(!$Error){
    (echo "#Sucessful User Account Logoff (LogonType=10) " $successUserAccLogOffType | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Sucessful User Account Logoff (LogonType=10) "
}else{
    Write-Host "[-] Sucessful User Account Logoff (LogonType=10) "
}

# RDP: Ouverture de session réussie
$Error.Clear()
$RDPopenOK =Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"; ID="21"}
if(!$Error){
    (echo "#RDP: Ouverture de session réussie " $RDPopenOK | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] RDP: Ouverture de session réussie "
}else{
    Write-Host "[-] RDP: Ouverture de session réussie "
}

# RDP: Réouverture de session réussie
$Error.Clear()
$RDPreopenOK =Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"; ID="25"}
if(!$Error){
    (echo "#RDP: Réouverture de session réussie " $RDPreopenOK | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] RDP: Réouverture de session réussie "
}else{
    Write-Host "[-] RDP: Réouverture de session réussie "
}

# RDP: Initialisation de Plugin
$Error.Clear()
$RDPinitPlugin=Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"; ID="32"}
if(!$Error){
    (echo "#RDP: Initialisation de Plugin " $RDPinitPlugin | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] RDP: Initialisation de Plugin "
}else{
    Write-Host "[-] RDP: Initialisation de Plugin "
}

# RDP: Démarrage de session
$Error.Clear()
$RDPstartSession=Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"; ID="57","58"}
if(!$Error){
    (echo "#RDP: Démarrage de session " $RDPstartSession | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] RDP: Démarrage de session "
}else{
    Write-Host "[-] RDP: Démarrage de session "
}

# RDP: Ouverture de connexion
$Error.Clear()
$RDPopenCo=Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"; ID="261"}
if(!$Error){
    (echo "#RDP: Ouverture de connexion " $RDPopenCo | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] RDP: Ouverture de connexion "
}else{
    Write-Host "[-] RDP: Ouverture de connexion "
}

# RDP: Authentification Réussie/Echouée
$Error.Clear()
$RDPauthOKfail=Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"; ID="1148","1149"}
if(!$Error){
    (echo "# RDP: Authentification Réussie/Echouée " $RDPauthOKfail | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+]  RDP: Authentification Réussie/Echouée "
}else{
    Write-Host "[-]  RDP: Authentification Réussie/Echouée "
}

# RDP: Session Initiée
$Error.Clear()
$RDPsessionInit=Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"; ID="1146"}
if(!$Error){
    (echo "# RDP: Session Initiée " $RDPsessionInit | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+]  RDP: Session Initiée "
}else{
    Write-Host "[-]  RDP: Session Initiée "
}


####################  -- Scheduled task -- #################### 
Write-Host "Scheduled task ..."
(echo "# Scheduled task #"| .\nc.exe $ipServ $portServ -w $timer)
#$datenow=Get-Date -Format "dd/MM/yyyy"

# Démarrage de la tâche
$Error.Clear()
$STstartTask=Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-TaskScheduler/Operational"; ID="100"; StartTime=$datenow;EndTime=$dateend}
if(!$Error){
    (echo "#Démarrage de la tâche " $STstartTask | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+]  Démarrage de la tâche "
}else{
    Write-Host "[-]  Démarrage de la tâche "
}

# Enregistrement de la tâche
$Error.Clear()
$STsaveTask=Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-TaskScheduler/Operational"; ID="106"}
if(!$Error){
    (echo "#Enregistrement de la tâche " $STsaveTask | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+]  Enregistrement de la tâche "
}else{
    Write-Host "[-]  Enregistrement de la tâche "
}

# Lancement de la tâche 
$Error.Clear()
$STlaunchTask=Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-TaskScheduler/Operational"; ID="107","108","109","110","129"; StartTime=$datenow;EndTime=$dateend}
if(!$Error){
    (echo "#Lancement de la tâche " $STlaunchTask | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+]  Lancement de la tâche "
}else{
    Write-Host "[-]  Lancement de la tâche "
}

# Fin de la tâche
$Error.Clear()
$STendTask=Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-TaskScheduler/Operational"; ID="102"; StartTime=$datenow;EndTime=$dateend}
if(!$Error){
    (echo "#Fin de la tâche " $STendTask | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+]  Fin de la tâche "
}else{
    Write-Host "[-]  Fin de la tâche "
}

####################  -- Process creation -- #################### 
Write-Host "Process creation ..."
(echo "# Process creation #"| .\nc.exe $ipServ $portServ -w $timer)

# Audit process Creation
$Error.Clear()
$AuditProcessCreate=Get-EventLog Security -InstanceId 4688
if(!$Error){
    (echo "#Audit process Creation " $AuditProcessCreate | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+]  Audit process Creation "
}else{
    Write-Host "[-]  Audit process Creation "
}

# Audit process Terminaison
$Error.Clear()
$AuditProcessTerm=Get-EventLog Security -InstanceId 4689
if(!$Error){
    (echo "#Audit process Terminaison " $AuditProcessTerm | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+]  Audit process Terminaison "
}else{
    Write-Host "[-]  Audit process Terminaison "
}

####################  -- PowerShell -- #################### 
Write-Host "PowerShell ..."
(echo "# PowerShell #"| .\nc.exe $ipServ $portServ -w $timer)

# Execution de commande
$Error.Clear()
$PSexecCommand=Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-PowerShell/Operational";ID="4103"}
if(!$Error){
    (echo "#Execution de commande " $PSexecCommand | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+]  Execution de commande "
}else{
    Write-Host "[-]  Execution de commande "
}

# Script Block Logging
$Error.Clear()
$PSblockLog=Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-PowerShell/Operational";ID="4104"}
if(!$Error){
    (echo "#Script Block Logging " $PSblockLog | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+] Script Block Logging "
}else{
    Write-Host "[-] Script Block Logging "
}

# Pipe Line Execution détail
$Error.Clear()
$PSpipeLine=Get-WinEvent -FilterHashtable @{logname="Windows PowerShell";ID="800"}
if(!$Error){
    (echo "# Pipe Line Execution détail " $PSpipeLine | .\nc.exe $ipServ $portServ -w $timer)
    Write-Host "[+]  Pipe Line Execution détail "
}else{
    Write-Host "[-]  Pipe Line Execution détail "
}

 Write-Host "#### Fin du script #### "
