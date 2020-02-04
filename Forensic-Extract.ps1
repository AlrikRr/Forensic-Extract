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

$path = Read-Host "Chemin absolu vers le programme nc.exe [C:\users\toto\Tools] : "
$ipServ = Read-Host "Entrez l'adresse IP du serveur Netcat : "
$portServ = Read-host "Entrez le port d'écoute du serveur Netcat [Défaut:4444] : "
$timer = Read-host "Entrer le nombre de secondes entre chaque envoie au serveur Netcat : [Défaut:2]"


# ----- Début du script ----- #

## -- Déplacement dans $path --##
try {cd $path }
catch {
        Write-Host "Erreur : Impossible d'atteindre le chemin vers les outils Unix"
        Write-Host "Fin du script ..."
        exit
    }

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

## -- EventsLogs -- ##
