
# Récupération d'informations sur un poste compromis/
# Windows vers Windows/Linux
# ATTENTION il est impératif de lancer une écoute Netcat sur un autre poste du même réseau : nc.exe -L -p 4444
#      -L : Lancer une écoute et ouvre une nouvelle connexion quand celle -ci est fermée
#      -p : précise le port d'écoute du server

# ----- Récupération Variables ----- #

# Encodage Français
[Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(437) 

$path = Read-Host "Chemin absolue vers les outils Unix : "
$ipServ = Read-Host "Entrez l'adresse ip du serveur Netcat : "
$portServ = Read-host "Entrez le port d'écoute du serveur Netcat : "
$timer = Read-host "Entrer le nombre de seconde entre chaque envoie au serveur Netcat : [défaut 1]"


# ----- Début du script ----- #

## -- Déplacement dans $path --##
try {cd $path }
catch {
        Write-Host "Erreur : Impossible d'atteindre le chemin vers les outils Unix"
        Write-Host "Fin du script ..."
        exit
    }

## -- Date et nom du poste -- ##
$hostname = (hostname) | Out-String
$date = Get-Date -Format "dddd dd/MM/yyyy HH:mm"
(echo "##########" $hostname "##########" $date "##########" | .\nc.exe $ipServ $portServ -w $timer)

## -- Récupération interfaces -- ##
$ipconfig = (ipconfig /all) | Out-String
(echo "########## Interfaces ##########" $ipconfig | .\nc.exe $ipServ $portServ -w $timer)

## -- Récupération connexions -- ##
$netstat = (netstat) | Out-String
(echo "########## Connexions ##########" $netstat | .\nc.exe $ipServ $portServ -w $timer)

## -- Récupération Historique de connexions -- ##
$netstatPlus = (netstat -abn) | Out-String
(echo "########## Historique de connexions ##########" $netstatPlus | .\nc.exe $ipServ $portServ -w $timer)

## -- Récupération des users connectés -- ##
$users = (query user) | Out-String
(echo "########## Sessions User ouvertes ##########" $users | .\nc.exe $ipServ $portServ -w $timer)

## -- Récupération liste de processus en execution -- ##
$tasklist = (tasklist) | Out-String
(echo "########## Processus en cours ##########" $tasklist | .\nc.exe $ipServ $portServ -w $timer)

## -- Récupération des services en execution -- ##
$netstart = (net start) | Out-String
(echo "########## Services en cours ##########" $netstart | .\nc.exe $ipServ $portServ -w $timer)

## -- Récupération des fichiers ouverts -- ##
$openfiles = (openfiles) | Out-String
(echo "########## Fichiers ouverts ##########" $openfiles | .\nc.exe $ipServ $portServ -w $timer)

## -- Récupération des routes -- ##
$routes = (route print) | Out-String
(echo "########## Routes ##########" $routes | .\nc.exe $ipServ $portServ -w $timer)

## -- Récupération des volumes montés -- ##
$wmic = (wmic logicaldisk list brief) | Out-String
(echo "########## Volumes Montés ##########" $wmic | .\nc.exe $ipServ $portServ -w $timer)

## -- Récupération des crontab -- ##
$crontab = (schtasks /query) | Out-String
(echo "########## Crontab ##########" $crontab | .\nc.exe $ipServ $portServ -w $timer)

## -- Récupération des Drivers -- ##
$drivers = (DriverQuery) | Out-String
(echo "########## Drivers ##########" $drivers | .\nc.exe $ipServ $portServ -w $timer)

## -- Récupération des volumes partagés -- ##
$netshare = (net share) | Out-String
(echo "########## Volumes partagés ##########"$netshare | .\nc.exe $ipServ $portServ -w $timer)

## -- Récupération de l'historique CMD -- ##
$history = ("doskey /history" | cmd) | Out-String
(echo "########## Historique CMD ##########" $history | .\nc.exe $ipServ $portServ -w $timer)

## -- Récupération info Firewall -- ##
$firewallProfiles = (netsh advfirewall show allprofiles) | % { $_ -replace “%systemroot%”,$env:systemroot } | Out-String
(echo "########## Firewall Profiles ##########" $firewallProfiles | .\nc.exe $ipServ $portServ -w $timer)

## -- Dump de la mémoire vive -- ##
