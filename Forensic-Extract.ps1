# Forensic-Extract v2.0

######### Légende ###
# - [!] Warning     #
# - [+] Ok          #
# - [-] Erreur      #
#####################

################################### Fonctionnalités ###############################
##                                                                                #
## - Vérification si le script est executé en administrateur                      #
##                                                                                #
## - Vérification de la version PowerShell : Version Optimale = 5 (5.1.16299.1146)#
##                                                                                #
## - Vérification de la saisie utilisateur (Antislash et si le chemin existe)                     #
##                                                                                #
## - Création d'un dossier comprenant le nom du poste et la date                  #
##                                                                                #
## - A la fin de l'extract, compression dans une archive ZIP                      #
##                                                                                # 
## - Supression du dossier d'origine après compression.                           #
##                                                                                #
###################################################################################

################# ---- Bannière ---- ##################
Write-Host "
  ______                       _             ______      _                  _   
 |  ____|                     (_)           |  ____|    | |                | |  
 | |__ ___  _ __ ___ _ __  ___ _  ___ ______| |__  __  _| |_ _ __ __ _  ___| |_ 
 |  __/ _ \| '__/ _ \ '_ \/ __| |/ __|______|  __| \ \/ / __| '__/ _` |/ __| __|
 | | | (_) | | |  __/ | | \__ \ | (__       | |____ >  <| |_| | | (_| | (__| |_ 
 |_|  \___/|_|  \___|_| |_|___/_|\___|      |______/_/\_\\__|_|  \__,_|\___|\__|                       
           )     )  
 (   (  ( /(  ( /(  
 )\  )\ )(_)) )\()) 
((_)((_|(_)  ((_)\  
\ \ / /|_  ) /  (_) 
 \ V /  / / | () |  
  \_/  /___(_)__/   
                   
                                                                                

                                                                                "
   
# N'affiche pas les erreurs dans le terminal
$ErrorActionPreference= 'silentlycontinue'



#######################################################################################
####################  -- Vérification des droits Administrateur -- ####################
#######################################################################################
           $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

        if ( $isAdmin -eq "True" ){
                Write-Host "[+] Administrateur" -ForegroundColor Green

        }else{
                Write-Host "[-] Administrateur" -ForegroundColor Red
                sleep(10)
                exit
        }
   
#######################################################################################     
####################  -- Vérification de la version PowerShell -- #####################
#######################################################################################
$version = $PsVersionTable.PSVersion.Major

if ( $version -eq "5" ){
    Write-Host "[+] Version PowerShell" -ForegroundColor Green
}else{
     Write-Host "[!] Version PowerShell : "$version  -ForegroundColor Yellow
     Write-Host "[!] Ce script utilise la version 5, vous risquez de rencontrer des problèmes de compatibilité" -ForegroundColor Yellow
}

#######################################################################################
####################  -- Saisie Utilisateur et variables  -- ##########################
#######################################################################################

Write-Host "[!] L'extraction va être stockée dans un dossier comportant le nom du poste et la date actuelle." -ForegroundColor Yellow
Write-Host "[!] Ce dossier sera ensuite compressé en archive ZIP et supprimé." -ForegroundColor Yellow
$pathSaisie = Read-Host "Chemin absolu où stocker l'extraction ? [Exemple = E:\ ] "

# Ajout de l'antislash s'il n'est pas présent
if ($pathSaisie[-1] -ne "\"){
    $pathSaisie = $pathSaisie+"\"
}

# Récupère le chemin de System32
$pathSystem32 = "c:\Windows\System32\"

# Séparateurs pour la mise en forme du fichier texte
$separateur1 = "################################# ---- "
$separateur2 = "---- #################################"

# Récupère le nom du poste et date
$hostname = $env:computername
$date_ddMMyyyy = Get-Date -Format "dd-MM-yyyy"

# Chemin complet avec ajout du dossier horodaté
$pathExtract = $pathSaisie + $hostname + "_" + $date_ddMMyyyy + "\"

# Horodatage + hostname sur le nom des fichiers
# format : [nomdufichier]_hostname_01/12/2020[extension]
$format_fichier = "_" + $hostname + "_" + $date_ddMMyyyy

# Création du nom de l'archive
$pathArchive = $pathSaisie+$hostname+ "_" +$date_ddMMyyyy+".zip"

# Point de départ archive
$pathArchivePoint = $pathExtract+"*"


###############################################################################################################
#################### #################### ----- Début du script ----- #################### ####################
############################################################################################################### 




#######################################################################################
####################  -- Check si le chemin saisie existe  -- #########################
####################################################################################### 

if ( Test-Path $pathSaisie){
         
        Write-Host "[+] Vérification du chemin saisie" -ForegroundColor Green
}
else{
        Write-Host "[-] Vérification du chemin saisie" -ForegroundColor Red
        sleep(10)
        exit
}

# Création du dossier où seront stoké les logs
try {
$test = New-Item -ItemType directory -Path $pathSaisie$hostname"_"$date_ddMMyyyy"\" | Out-String
 Write-Host "[+] Création du dossier : "$pathExtract -ForegroundColor Green
}catch{

}



#######################################################################################
####################  -- Déplacement dans System32 pour executer wevtutil -- ##########
####################################################################################### 
try {
        cd $pathSystem32 
        Write-Host "[!] Déplacement dans System32" -ForegroundColor Yellow
}
catch {
        Write-Host "[-] Déplacement dans System32" -ForegroundColor Red
         sleep(10)
        exit
}

#################################################################################################################
#################################  -- Récupération des logs ANSSI -- ############################################
#################################################################################################################

Write-Host "[!] Collect des Journaux" -ForegroundColor Yellow

#*********************************#
#           Application           #
#*********************************#
 try{
    .\wevtutil epl Application $pathExtract"Application"$format_fichier".evtx"
    Write-Host "[+] Collect : Application" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : Application" -ForegroundColor Red
 }

#*********************************#
#           Security              #
#*********************************#
 try{
    .\wevtutil epl Security $pathExtract"Security"$format_fichier".evtx"
    Write-Host "[+] Collect : Security" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : Security" -ForegroundColor Red
 }

#***************************************************************#
#           Microsoft-Windows-AppLocker/EXE and DLL             #
#***************************************************************#
 try{
    .\wevtutil epl "Microsoft-Windows-AppLocker/EXE and DLL" $pathExtract"AppLocker-EXE-and-DLL"$format_fichier".evtx"
    Write-Host "[+] Collect : Microsoft-Windows-AppLocker/EXE and DLL" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : Microsoft-Windows-AppLocker/EXE and DLL" -ForegroundColor Red
 }

#***************************************************************#
#            Microsoft-Windows-AppLocker/MSI and Script         #
#***************************************************************#
 try{
    .\wevtutil epl "Microsoft-Windows-AppLocker/MSI and Script" $pathExtract"AppLocker-MSI-and-Script"$format_fichier".evtx"
    Write-Host "[+] Collect : Microsoft-Windows-AppLocker/MSI and Script" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : Microsoft-Windows-AppLocker/MSI and Script" -ForegroundColor Red
 }

#*********************************#
#           System                #
#*********************************#
 try{
    .\wevtutil epl System $pathExtract"System"$format_fichier".evtx"
    Write-Host "[+] Collect : System" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : System" -ForegroundColor Red
 }

#***************************************************************#
#        Microsoft-Windows-WindowsUpdateClient/Operational      #
#***************************************************************#
 try{
    .\wevtutil epl "Microsoft-Windows-WindowsUpdateClient/Operational" $pathExtract"WindowsUpdateClient-Operational"$format_fichier".evtx"
    Write-Host "[+] Collect : Microsoft-Windows-WindowsUpdateClient/Operational" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : Microsoft-Windows-WindowsUpdateClient/Operational" -ForegroundColor Red
 }


#*********************#
#       Setup         #
#*********************#
 try{
    .\wevtutil epl Setup $pathExtract"Setup"$format_fichier".evtx"
    Write-Host "[+] Collect : Setup" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : Setup" -ForegroundColor Red
 }

#******************************************************************************#
#        Microsoft-Windows-WindowsFirewall With Advanced Security/Firewall     #
#******************************************************************************#
 try{
    .\wevtutil epl "Microsoft-Windows-WindowsFirewall With Advanced Security/Firewall" $pathExtract"WindowsFirewall"$format_fichier".evtx"
    Write-Host "[+] Collect : Microsoft-Windows-WindowsFirewall With Advanced Security/Firewall" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : Microsoft-Windows-WindowsFirewall With Advanced Security/Firewall" -ForegroundColor Red
 }

#******************************************************************************#
#        Microsoft-Windows-Application-Experience/Program-Inventory            #
#******************************************************************************#
 try{
    .\wevtutil epl "Microsoft-Windows-Application-Experience/Program-Inventory" $pathExtract"Application-Exeperience-Program-Inventory"$format_fichier".evtx"
    Write-Host "[+] Collect : Microsoft-Windows-Application-Experience/Program-Inventory" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : Microsoft-Windows-Application-Experience/Program-Inventory" -ForegroundColor Red
 }

#*************************************************************************#
#        Microsoft-Windows-CodeIntegrity/Operational                      #
#*************************************************************************#
 try{
    .\wevtutil epl "Microsoft-Windows-CodeIntegrity/Operational" $pathExtract"Windows-CodeIntegrity-Operational"$format_fichier".evtx"
    Write-Host "[+] Collect : Microsoft-Windows-CodeIntegrity/Operational" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : Microsoft-Windows-CodeIntegrity/Operational" -ForegroundColor Red
 }


#*****************************************************************#
#        Microsoft-Windows-WindowsDefender/Operational            #
#*****************************************************************#
 try{
    .\wevtutil epl "Microsoft-Windows-WindowsDefender/Operational" $pathExtract"WindowsDefender-Operational"$format_fichier".evtx"
    Write-Host "[+] Collect : Microsoft-Windows-WindowsDefender/Operational" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : Microsoft-Windows-WindowsDefender/Operational" -ForegroundColor Red
 }

#***********************************************************************************#
#        Microsoft-Windows-TerminalServices-LocalSessionManager/Operational         #
#***********************************************************************************#
 try{
    .\wevtutil epl "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" $pathExtract"TerminalServices-LocalSessionManager-Operational"$format_fichier".evtx"
    Write-Host "[+] Collect : Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" -ForegroundColor Red
 }

#***************************************************************************************#
#        Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational         #
#***************************************************************************************#
 try{
    .\wevtutil epl "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" $pathExtract"TerminalServices-RemoteConnectionManager-Operational"$format_fichier".evtx"
    Write-Host "[+] Collect : Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" -ForegroundColor Red
 }

#************************************************************#
#        Microsoft-Windows-TaskScheduler/Operational         #
#************************************************************#
 try{
    .\wevtutil epl "Microsoft-Windows-TaskScheduler/Operational" $pathExtract"Windows-TaskScheduler-Operational"$format_fichier".evtx"
    Write-Host "[+] Collect : Microsoft-Windows-TaskScheduler/Operational" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : Microsoft-Windows-TaskScheduler/Operational" -ForegroundColor Red
 }

#************************************#
#         Windows PowerShell         #
#************************************#
 try{
    .\wevtutil epl "Windows PowerShell" $pathExtract"Windows-PowerShell"$format_fichier".evtx"
    Write-Host "[+] Collect : Windows PowerShell" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : Windows PowerShell" -ForegroundColor Red
 }

#*********************************************************#
#        Microsoft-Windows-PowerShell/Operational         #
#*********************************************************#
 try{
    .\wevtutil epl "Microsoft-Windows-PowerShell/Operational" $pathExtract"Windows-PowerShell-Operational"$format_fichier".evtx"
    Write-Host "[+] Collect : Microsoft-Windows-PowerShell/Operational" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : Microsoft-Windows-PowerShell/Operational" -ForegroundColor Red
 }

#################################################################################################################
#################################  -- Récupération des information du poste -- ##################################
#################################################################################################################


#*********************************************************#
#       Déplacement dans le chemin où sont les journaux   #
#*********************************************************#
 try {
        cd $pathExtract 
        Write-Host "[!] Déplacement dans : "$pathExtract -ForegroundColor Yellow
}
catch {
        Write-Host "[-] Déplacement dans : "$pathExtract -ForegroundColor Red
        sleep(10)
        exit
}

Write-Host "[!] Collect des informations du poste" -ForegroundColor Yellow



#******************#
#        Date      #
#******************#
 try{
       $date = Get-Date -Format "dddd dd/MM/yyyy HH:mm"
       echo $separateur1"Date"$separateur2 | Out-File -Append $pathExtract"Logs"$format_fichier".txt"
       $date | Out-File -Append $pathExtract"Logs"$format_fichier".txt"
       Write-Host "[+] Collect : Date" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : Date" -ForegroundColor Red
 }


#**********************************#
#        Interfaces Réseau         #
#**********************************#
 try{
       $ipconfig = Get-NetIPAddress | Out-String
       echo $separateur1"Ipconfig"$separateur2 | Out-File -Append $pathExtract"Logs"$format_fichier".txt"
       $ipconfig | Out-File -Append $pathExtract"Logs"$format_fichier".txt"
       Write-Host "[+] Collect : Interfaces Réseau" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : Interfaces Réseau" -ForegroundColor Red
 }


#**************************************#
#        Netstat Port Connexio         #
#**************************************#
 try{
       $netstat = Get-NetTCPConnection | ft -auto
       echo $separateur1"Netstat Port Connexion"$separateur2 | Out-File -Append $pathExtract"Logs"$format_fichier".txt"
       $netstat | Out-File -Append $pathExtract"Logs"$format_fichier".txt"
       Write-Host "[+] Collect : Netstat Port Connexion" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : Netstat Port Connexion" -ForegroundColor Red
 }

#******************************************#
#       Netstat Port Connexion Processus   #
#******************************************#
 try{
       $processes = (Get-NetTCPConnection).OwningProcess
       $netstat = foreach ($process in $processes) {Get-Process -PID $process | select ID,ProcessName}
       echo $separateur1"Netstat Port Connexion Processus"$separateur2 | Out-File -Append $pathExtract"Logs"$format_fichier".txt"
       $netstat | Out-File -Append $pathExtract"Logs"$format_fichier".txt"
       Write-Host "[+] Collect : Netstat Port Connexion Processus" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : Netstat Port Connexion Processus" -ForegroundColor Red
 }

#*****************************************#
#       Processus en cours d'executions   #
#*****************************************#
 try{
       $process = Get-Process | ft -auto
       echo $separateur1"Processus en cours d'execution"$separateur2 | Out-File -Append $pathExtract"Logs"$format_fichier".txt"
       $process | Out-File -Append $pathExtract"Logs"$format_fichier".txt"
       Write-Host "[+] Collect : Processus en cours d'execution" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : Processus en cours d'execution" -ForegroundColor Red
 }

#****************************#
#       Liste des services   #
#****************************#
 try{
       $services = Get-Service | ft -auto
       echo $separateur1"Liste des services"$separateur2 | Out-File -Append $pathExtract"Logs"$format_fichier".txt"
       $services | Out-File -Append $pathExtract"Logs"$format_fichier".txt"
       Write-Host "[+] Collect : Liste des services" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : Liste des services" -ForegroundColor Red
 }

#*****************#
#       Routes    #
#*****************#
 try{
       $route = Get-NetRoute | ft -auto
       echo $separateur1"Routes"$separateur2 | Out-File -Append $pathExtract"Logs"$format_fichier".txt"
       $route | Out-File -Append $pathExtract"Logs"$format_fichier".txt"
       Write-Host "[+] Collect : Routes" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : Routes" -ForegroundColor Red
 }
 

#*************************#
#        Volumes montés   #
#*************************#
 try{
       $disk = Get-PSDrive | ft -auto
       echo $separateur1"Volumes montés"$separateur2 | Out-File -Append $pathExtract"Logs"$format_fichier".txt"
       $disk | Out-File -Append $pathExtract"Logs"$format_fichier".txt"
       Write-Host "[+] Collect : Volumes montés" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : Volumes montés" -ForegroundColor Red
 }


#****************************#
#       TaskScheduler        #
#****************************#
 try{
       $task = Get-ScheduledTask | ft -auto
       echo $separateur1"TaskScheduler"$separateur2 | Out-File -Append $pathExtract"Logs"$format_fichier".txt"
       $task | Out-File -Append $pathExtract"Logs"$format_fichier".txt"
       Write-Host "[+] Collect : TaskScheduler" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : TaskScheduler" -ForegroundColor Red
 }


#******************************#
#      Volumes partagés        #
#******************************#
 try{
       $share = Get-SmbShare | ft -auto 
       echo $separateur1"Volumes partagés"$separateur2 | Out-File -Append $pathExtract"Logs"$format_fichier".txt"
       $share | Out-File -Append $pathExtract"Logs"$format_fichier".txt"
       Write-Host "[+] Collect : Volumes partagés" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : Volumes partagés" -ForegroundColor Red
 }


#**************************************#
#      Historique des commandes        #
#**************************************#
 try{
       $history = Get-History | ft -auto 
       echo $separateur1"Historique des commandes"$separateur2 | Out-File -Append $pathExtract"Logs"$format_fichier".txt"
       $history | Out-File -Append $pathExtract"Logs"$format_fichier".txt"
       Write-Host "[+] Collect : Historique des commandes" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : Historique des commandes" -ForegroundColor Red
 }

#****************************#
#        Liste des Drivers   #
#****************************#
 try{
       $driver = Get-WindowsDriver –Online -All | ft -auto 
       echo $separateur1"Liste des Drivers"$separateur2 | Out-File -Append $pathExtract"Logs"$format_fichier".txt"
       $driver | Out-File -Append $pathExtract"Logs"$format_fichier".txt"
       Write-Host "[+] Collect : Liste des Drivers" -ForegroundColor Green
    }
 catch{
     Write-Host "[-] Collect : Liste des Drivers" -ForegroundColor Red
 }


#######################################################################################
####################  -- Compression en Archive ZIP  -- ###############################
####################################################################################### 



 try{

         $compress = @{
          Path = $pathArchivePoint
          CompressionLevel = "Fastest"
          DestinationPath = $pathArchive
        }
        Compress-Archive @compress
        Write-Host "[+] Archive : "$pathArchive -ForegroundColor Green
}catch{
           Write-Host "[-] Archive : "$pathArchive -ForegroundColor Red
}


#######################################################################################
####################  --Suppression ancien dossier   -- ###############################
####################################################################################### 

try{
        cd ../
        Remove-Item $pathExtract -Recurse -Force -Confirm:$false
        Write-Host "[+] Supression : "$pathExtract -ForegroundColor Green
}catch{
         Write-Host "[-] Supression : "$pathExtract -ForegroundColor Red
}


#######################################################################################
####################  --Fin du script -- ##############################################
####################################################################################### 
  Write-Host "[!] Fin du script" -ForegroundColor Yellow
