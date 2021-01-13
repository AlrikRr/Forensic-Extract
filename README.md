# Forensic-Extract V2.0

<a href="https://github.com/AlrikRr/Forensic-Extract/blob/master/LICENSE"><img alt="GitHub license" src="https://img.shields.io/github/license/AlrikRr/Forensic-Extract"></a>
<a href="https://github.com/AlrikRr/Forensic-Extract/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/AlrikRr/Forensic-Extract"></a>
<a href="https://github.com/AlrikRr/Forensic-Extract/network"><img alt="GitHub forks" src="https://img.shields.io/github/forks/AlrikRr/Forensic-Extract"></a>
<a href="https://github.com/AlrikRr/Forensic-Extract/issues"><img alt="GitHub issues" src="https://img.shields.io/github/issues/AlrikRr/Forensic-Extract"></a>


![Capture.PNG](Capture.PNG)


Forensic-Extract est un script PowerShell permettant avec un compte administrateur de récupérer différents logs / information sur un poste compromis.  

## :clipboard: **Pré-Requis** :
- Compte Administrateur
- PowerShell version 5
- Un endroit où stocker les données (USB, Disque partagé, etc.)


## :fire: **Fonctionnalités** :
- Test de vérification si le compte est bien administrateur
- Vérification de la version PowerShell installé
- Saisie Utilisateur du lieu où stocker les logs
- Création d'un dossier avec le nom du poste et la date actuelle.
- Récupération de journaux au format `evtx`
- Résupération des information du poste au format `.txt`
- Résultat final archivé au format `.zip`

##  :question: **Comment-ça marche ?**

L'utilisation est très simple, il suffit d'éxecuter le script avec un compte Administrateur.  
Le script va démarrer ses premières vérifications et vous demander où sauvegarder les logs.  

Si le chemin saisie par l'utiisateur existe, un dossier nommé avec le nom du poste et la date va être créer.  
Ce dossier va contenir les logs et va être ensuite compressé en archive `.zip`.  

En cas d'erreur importante (Mauvais Chemin, Pas assez de droits pour le compte, etc.) le script va s'arrêter.

Si une commandes de récupération d'un fichier logs ne fonctionne pas, une erreur va apparaître mais le script ne va pas s'arrêter.  

##  :floppy_disk: **Ce qui est récupéré** :

### Journaux Microsoft
-  Application 
- Security
- Microsoft-Windows-AppLocker/EXE and DLL
- Microsoft-Windows-AppLocker/MSI and Script
- System
- Microsoft-Windows-WindowsUpdateClient/Operational
- Setup
- Microsoft-Windows-WindowsFirewall With Advanced Security/Firewall
- Microsoft-Windows-Application-Experience/Program-Inventory
- Microsoft-Windows-CodeIntegrity/Operational
- Microsoft-Windows-WindowsDefender/Operational
- Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
- Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
- Microsoft-Windows-TaskScheduler/Operational
- Windows PowerShell
- Microsoft-Windows-PowerShell/Operational

### Informations du poste
- Nom du poste 
- la date
- les interfaces réseaux
- les ports de connexion 
- les processus associées aux ports de connexion
- la liste des processus en exécutions 
- les services en exécutions 
- les routes
- la liste des volumes montés
- les tâches programmées 
- les volumes samba
- historique des commandes
- les drivers 


##  :frowning: **La légende**
![legende.png](legende.png)
