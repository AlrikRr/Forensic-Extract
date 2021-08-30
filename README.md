# Forensic-Extract V2.0

<a href="https://github.com/AlrikRr/Forensic-Extract/blob/master/LICENSE"><img alt="GitHub license" src="https://img.shields.io/github/license/AlrikRr/Forensic-Extract"></a>
<a href="https://github.com/AlrikRr/Forensic-Extract/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/AlrikRr/Forensic-Extract"></a>
<a href="https://github.com/AlrikRr/Forensic-Extract/network"><img alt="GitHub forks" src="https://img.shields.io/github/forks/AlrikRr/Forensic-Extract"></a>
<a href="https://github.com/AlrikRr/Forensic-Extract/issues"><img alt="GitHub issues" src="https://img.shields.io/github/issues/AlrikRr/Forensic-Extract"></a>


![Capture.PNG](Capture.PNG)

Forensic-Extract is a PowerShell script that allows you to retrieve windows logs and much information about a compromise computer.

## :clipboard: **Prerequisite** :
- Admin rights
- PowerShell version 5
- A place to store data (USB, shared drive, etc.)


## :fire: **Features** :
- Check if the account is an administrator
- Verification of the PowerShell version installed
- User input of the location where to store the logs
- Creation of a folder with the name of the station and the current date.
- Retrieve Windows logs in `evtx` format
- Retrieve information from the workstation in `.txt` format
- Final result archived in `.zip` format

##  :question: **How it works ?**

The usage is very simple, you just need to run the script with an **Administrator account**.  
The script will start its first checks and **ask you where to save the logs**.  

If the path entered by the user exists, a folder named with the name of the computer and the date will be created.  
This folder will store the logs and will then be **compressed into a `.zip` archive**.  

In case of an **important error** (Wrong Path, Not enough rights for the account, etc.) **the script will terminate**.  

If a command to retrieve a log file doesn't work, an error will be displayed but the script won't stop.  


##  :floppy_disk: **Retrive data** :

### Microsoft Events
- Application 
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

### Computer information
- Computer name 
- Current date
- Network interfaces
- Port status 
- Processus name associated with open port
- Processus name currently in use 
- Services currently in use
- Network routing
- Mounted device
- Cron jobs 
- SAMBA shares
- Doskey history
- Drivers


##  :frowning: **Legend**
![legende.png](legende.png)

- Information warning
- Success warning
- Failure warning
