# windows
Windows repository with scripts and stuff for windows

## Forensic-Extract.ps1

This script will extract some information about your computer. You need to Init a netcat listener on another computer.
You also need the **nc.exe** from **UnixTools**.

Extract:
- Date and hostname
- Network Interfaces
- connections
- connections history
- users session
- ps list
- services list
- open files
- mounted disk
- routes
- crontab
- drivers
- shared disk
- cmd history
- firewall profiles
- EventLogs (based on ANSSI recommendation)

## Forsensic-Extract.ps1

Improved version, runs locally without netcat
