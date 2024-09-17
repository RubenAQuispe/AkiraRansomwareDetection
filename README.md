
# Akira Ransomware Detection Script

This script helps detect Akira ransomware infections and suspicious activities on a system. It searches for encrypted files, recent suspicious executables, ransom notes, suspicious PowerShell logs, and potentially malicious scheduled tasks.

## Features:
- Searches for `.akira`, `.powerranges`, and `.akiranew` encrypted files.
- Identifies suspicious executables and scripts like `w.exe`, Mimikatz, LaZagne, and AdFind.
- Locates ransom notes (`README.txt`, `HELP.txt`, etc.).
- Searches for suspicious event logs (e.g., process creation, PowerShell executions).
- Logs all findings into a report.

## Requirements:
- Windows PowerShell.
- Administrator privileges to access event logs and system-wide scans.

## How to Run:
1. Download the script and run it in PowerShell with administrator privileges.
2. The scan results will be saved to `C:\temp` or another specified location.

## Usage:
```powershell
.\AkiraRansomwareDetection.ps1
```

## Output:
- **Akira_Encrypted_Files_Log.txt**: List of encrypted files found.
- **Potential_Malicious_Executables_Log.txt**: Recent suspicious executables detected.
- **Suspicious_Scripts_Log.txt**: Recently modified suspicious scripts.
- **Suspicious_EventLogs_Log.txt**: Detected suspicious PowerShell or security event logs.
- **Ransom_Note_Files_Log.txt**: Any ransom notes found.
- **Suspicious_ScheduledTasks_Log.txt**: Recently added or modified scheduled tasks.
