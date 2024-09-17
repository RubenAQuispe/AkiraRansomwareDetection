# Akira Ransomware Detection Script

# Define the path to search (you can set it to C:\ or any other drive)
$searchPath = "C:\"

# Date range to search for recent files (e.g., last 7 days)
$daysAgo = (Get-Date).AddDays(-7)

# Log folder and file names
$logFolder = "C:\temp"
$akiraLogFile = "$logFolder\Akira_Encrypted_Files_Log.txt"
$exeLogFile = "$logFolder\Potential_Malicious_Executables_Log.txt"
$scriptsLogFile = "$logFolder\Suspicious_Scripts_Log.txt"
$eventLogsFile = "$logFolder\Suspicious_EventLogs_Log.txt"
$ransomNotesFile = "$logFolder\Ransom_Note_Files_Log.txt"
$tasksLogFile = "$logFolder\Suspicious_ScheduledTasks_Log.txt"

# Ensure log folder exists
if (-not (Test-Path $logFolder)) {
    New-Item -Path $logFolder -ItemType Directory
}

# Function to search for encrypted files
function Find-EncryptedFiles {
    Write-Output "Searching for encrypted files (.akira, .powerranges, .akiranew)..."
    if (Test-Path $akiraLogFile) { Remove-Item $akiraLogFile }

    $encryptedFiles = Get-ChildItem -Path $searchPath -Recurse -Filter "*.akira,*.powerranges,*.akiranew" -ErrorAction SilentlyContinue
    if ($encryptedFiles) {
        $encryptedFiles | ForEach-Object {
            $filePath = $_.FullName
            Write-Output $filePath
            Add-Content -Path $akiraLogFile -Value $filePath
        }
        Write-Output "Encrypted file list saved to $akiraLogFile."
    } else {
        Write-Output "No encrypted files found."
    }
}

# Function to search for recent executables (including w.exe, AdFind.exe, Advanced IP Scanner)
function Find-RecentExecutables {
    Write-Output "Searching for recent executables (including w.exe, AdFind.exe, Advanced IP Scanner)..."
    if (Test-Path $exeLogFile) { Remove-Item $exeLogFile }

    $executableExtensions = "*.exe", "*.dll", "*.bat", "*.cmd"
    $recentExecutables = Get-ChildItem -Path $searchPath -Recurse -Include $executableExtensions -ErrorAction SilentlyContinue | 
                        Where-Object { $_.Name -match "w\.exe|AdFind\.exe|ipscan|mimikatz|LaZagne" -or $_.LastWriteTime -ge $daysAgo -or $_.CreationTime -ge $daysAgo }

    if ($recentExecutables) {
        $recentExecutables | ForEach-Object {
            $filePath = $_.FullName
            Write-Output $filePath
            Add-Content -Path $exeLogFile -Value $filePath
        }
        Write-Output "Recent executable file list saved to $exeLogFile."
    } else {
        Write-Output "No recent executables found."
    }
}

# Function to search for suspicious scripts
function Find-SuspiciousScripts {
    Write-Output "Searching for suspicious scripts..."
    if (Test-Path $scriptsLogFile) { Remove-Item $scriptsLogFile }

    $scriptExtensions = "*.ps1", "*.vbs", "*.js"
    $recentScripts = Get-ChildItem -Path $searchPath -Recurse -Include $scriptExtensions -ErrorAction SilentlyContinue | 
                     Where-Object { $_.LastWriteTime -ge $daysAgo -or $_.CreationTime -ge $daysAgo }

    if ($recentScripts) {
        $recentScripts | ForEach-Object {
            $filePath = $_.FullName
            Write-Output $filePath
            Add-Content -Path $scriptsLogFile -Value $filePath
        }
        Write-Output "Suspicious script file list saved to $scriptsLogFile."
    } else {
        Write-Output "No suspicious scripts found."
    }
}

# Function to search for ransom notes
function Find-RansomNotes {
    Write-Output "Searching for ransom notes..."
    if (Test-Path $ransomNotesFile) { Remove-Item $ransomNotesFile }

    $ransomNoteNames = "README.txt", "HELP.txt", "*.akira.txt"
    $ransomNotes = Get-ChildItem -Path $searchPath -Recurse -Include $ransomNoteNames -ErrorAction SilentlyContinue

    if ($ransomNotes) {
        $ransomNotes | ForEach-Object {
            $filePath = $_.FullName
            Write-Output $filePath
            Add-Content -Path $ransomNotesFile -Value $filePath
        }
        Write-Output "Ransom note file list saved to $ransomNotesFile."
    } else {
        Write-Output "No ransom notes found."
    }
}

# Function to search for suspicious event logs
function Find-SuspiciousEventLogs {
    Write-Output "Searching for suspicious event logs..."
    if (Test-Path $eventLogsFile) { Remove-Item $eventLogsFile }

    $eventID = 4688  # Process creation event ID
    $suspiciousEvents = Get-WinEvent -FilterHashtable @{
        LogName = "Security"
        ID = $eventID
        StartTime = $daysAgo
    } | Where-Object { $_.Message -like "*Akira*" }

    if ($suspiciousEvents) {
        $suspiciousEvents | ForEach-Object {
            $eventMessage = $_.Message
            Write-Output $eventMessage
            Add-Content -Path $eventLogsFile -Value $eventMessage
        }
        Write-Output "Suspicious event logs saved to $eventLogsFile."
    } else {
        Write-Output "No suspicious event logs found."
    }
}

# Function to search for suspicious scheduled tasks
function Find-SuspiciousScheduledTasks {
    Write-Output "Searching for suspicious scheduled tasks..."
    if (Test-Path $tasksLogFile) { Remove-Item $tasksLogFile }

    $tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\\Microsoft*" }
    $recentTasks = $tasks | Where-Object { $_.Date -ge $daysAgo }

    if ($recentTasks) {
        $recentTasks | ForEach-Object {
            $taskName = $_.TaskName
            $taskPath = $_.TaskPath
            Write-Output "$taskPath\\$taskName"
            Add-Content -Path $tasksLogFile -Value "$taskPath\\$taskName"
        }
        Write-Output "Suspicious scheduled tasks saved to $tasksLogFile."
    } else {
        Write-Output "No suspicious scheduled tasks found."
    }
}

# Start the combined scan
Find-EncryptedFiles
Find-RecentExecutables
Find-SuspiciousScripts
Find-RansomNotes
Find-SuspiciousEventLogs
Find-SuspiciousScheduledTasks

Write-Output "Combined scan completed. Check logs in $logFolder for details."
