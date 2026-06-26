param(
    [Parameter(Mandatory = $true)]
    [string]$SamplesFolder,

    [string]$HostSubmitScript = "C:\pdf_sandbox\shared\tools\host_submit_job.ps1",
    [string]$VBoxManage = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
    [string]$VmName = "win-sandbox",

    [string]$FilePattern = "*.pdf",
    [int]$ObserveSeconds = 90,
    [int]$DelayBetweenJobsSeconds = 5,

    [switch]$Recurse
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $SamplesFolder)) {
    throw "Samples folder not found: $SamplesFolder"
}

if (-not (Test-Path $HostSubmitScript)) {
    throw "host_submit_job.ps1 not found: $HostSubmitScript"
}

if (-not (Test-Path $VBoxManage)) {
    throw "VBoxManage not found: $VBoxManage"
}

$logDir = "C:\pdf_sandbox\shared\batch_logs"
New-Item -ItemType Directory -Force $logDir | Out-Null

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logPath = Join-Path $logDir "submit_batch_$timestamp.log"

function Write-Log {
    param([string]$Message)

    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Write-Host $line
    Add-Content -Path $logPath -Value $line
}

function Stop-VMIfRunning {
    try {
        $vmInfo = & $VBoxManage showvminfo $VmName --machinereadable
        $running = $vmInfo | Select-String 'VMState="running"'

        if ($running) {
            Write-Log "Powering off VM: $VmName"
            & $VBoxManage controlvm $VmName poweroff | Out-Null
            Start-Sleep -Seconds 6
        }
        else {
            Write-Log "VM already off: $VmName"
        }
    }
    catch {
        Write-Log "Warning while stopping VM: $($_.Exception.Message)"
    }
}

$files = Get-ChildItem -Path $SamplesFolder -Filter $FilePattern -File -Recurse:$Recurse.IsPresent |
    Sort-Object FullName

if (-not $files -or $files.Count -eq 0) {
    throw "No PDF files found in: $SamplesFolder"
}

Write-Log "Found $($files.Count) file(s)."
Write-Log "Samples folder: $SamplesFolder"
Write-Log "Using host submit script: $HostSubmitScript"

$results = @()

for ($i = 0; $i -lt $files.Count; $i++) {
    $file = $files[$i]
    $index = $i + 1

    Write-Log "========== [$index/$($files.Count)] START: $($file.FullName)"

    try {
        & powershell.exe -ExecutionPolicy Bypass -File $HostSubmitScript `
            -SamplePath $file.FullName `
            -ObserveSeconds $ObserveSeconds

        $results += [pscustomobject]@{
            File = $file.FullName
            Status = "Success"
        }

        Write-Log "========== [$index/$($files.Count)] SUCCESS: $($file.Name)"
    }
    catch {
        $results += [pscustomobject]@{
            File = $file.FullName
            Status = "Failed"
        }

        Write-Log "========== [$index/$($files.Count)] FAILED: $($file.Name)"
        Write-Log "Error: $($_.Exception.Message)"
    }

    Stop-VMIfRunning

    if ($index -lt $files.Count) {
        Start-Sleep -Seconds $DelayBetweenJobsSeconds
    }
}

$summaryPath = Join-Path $logDir "submit_batch_summary_$timestamp.csv"
$results | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8

$successCount = ($results | Where-Object { $_.Status -eq "Success" }).Count
$failedCount = ($results | Where-Object { $_.Status -eq "Failed" }).Count

Write-Log "Batch finished."
Write-Log "Success count: $successCount"
Write-Log "Failed count: $failedCount"
Write-Log "Log file: $logPath"
Write-Log "Summary file: $summaryPath"