param(
    [Parameter(Mandatory=$true)]
    [string]$VmName,

    [string]$VBoxManagePath = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",

    [int]$TimeoutSeconds = 90,

    [switch]$ForcePowerOffOnTimeout
)

$ErrorActionPreference = "Continue"

function Write-Log {
    param([string]$Message)
    Write-Host "[VM Shutdown] $Message"
}

if (-not (Test-Path $VBoxManagePath)) {
    Write-Log "VBoxManage not found at: $VBoxManagePath"
    exit 1
}

Write-Log "Checking VM state: $VmName"

$info = & $VBoxManagePath showvminfo $VmName --machinereadable 2>&1
$infoText = ($info | Out-String).ToLower()

if ($LASTEXITCODE -ne 0) {
    Write-Log "Could not read VM info."
    Write-Log $infoText
    exit 1
}

if ($infoText -match 'vmstate="poweroff"') {
    Write-Log "VM is already powered off."
    exit 0
}

if ($infoText -match 'vmstate="aborted"') {
    Write-Log "VM is already aborted/off."
    exit 0
}

Write-Log "Sending ACPI shutdown signal..."

& $VBoxManagePath controlvm $VmName acpipowerbutton 2>&1 | Out-Null

if ($LASTEXITCODE -ne 0) {
    Write-Log "ACPI shutdown command failed."
    exit 1
}

$start = Get-Date

while ($true) {
    Start-Sleep -Seconds 2

    $elapsed = ((Get-Date) - $start).TotalSeconds

    $stateInfo = & $VBoxManagePath showvminfo $VmName --machinereadable 2>&1
    $stateText = ($stateInfo | Out-String).ToLower()

    if ($stateText -match 'vmstate="poweroff"') {
        Write-Log "VM powered off successfully."
        exit 0
    }

    if ($stateText -match 'vmstate="aborted"') {
        Write-Log "VM is aborted/off."
        exit 0
    }

    if ($elapsed -ge $TimeoutSeconds) {
        Write-Log "VM did not power off within timeout."

        if ($ForcePowerOffOnTimeout) {
            Write-Log "Forcing VM power off..."

            & $VBoxManagePath controlvm $VmName poweroff 2>&1 | Out-Null

            if ($LASTEXITCODE -eq 0) {
                Write-Log "VM was forced powered off successfully."
                exit 0
            }
            else {
                Write-Log "Forced power off failed."
                exit 2
            }
        }
        else {
            Write-Log "Leaving it running because force power off was not enabled."
            exit 2
        }
    }
}