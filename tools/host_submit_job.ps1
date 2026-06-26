param(
    [Parameter(Mandatory = $true)]
    [string]$SamplePath,

    [string]$VmName = "win-sandbox",
    [string]$SnapshotName = "analysis-base-v2",
    [string]$VBoxManage = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",

    [int]$ObserveSeconds = 90,
    [int]$BootTimeoutSeconds = 180,
    [int]$ResultTimeoutSeconds = 420
)

$ErrorActionPreference = "Stop"

# Shared folder used by the local VM dynamic analysis pipeline.
# Update this path if your VirtualBox shared folder is configured differently.
$ShareRoot  = "C:\pdf_sandbox\shared"
$InputRoot  = Join-Path $ShareRoot "input"
$JobsRoot   = Join-Path $ShareRoot "jobs"
$OutputRoot = Join-Path $ShareRoot "output"
$ReadyFlag  = Join-Path $OutputRoot "guest.ready"

New-Item -ItemType Directory -Force $InputRoot, $JobsRoot, $OutputRoot | Out-Null

if (-not (Test-Path $SamplePath)) {
    throw "Sample not found: $SamplePath"
}

Remove-Item $ReadyFlag -ErrorAction SilentlyContinue

$vmInfo = & $VBoxManage showvminfo $VmName --machinereadable
$running = $vmInfo | Select-String 'VMState="running"'

if ($running) {
    Write-Host "Powering off running VM..."
    & $VBoxManage controlvm $VmName poweroff | Out-Null
    Start-Sleep -Seconds 6
}

Write-Host "Restoring snapshot: $SnapshotName"
& $VBoxManage snapshot $VmName restore $SnapshotName | Out-Null

Write-Host "Starting VM: $VmName"
& $VBoxManage startvm $VmName --type gui | Out-Null

$bootDeadline = (Get-Date).AddSeconds($BootTimeoutSeconds)
while ((Get-Date) -lt $bootDeadline) {
    if (Test-Path $ReadyFlag) { break }
    Start-Sleep -Seconds 3
}

if (-not (Test-Path $ReadyFlag)) {
    throw "Guest watcher did not become ready within timeout."
}

$jobId = "job_{0}_{1}" -f (Get-Date -Format "yyyyMMdd_HHmmss_fff"), ([guid]::NewGuid().ToString("N").Substring(0,8))
$sampleName = "{0}__{1}" -f $jobId, (Split-Path $SamplePath -Leaf)
$destSample = Join-Path $InputRoot $sampleName
Copy-Item $SamplePath $destSample -Force

$guestSamplePath = "\\VBoxSvr\shared\input\$sampleName"

$job = [ordered]@{
    job_id = $jobId
    sample_path = $guestSamplePath
    observe_seconds = $ObserveSeconds
    submitted_at = (Get-Date).ToString("o")
}

$jobFile = Join-Path $JobsRoot "$jobId.json"
$job | ConvertTo-Json -Depth 5 | Set-Content -Path $jobFile -Encoding UTF8

Write-Host "Job submitted: $jobId"

$outRoot = Join-Path $OutputRoot $jobId
$statusFile = Join-Path $outRoot "status.json"

$deadline = (Get-Date).AddSeconds($ResultTimeoutSeconds)
while ((Get-Date) -lt $deadline) {
    if (Test-Path $statusFile) { break }
    Start-Sleep -Seconds 5
}

if (-not (Test-Path $statusFile)) {
    throw "Timed out waiting for status.json for job: $jobId"
}

$status = Get-Content $statusFile -Raw | ConvertFrom-Json

$procmonPml = Join-Path $outRoot "procmon.pml"
$procmonCsv = Join-Path $outRoot "procmon.csv"
$sysmonXml  = Join-Path $outRoot "sysmon.xml"

$procmonEvidenceOk = (
    (Test-Path $procmonPml) -and ((Get-Item $procmonPml).Length -gt 0)
) -or (
    (Test-Path $procmonCsv) -and ((Get-Item $procmonCsv).Length -gt 0)
)

$sysmonEvidenceOk = (Test-Path $sysmonXml) -and ((Get-Item $sysmonXml).Length -gt 0)

if (($status.state -ne "completed") -or (-not $procmonEvidenceOk) -or (-not $sysmonEvidenceOk)) {
    throw ("Job failed validation. state={0}, procmonEvidenceOk={1}, sysmonEvidenceOk={2}" -f `
        $status.state, $procmonEvidenceOk, $sysmonEvidenceOk)
}

Write-Host "SUCCESS -> $outRoot"
Write-Host "Sample SHA256 -> $($status.sample_sha256)"
Write-Host "Sysmon events -> $($status.sysmon_event_count)"

$ShutdownScript = "C:\pdf_sandbox\shared\tools\shutdown_vm_after_job.ps1"

if (Test-Path $ShutdownScript) {
    Write-Host "[Host] Shutting down VM after dynamic job completion..."

    & powershell.exe `
        -NoLogo `
        -NoProfile `
        -NonInteractive `
        -ExecutionPolicy Bypass `
        -File $ShutdownScript `
        -VmName $VmName `
        -TimeoutSeconds 10 `
        -ForcePowerOffOnTimeout

    Write-Host "[Host] VM shutdown step completed. Exit code: $LASTEXITCODE"
}
else {
    Write-Host "[Host] Shutdown script not found: $ShutdownScript"
}