<#
.SYNOPSIS
    Runs an Atomic Red Team scenario on the Windows VM, logs UTC start/end and
    commands to execution_manifest.json, and exports Sysmon/Security/System .evtx logs.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScenarioName,

    [Parameter(Mandatory = $true)]
    [string[]]$AtomicTechniques,

    [string]$OutRoot = "C:\T12Lab\Traces",
    [switch]$ClearLogsBeforeRun
)

$ErrorActionPreference = "Stop"
$scenarioDir = Join-Path $OutRoot $ScenarioName
New-Item -ItemType Directory -Force -Path $scenarioDir | Out-Null

if ($ClearLogsBeforeRun) {
    wevtutil cl "Microsoft-Windows-Sysmon/Operational"
    wevtutil cl "Security"
    wevtutil cl "System"
}

$scenarioStartUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$testsLog = @()

foreach ($tech in $AtomicTechniques) {
    $tStart = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    Write-Host "[+] Running Atomic test: $tech"
    $cmdText = "Invoke-AtomicTest $tech -Confirm:`$false"
    $output = Invoke-AtomicTest $tech -Confirm:$false 2>&1 | Out-String
    $tEnd = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

    $testsLog += [ordered]@{
        technique_id = $tech
        command      = $cmdText
        start_utc    = $tStart
        end_utc      = $tEnd
        output_tail  = ($output -split "`n" | Select-Object -Last 10) -join "`n"
    }
}

$scenarioEndUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

# Export raw .evtx logs
$sysmonEvtx = Join-Path $scenarioDir "Sysmon.evtx"
$secEvtx    = Join-Path $scenarioDir "Security.evtx"
$sysEvtx    = Join-Path $scenarioDir "System.evtx"

wevtutil epl "Microsoft-Windows-Sysmon/Operational" $sysmonEvtx /ow:true
wevtutil epl "Security" $secEvtx /ow:true
wevtutil epl "System" $sysEvtx /ow:true

$manifest = [ordered]@{
    scenario_name = $ScenarioName
    host          = $env:COMPUTERNAME
    start_utc     = $scenarioStartUtc
    end_utc       = $scenarioEndUtc
    tests         = $testsLog
    evtx_files    = @("Sysmon.evtx", "Security.evtx", "System.evtx")
}

$manifestPath = Join-Path $scenarioDir "execution_manifest.json"
$manifest | ConvertTo-Json -Depth 6 | Set-Content -Path $manifestPath -Encoding UTF8
Write-Host "[+] Saved scenario trace and manifest to: $scenarioDir"
