<#
.SYNOPSIS
    Minimal Windows VM lab setup for TEAM T12 DFIR Pipeline.
    Downloads only:
      1. Sysinternals Sysmon (official Microsoft download)
      2. SwiftOnSecurity sysmon-config (official GitHub)
      3. Invoke-AtomicRedTeam + atomics (official RedCanaryCo GitHub)
#>
[CmdletBinding()]
param(
    [string]$LabDir = "C:\T12Lab",
    [string]$SysmonConfigPath = ""
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $LabDir | Out-Null

# 1. Install Sysmon
$sysmonDir = Join-Path $LabDir "Sysmon"
$sysmonZip = Join-Path $LabDir "Sysmon.zip"
if (-not (Test-Path (Join-Path $sysmonDir "Sysmon64.exe"))) {
    Write-Host "[+] Downloading Sysinternals Sysmon..."
    Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $sysmonZip
    Expand-Archive -Path $sysmonZip -DestinationPath $sysmonDir -Force
    Remove-Item $sysmonZip -Force
}

# 2. Download SwiftOnSecurity Sysmon config (covers Events 1,3,8,10,11,12,13,14,22)
if (-not $SysmonConfigPath) {
    $SysmonConfigPath = Join-Path $LabDir "sysmonconfig-export.xml"
    Write-Host "[+] Downloading SwiftOnSecurity sysmon-config..."
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile $SysmonConfigPath
}

Write-Host "[+] Installing/updating Sysmon64 with $SysmonConfigPath..."
& (Join-Path $sysmonDir "Sysmon64.exe") -accepteula -i $SysmonConfigPath
if ($LASTEXITCODE -ne 0) {
    & (Join-Path $sysmonDir "Sysmon64.exe") -c $SysmonConfigPath
}

# 3. Install Invoke-AtomicRedTeam from official repo
Write-Host "[+] Installing Invoke-AtomicRedTeam..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (IWR "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1" -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force

Write-Host "[+] Lab setup complete."
