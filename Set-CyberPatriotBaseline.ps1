<# 
Set-CyberPatriotBaseline.ps1
--------------------------------
Applies a CyberPatriot-style local security baseline and verifies results.

Implements:
 - Password policy: Max age 90d, Min length 14, History 24, Complexity on
 - Lockout: threshold 10, window 15, duration 15
 - Limit blank passwords to console only = Enabled
 - Block anonymous enumeration of SAM accounts and shares = Enabled
 - Advanced Audit Policy (success/failure common categories)
 - Windows Firewall ON (all profiles)
 - Configure Automatic Updates = Enabled (AUOptions=4)

Safety/Resilience:
 - Backs up current Local Security Policy (INF)
 - Applies INF via secedit with timeout and clean DB/log
 - Fallback setters: net accounts + registry
 - Verification report at end

PARAMS:
 -WorkingDir            (default C:\CyberPatriotBaseline)
 -TemplateName          (default cyberpatriot-baseline.inf)
 -NoFirewall            (switch) skip enabling firewall
 -SkipSecedit           (switch) bypass secedit entirely
 -SeceditTimeoutSec     (int, default 120) kill secedit if it hangs

PowerShell 5.1 compatible. Run as Administrator.
#>

[CmdletBinding()]
param(
  [string]$WorkingDir   = "C:\CyberPatriotBaseline",
  [string]$TemplateName = "cyberpatriot-baseline.inf",
  [switch]$NoFirewall,
  [switch]$SkipSecedit,
  [int]$SeceditTimeoutSec = 120
)

# ------------------- helpers -------------------
function Assert-Admin {
  $id=[Security.Principal.WindowsIdentity]::GetCurrent()
  $p =New-Object Security.Principal.WindowsPrincipal($id)
  if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw "Run this script in an elevated PowerShell session (Run as Administrator)."
  }
}
function New-Folder($p){ if(-not (Test-Path $p)){ New-Item -ItemType Directory -Path $p -Force | Out-Null } }

function Export-CurrentSecurityPolicy($path){
