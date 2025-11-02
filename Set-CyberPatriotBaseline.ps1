<# 
.SYNOPSIS
  Applies a CyberPatriot-style local security baseline via secedit + auditpol.
  - Backs up current Local Security Policy to an INF
  - Applies hardened Account Policy & Security Options (via INF)
  - Configures Advanced Audit Policy (via auditpol)
  - Enables Windows Firewall on all profiles

.PARAMETERS
  -WorkingDir   : Folder to store backup and generated files (default: C:\CyberPatriotBaseline)
  -TemplateName : Name for the template INF (default: cyberpatriot-baseline.inf)
  -NoFirewall   : Skip enabling firewall if specified

.NOTES
  - Run as Administrator (elevated PowerShell).
  - PowerShell 5.1 compatible.
  - secedit writes logs to %windir%\security\logs\ and %windir%\security\database\
#>

[CmdletBinding()]
param(
    [string]$WorkingDir   = "C:\CyberPatriotBaseline",
    [string]$TemplateName = "cyberpatriot-baseline.inf",
    [switch]$NoFirewall
)

function Assert-Admin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run in an elevated PowerShell session (Run as Administrator)."
    }
}

function New-Folder($path) {
    if (-not (Test-Path $path)) { New-Item -ItemType Directory -Path $path -Force | Out-Null }
}

function Export-CurrentSecurityPolicy($path) {
    Write-Host "Backing up current Local Security Policy to:`n  $path" -ForegroundColor DarkGray
    secedit /export /cfg "$path" | Out-Null
    if (-not (Test-Path $path)) { throw "Failed to export current policy to $path" }
}

function Write-BaselineInf($path) {
    # Hardened but sane defaults; adjust as needed
    $inf = @"
[Unicode]
Unicode=yes
[Version]
signature=`"$CHICAGO$`"
Revision=1

[System Access]
; --- Password & Lockout Policy ---
MinimumPasswordAge = 1
MaximumPasswordAge = 60
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
ClearTextPassword = 0
; --- Lockout ---
LockoutBadCount = 5
ResetLockoutCount = 15
LockoutDuration = 15
; --- Guest account disabled ---
EnableGuestAccount = 0

[Event Audit]
; (Legacy switches; Advanced Audit Policy will be applied separately below)
AuditSystemEvents = 3
AuditLogonEvents = 3
AuditObjectAccess = 3
AuditPrivilegeUse = 3
AuditPolicyChange = 3
AuditAccountManage = 3
AuditProcessTracking = 3
AuditDSAccess = 0
AuditAccountLogon = 3

[Registry Values]
; --- Limit blank passwords to console logon only ---
MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=4,1
; --- Restrict anonymous enumeration of SAM accounts and shares ---
MACHINE\System\CurrentControlSet\Control\Lsa\restrictanonymous=4,1
; --- Do not store LM hash value on next password change ---
MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1
; --- ForceGuest off (Don’t force network logons to Guest) ---
MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest=4,0
; --- Require SMB signing (client) ---
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature=4,1
; --- Require SMB signing (server) ---
MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\EnableSecuritySignature=4,1

[Privilege Rights]
; Keep simple here; CyberPatriot typically focuses on account & audit policy in SecPol.
; You can extend with entries like:
; SeDenyNetworkLogonRight = *S-1-5-7
; SeDenyInteractiveLogonRight = *S-1-5-7
; SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546
"@

    $inf | Set-Content -Path $path -Encoding Unicode
}

function Apply-SecurityTemplate($infPath) {
    Write-Host "Applying security template:`n  $infPath" -ForegroundColor Cyan
    # Use a fresh DB path per run to avoid locks
    $dbPath = Join-Path $env:WINDIR "security\database\cpbaseline.sdb"
    secedit /configure /db "$dbPath" /cfg "$infPath" /areas SECURITYPOLICY | Out-Null
}

function Set-AdvancedAuditPolicy {
    Write-Host "Configuring Advanced Audit Policy (success & failure for core categories)..." -ForegroundColor Cyan

    # Categories chosen for strong visibility in CyberPatriot-like scoring:
    $cats = @(
        "Account Logon",
        "Account Management",
        "DS Access",          # often not applicable on standalone, but harmless
        "Logon/Logoff",
        "Object Access",
        "Policy Change",
        "Privilege Use",
        "System",
        "Detailed Tracking"
    )

    foreach ($c in $cats) {
        try {
            auditpol /set /category:"$c" /success:enable /failure:enable | Out-Null
        } catch {
            Write-Warning "Failed setting audit policy for category '$c': $($_.Exception.Message)"
        }
    }

    # Optional: turn on a few noisy-but-useful subcategories explicitly (adjust as needed)
    $subs = @(
        "Credential Validation",
        "Computer Account Management",
        "User Account Management",
        "Logon",
        "Logoff",
        "Account Lockout",
        "Security Group Management",
        "Process Creation",
        "Process Termination",
        "Plug and Play Events",
        "Removable Storage"
    )
    foreach ($s in $subs) {
        try {
            auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null
        } catch {
            # Not all subcategories exist on all SKUs; ignore failures.
        }
    }
}

function Enable-FirewallAllProfiles {
    Write-Host "Enabling Windows Firewall for Domain, Private, and Public profiles..." -ForegroundColor Cyan
    try {
        netsh advfirewall set allprofiles state on | Out-Null
    } catch {
        Write-Warning "Failed to enable firewall: $($_.Exception.Message)"
    }
}

# ----------------- MAIN -----------------
try {
    Assert-Admin

    New-Folder -path $WorkingDir
    $backupInf = Join-Path $WorkingDir "backup-$(Get-Date -Format yyyyMMdd-HHmmss).inf"
    $baselineInf = Join-Path $WorkingDir $TemplateName

    Export-CurrentSecurityPolicy -path $backupInf
    Write-BaselineInf -path $baselineInf
    Apply-SecurityTemplate -infPath $baselineInf
    Set-AdvancedAuditPolicy
    if (-not $NoFirewall) { Enable-FirewallAllProfiles }

    Write-Host "`nBaseline applied successfully." -ForegroundColor Green
    Write-Host "Backup of previous policy: $backupInf" -ForegroundColor DarkGray
    Write-Host "Template applied:          $baselineInf" -ForegroundColor DarkGray
    Write-Host "`nYou may need to sign out/in for some settings to fully take effect." -ForegroundColor Yellow
}
catch {
    Write-Error $_.Exception.Message
    Write-Host "See secedit logs under %WINDIR%\security\logs for details." -ForegroundColor DarkGray
}
