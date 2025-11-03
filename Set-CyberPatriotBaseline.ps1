<# 
.SYNOPSIS
  Applies a CyberPatriot-style local security baseline (PowerShell 5.1).
  Implements:
   - Maximum password age = 90 days
   - Account lockout threshold = 10 attempts
   - Limit blank passwords to console logon only = Enabled
   - Do not allow anonymous enumeration of SAM accounts and shares = Enabled
   - Firewall enabled on all profiles
   - Configure Automatic Updates = Enabled (auto download & schedule install)

  Also:
   - Backs up current Local Security Policy to INF
   - Applies hardened Security Options (INF via secedit)
   - Configures Advanced Audit Policy (auditpol)

.PARAMETERS
  -WorkingDir   : Folder for backup + template files (default: C:\CyberPatriotBaseline)
  -TemplateName : Output INF template name (default: cyberpatriot-baseline.inf)
  -NoFirewall   : Skip enabling firewall if specified

.NOTES
  - Run as Administrator.
  - PowerShell 5.1 compatible.
#>

[CmdletBinding()]
param(
    [string]$WorkingDir   = "C:\CyberPatriotBaseline",
    [string]$TemplateName = "cyberpatriot-baseline.inf",
    [switch]$NoFirewall
)

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script in an elevated PowerShell session (Run as Administrator)."
    }
}

function New-Folder($path) {
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
}

function Export-CurrentSecurityPolicy($path) {
    Write-Host "Backing up current Local Security Policy to:`n  $path" -ForegroundColor DarkGray
    secedit /export /cfg "$path" | Out-Null
    if (-not (Test-Path $path)) { throw "Failed to export current Local Security Policy to $path" }
}

function Write-BaselineInf($path) {
    # INF: implements points #7, #8, #9, #10 (SAM/shares), plus other safe defaults
    $inf = @"
[Unicode]
Unicode=yes
[Version]
signature=`"$CHICAGO$`"
Revision=1

[System Access]
; --- Password Policy ---
MinimumPasswordAge = 1
MaximumPasswordAge = 90       ; (#7) Max password age = 90 days
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
ClearTextPassword = 0

; --- Account Lockout Policy ---
LockoutBadCount = 10          ; (#8) Lockout threshold = 10 invalid attempts
ResetLockoutCount = 15
LockoutDuration = 15

; --- Guest account disabled ---
EnableGuestAccount = 0

[Event Audit]
; Legacy audit switches (Advanced Audit Policy is also set separately)
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
; (#9) Limit blank passwords to console logon only = Enabled
MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=4,1

; (#10) Do not allow anonymous enumeration of SAM accounts AND shares = Enabled
; Enable both RestrictAnonymous and RestrictAnonymousSAM for coverage
MACHINE\System\CurrentControlSet\Control\Lsa\restrictanonymous=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM=4,1

; --- Do not store LM hash value on next password change ---
MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1

; --- Don’t force network logons to Guest ---
MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest=4,0

; --- Require SMB signing (client & server) ---
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\EnableSecuritySignature=4,1

[Privilege Rights]
; Extend here if you want to set/deny specific user rights (Se* values).
"@

    $inf | Set-Content -Path $path -Encoding Unicode
}

function Apply-SecurityTemplate($infPath) {
    Write-Host "Applying security template:`n  $infPath" -ForegroundColor Cyan
    $dbPath = Join-Path $env:WINDIR "security\database\cpbaseline.sdb"
    secedit /configure /db "$dbPath" /cfg "$infPath" /areas SECURITYPOLICY | Out-Null
}

function Set-AdvancedAuditPolicy {
    Write-Host "Configuring Advanced Audit Policy (success & failure for core categories)..." -ForegroundColor Cyan
    $cats = @(
        "Account Logon","Account Management","DS Access","Logon/Logoff",
        "Object Access","Policy Change","Privilege Use","System","Detailed Tracking"
    )
    foreach ($c in $cats) {
        try { auditpol /set /category:"$c" /success:enable /failure:enable | Out-Null } catch {}
    }

    $subs = @(
        "Credential Validation","Computer Account Management","User Account Management",
        "Logon","Logoff","Account Lockout","Security Group Management",
        "Process Creation","Process Termination","Removable Storage"
    )
    foreach ($s in $subs) {
        try { auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null } catch {}
    }
}

function Enable-FirewallAllProfiles {
    Write-Host "Enabling Windows Firewall for Domain, Private, and Public profiles..." -ForegroundColor Cyan
    try { netsh advfirewall set allprofiles state on | Out-Null } catch {
        Write-Warning "Failed to enable firewall: $($_.Exception.Message)"
    }
}

function Ensure-AutomaticUpdates {
    <#
      Implements point #11:
       - Sets "Configure Automatic Updates" policy = Enabled (AUOptions=4)
       - Ensures Windows Update service is set to (Delayed) Automatic and running
       - Clears any "Turn off Automatic Updates" style blocks (NoAutoUpdate=0)
      Visible in gpedit.msc under:
        Computer Configuration -> Administrative Templates -> Windows Components -> Windows Update
    #>
    Write-Host "Configuring Windows Update policy: 'Configure Automatic Updates' = Enabled..." -ForegroundColor Cyan

    $wuAU = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    if (-not (Test-Path $wuAU)) { New-Item -Path $wuAU -Force | Out-Null }

    # Enable policy + set option "4" (Auto download and schedule install)
    New-ItemProperty -Path $wuAU -Name "NoAutoUpdate"         -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $wuAU -Name "AUOptions"            -Value 4 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $wuAU -Name "ScheduledInstallDay"  -Value 0 -PropertyType DWord -Force | Out-Null  # 0 = Every day
    New-ItemProperty -Path $wuAU -Name "ScheduledInstallTime" -Value 3 -PropertyType DWord -Force | Out-Null  # 3 = 3:00 AM

    # Make sure Windows Update service is enabled and running
    try {
        Set-Service -Name wuauserv -StartupType AutomaticDelayedStart
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Could not set/start Windows Update service (wuauserv): $($_.Exception.Message)"
    }
}

# ----------------- MAIN -----------------
try {
    Assert-Admin

    New-Folder -path $WorkingDir
    $backupInf   = Join-Path $WorkingDir "backup-$(Get-Date -Format yyyyMMdd-HHmmss).inf"
    $baselineInf = Join-Path $WorkingDir $TemplateName

    Export-CurrentSecurityPolicy -path $backupInf
    Write-BaselineInf -path $baselineInf
    Apply-SecurityTemplate -infPath $baselineInf
    Set-AdvancedAuditPolicy
    if (-not $NoFirewall) { Enable-FirewallAllProfiles }
    Ensure-AutomaticUpdates

    Write-Host "`nBaseline applied successfully." -ForegroundColor Green
    Write-Host "Backup of previous policy: $backupInf" -ForegroundColor DarkGray
    Write-Host "Template applied:          $baselineInf" -ForegroundColor DarkGray
    Write-Host "`nSome settings may require sign-out/restart to fully take effect." -ForegroundColor Yellow
}
catch {
    Write-Error $_.Exception.Message
    Write-Host "See secedit logs under %WINDIR%\security\logs for details." -ForegroundColor DarkGray
}
