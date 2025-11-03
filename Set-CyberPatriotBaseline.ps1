<# 
Applies a CyberPatriot-style local security baseline and verifies results.
- Password policy: Max age 90d, Min length 14, History 24, Complexity on
- Lockout: threshold 10, window 15, duration 15
- Limit blank passwords to console only = Enabled
- Block anonymous enumeration of SAM accounts and shares = Enabled
- Advanced Audit Policy (success/failure common cats)
- Windows Firewall ON (all profiles)
- Configure Automatic Updates = Enabled (AUOptions=4)
- Backup current SecPol, apply INF via secedit (/overwrite), plus net accounts fallback
- Verification summary at the end

Run elevated (PowerShell 5.1+)
#>

[CmdletBinding()]
param(
  [string]$WorkingDir   = "C:\CyberPatriotBaseline",
  [string]$TemplateName = "cyberpatriot-baseline.inf",
  [switch]$NoFirewall
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
  Write-Host "Backup Local Security Policy -> $path" -ForegroundColor DarkGray
  secedit /export /cfg "$path" | Out-Null
  if(-not (Test-Path $path)){ throw "Failed to export policy to $path" }
}

function Write-BaselineInf($path){
  $inf=@"
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1

[System Access]
; Password Policy
MinimumPasswordAge = 1
MaximumPasswordAge = 90
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
ClearTextPassword = 0

; Account Lockout Policy
LockoutBadCount = 10
ResetLockoutCount = 15
LockoutDuration = 15

; Guest disabled
EnableGuestAccount = 0

[Event Audit]
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
; Limit blank passwords to console only
MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=4,1

; Block anonymous enumeration of SAM accounts and shares
MACHINE\System\CurrentControlSet\Control\Lsa\restrictanonymous=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM=4,1

; Don't store LM hash
MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1

; Don't force network logons to Guest
MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest=4,0

; Require SMB signing (client/server)
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\EnableSecuritySignature=4,1
"@
  $inf | Set-Content -Path $path -Encoding Unicode
}

function Apply-SeceditTemplate($infPath){
  Write-Host "Applying INF via secedit..." -ForegroundColor Cyan
  $db = Join-Path $env:WINDIR "security\database\cpbaseline_$(Get-Date -Format yyyyMMddHHmmss).sdb"
  $log= Join-Path $env:WINDIR "security\logs\cpbaseline_$(Get-Date -Format yyyyMMddHHmmss).log"
  # /overwrite to avoid DB reuse, /areas SECURITYPOLICY, and a dedicated log
  secedit /configure /db "$db" /cfg "$infPath" /areas SECURITYPOLICY /overwrite /log "$log" | Out-Null
  Write-Host "secedit DB:  $db" -ForegroundColor DarkGray
  Write-Host "secedit log: $log" -ForegroundColor DarkGray
}

function Fallback-AccountPolicies {
  # Apply password/lockout with net accounts to catch cases secedit skipped or GPOs aren’t in play
  Write-Host "Applying password/lockout policy via 'net accounts' (fallback)..." -ForegroundColor Cyan
  & net accounts /maxpwage:90 /minpwlen:14 /uniquepw:24 | Out-Null
  & net accounts /lockoutthreshold:10 /lockoutduration:15 /lockoutwindow:15 | Out-Null
}

function Set-AdvancedAuditPolicy {
  Write-Host "Configuring Advanced Audit Policy..." -ForegroundColor Cyan
  $cats=@("Account Logon","Account Management","DS Access","Logon/Logoff","Object Access","Policy Change","Privilege Use","System","Detailed Tracking")
  foreach($c in $cats){ try{ auditpol /set /category:"$c" /success:enable /failure:enable | Out-Null }catch{} }
  $subs=@("Credential Validation","Computer Account Management","User Account Management","Logon","Logoff","Account Lockout","Security Group Management","Process Creation","Process Termination","Removable Storage")
  foreach($s in $subs){ try{ auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null }catch{} }
}

function Enable-FirewallAllProfiles {
  if($PSBoundParameters.ContainsKey('NoFirewall')){ return }
  Write-Host "Enabling Windows Firewall (all profiles)..." -ForegroundColor Cyan
  try{ netsh advfirewall set allprofiles state on | Out-Null }catch{ Write-Warning "Firewall enable failed: $($_.Exception.Message)" }
}

function Ensure-AutomaticUpdates {
  # Configure Automatic Updates = Enabled (AUOptions=4), set service to Automatic (+delayed) and start it
  Write-Host "Configuring Windows Update policy (Configure Automatic Updates = Enabled)..." -ForegroundColor Cyan
  $wuAU = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
  if(-not (Test-Path $wuAU)){ New-Item -Path $wuAU -Force | Out-Null }
  New-ItemProperty -Path $wuAU -Name "NoAutoUpdate" -Value 0 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $wuAU -Name "AUOptions" -Value 4 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $wuAU -Name "ScheduledInstallDay"  -Value 0 -PropertyType DWord -Force | Out-Null  # every day
  New-ItemProperty -Path $wuAU -Name "ScheduledInstallTime" -Value 3 -PropertyType DWord -Force | Out-Null  # 3 AM

  $svc = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
  if($null -eq $svc){ Write-Warning "wuauserv not found; skipping service steps."; return }
  try{ Set-Service -Name wuauserv -StartupType Automatic }catch{ Write-Warning "wuauserv startup type: $($_.Exception.Message)" }
  try{ Start-Service -Name wuauserv -ErrorAction SilentlyContinue }catch{ Write-Warning "wuauserv start: $($_.Exception.Message)" }
  try{ & sc.exe config wuauserv start= delayed-auto | Out-Null }catch{
    try{ New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv" -Name "DelayedAutoStart" -Value 1 -PropertyType DWord -Force | Out-Null }catch{}
  }
}

function Write-RegistryOptionsDirect {
  # Double-ensure registry-based options stick even if secedit skipped
  Write-Host "Writing registry security options directly (defense-in-depth)..." -ForegroundColor Cyan
  New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictanonymous"     -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM"  -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash"              -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ForceGuest"            -Value 0 -PropertyType DWord -Force | Out-Null

  $wk = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
  $sv = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
  New-Item -Path $wk -Force | Out-Null; New-Item -Path $sv -Force | Out-Null
  New-ItemProperty -Path $wk -Name "RequireSecuritySignature" -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $wk -Name "EnableSecuritySignature"  -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $sv -Name "RequireSecuritySignature" -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $sv -Name "EnableSecuritySignature"  -Value 1 -PropertyType DWord -Force | Out-Null
}

function Verify-And-Report {
  Write-Host "`n===== Verification =====" -ForegroundColor White

  # Domain join?
  $dom = (Get-WmiObject Win32_ComputerSystem).PartOfDomain
  Write-Host ("Domain joined: " + ($dom -as [bool])) -ForegroundColor Yellow
  if($dom){ Write-Host "NOTE: Domain GPOs may override local policy." -ForegroundColor DarkYellow }

  # Password policy / lockout (net accounts reflects effective SAM policy)
  Write-Host "`n-- net accounts --" -ForegroundColor Cyan
  cmd /c net accounts

  # Audit policy
  Write-Host "`n-- auditpol (summary) --" -ForegroundColor Cyan
  auditpol /get /category:* | Out-String | Write-Host

  # Firewall
  Write-Host "`n-- firewall state --" -ForegroundColor Cyan
  netsh advfirewall show allprofiles | Out-String | Write-Host

  # Key registry checks
  Write-Host "`n-- registry checks --" -ForegroundColor Cyan
  $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
  $wk  = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
  $sv  = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
  "LimitBlankPasswordUse = " + (Get-ItemProperty -Path $lsa -Name LimitBlankPasswordUse -ErrorAction SilentlyContinue).LimitBlankPasswordUse | Write-Host
  "restrictanonymous     = " + (Get-ItemProperty -Path $lsa -Name restrictanonymous     -ErrorAction SilentlyContinue).restrictanonymous     | Write-Host
  "RestrictAnonymousSAM  = " + (Get-ItemProperty -Path $lsa -Name RestrictAnonymousSAM  -ErrorAction SilentlyContinue).RestrictAnonymousSAM  | Write-Host
  "NoLMHash              = " + (Get-ItemProperty -Path $lsa -Name NoLMHash              -ErrorAction SilentlyContinue).NoLMHash              | Write-Host
  "ForceGuest            = " + (Get-ItemProperty -Path $lsa -Name ForceGuest            -ErrorAction SilentlyContinue).ForceGuest            | Write-Host
  "Workstation RequireSecuritySignature = " + (Get-ItemProperty -Path $wk -Name RequireSecuritySignature -ErrorAction SilentlyContinue).RequireSecuritySignature | Write-Host
  "Server     RequireSecuritySignature = " + (Get-ItemProperty -Path $sv -Name RequireSecuritySignature -ErrorAction SilentlyContinue).RequireSecuritySignature | Write-Host

  # Windows Update policy
  Write-Host "`n-- Windows Update policy --" -ForegroundColor Cyan
  $wuAU = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
  if(Test-Path $wuAU){
    Get-ItemProperty -Path $wuAU | Select-Object NoAutoUpdate,AUOptions,ScheduledInstallDay,ScheduledInstallTime | Format-List | Out-String | Write-Host
  } else { Write-Host "No local WU policy key found." }

  Write-Host "`n(secedit detailed log: %windir%\security\logs\*.log ; current DBs: %windir%\security\database\)" -ForegroundColor DarkGray
}

# ------------------- main -------------------
try {
  Assert-Admin
  New-Folder $WorkingDir
  $backup   = Join-Path $WorkingDir "backup-$(Get-Date -Format yyyyMMdd-HHmmss).inf"
  $baseline = Join-Path $WorkingDir $TemplateName

  Export-CurrentSecurityPolicy $backup
  Write-BaselineInf $baseline
  Apply-SeceditTemplate $baseline

  # Defense-in-depth to ensure settings "stick"
  Fallback-AccountPolicies
  Write-RegistryOptionsDirect
  Set-AdvancedAuditPolicy
  Enable-FirewallAllProfiles
  Ensure-AutomaticUpdates

  # Optional: kick a policy refresh
  try { gpupdate /target:computer /force | Out-Null } catch {}

  Write-Host "`nBaseline attempted. Showing verification..." -ForegroundColor Green
  Verify-And-Report
}
catch {
  Write-Error $_.Exception.Message
  Write-Host "If nothing changed, check: %WINDIR%\security\logs\scesrv.log and the secedit log listed above." -ForegroundColor DarkGray
}
