<# 
Set-CyberPatriotBaseline.ps1 (No-Secedit; ISE/PowerShell 5.1 friendly)

Applies a CyberPatriot-style local security baseline WITHOUT secedit:
 - Password policy: Max age 90d, Min length 14, History 24
 - Lockout: threshold 10, window 15, duration 15
 - Limit blank passwords to console only = Enabled
 - Block anonymous enumeration of SAM accounts and shares = Enabled
 - Advanced Audit Policy (success/failure for common categories)
 - Windows Firewall ON (all profiles)
 - Configure Automatic Updates = Enabled (AUOptions=4)
 - Verification report at end

Run as Administrator.
#>

[CmdletBinding()]
param(
  [string]$WorkingDir   = "C:\CyberPatriotBaseline",
  [switch]$NoFirewall
)

# ------------------- Helpers -------------------
function Assert-Admin {
  $id=[Security.Principal.WindowsIdentity]::GetCurrent()
  $p =New-Object Security.Principal.WindowsPrincipal($id)
  if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw "Run this script in an elevated PowerShell session (Run as Administrator)."
  }
}

function New-Folder {
  param([string]$Path)
  if(-not (Test-Path $Path)){ New-Item -ItemType Directory -Path $Path -Force | Out-Null }
}

function Ensure-RegistryKey {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -Path $Path)) {
    New-Item -Path $Path -Force | Out-Null
  }
}

# ------------------- Baseline setters -------------------
function Apply-PasswordAndLockoutPolicy {
  <#
    Uses 'net accounts' to apply local SAM policy immediately:
      - Maximum password age = 90
      - Minimum password length = 14
      - Password history = 24
      - Lockout threshold = 10, duration = 15, window = 15
  #>
  Write-Host "Applying password/lockout policy via 'net accounts'..." -ForegroundColor Cyan
  & net accounts /maxpwage:90 /minpwlen:14 /uniquepw:24 | Out-Null
  & net accounts /lockoutthreshold:10 /lockoutduration:15 /lockoutwindow:15 | Out-Null
}

function Write-SecurityOptionsRegistry {
  <#
    Security Options via registry (defense-in-depth):
      - Limit blank passwords to console only
      - Block anonymous enumeration of SAM accounts and shares
      - Do not store LM hash
      - Don’t force network logons to Guest
      - Require SMB signing (client & server)
  #>
  Write-Host "Writing Security Options to registry..." -ForegroundColor Cyan

  $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
  Ensure-RegistryKey -Path $lsa
  New-ItemProperty -Path $lsa -Name "LimitBlankPasswordUse" -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $lsa -Name "restrictanonymous"     -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $lsa -Name "RestrictAnonymousSAM"  -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $lsa -Name "NoLMHash"              -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $lsa -Name "ForceGuest"            -Value 0 -PropertyType DWord -Force | Out-Null

  $wk = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
  $sv = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
  Ensure-RegistryKey -Path $wk
  Ensure-RegistryKey -Path $sv
  New-ItemProperty -Path $wk -Name "RequireSecuritySignature" -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $wk -Name "EnableSecuritySignature"  -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $sv -Name "RequireSecuritySignature" -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $sv -Name "EnableSecuritySignature"  -Value 1 -PropertyType DWord -Force | Out-Null
}

function Set-AdvancedAuditPolicy {
  Write-Host "Configuring Advanced Audit Policy..." -ForegroundColor Cyan
  $cats=@(
    "Account Logon","Account Management","DS Access","Logon/Logoff",
    "Object Access","Policy Change","Privilege Use","System","Detailed Tracking"
  )
  foreach($c in $cats){ try{ auditpol /set /category:"$c" /success:enable /failure:enable | Out-Null }catch{} }

  $subs=@(
    "Credential Validation","Computer Account Management","User Account Management",
    "Logon","Logoff","Account Lockout","Security Group Management",
    "Process Creation","Process Termination","Removable Storage"
  )
  foreach($s in $subs){ try{ auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null }catch{} }
}

function Enable-FirewallAllProfiles {
  param([switch]$Skip)
  if($Skip){ return }
  Write-Host "Enabling Windows Firewall (all profiles)..." -ForegroundColor Cyan
  try{ netsh advfirewall set allprofiles state on | Out-Null }catch{
    Write-Warning "Firewall enable failed: $($_.Exception.Message)"
  }
}

function Ensure-AutomaticUpdates {
  <#
    Configure Automatic Updates = Enabled (AUOptions=4) + ensure service runs (5.1-safe).
    Visible in gpedit.msc under:
      Computer Config -> Administrative Templates -> Windows Components -> Windows Update
  #>
  Write-Host "Configuring Windows Update policy (Configure Automatic Updates = Enabled)..." -ForegroundColor Cyan

  $wu = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
  $wuAU = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
  Ensure-RegistryKey -Path $wu
  Ensure-RegistryKey -Path $wuAU

  New-ItemProperty -Path $wuAU -Name "NoAutoUpdate"         -Value 0 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $wuAU -Name "AUOptions"            -Value 4 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $wuAU -Name "ScheduledInstallDay"  -Value 0 -PropertyType DWord -Force | Out-Null  # every day
  New-ItemProperty -Path $wuAU -Name "ScheduledInstallTime" -Value 3 -PropertyType DWord -Force | Out-Null  # 3 AM

  $svc = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
  if($null -eq $svc){ Write-Warning "wuauserv not found; skipping service steps."; return }
  try{ Set-Service -Name wuauserv -StartupType Automatic }catch{ Write-Warning "wuauserv startup type: $($_.Exception.Message)" }
  try{ Start-Service -Name wuauserv -ErrorAction SilentlyContinue }catch{ Write-Warning "wuauserv start: $($_.Exception.Message)" }
  try{ & sc.exe config wuauserv start= delayed-auto | Out-Null }catch{
    try{
      Ensure-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv"
      New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv" -Name "DelayedAutoStart" -Value 1 -PropertyType DWord -Force | Out-Null
    }catch{}
  }
}

# ------------------- Verification -------------------
function Verify-And-Report {
  Write-Host "`n===== Verification =====" -ForegroundColor White

  $dom = (Get-WmiObject Win32_ComputerSystem).PartOfDomain
  Write-Host ("Domain joined: " + ($dom -as [bool])) -ForegroundColor Yellow
  if($dom){ Write-Host "NOTE: Domain GPOs may override local policy." -ForegroundColor DarkYellow }

  Write-Host "`n-- net accounts --" -ForegroundColor Cyan
  cmd /c net accounts

  Write-Host "`n-- auditpol (summary) --" -ForegroundColor Cyan
  auditpol /get /category:* | Out-String | Write-Host

  Write-Host "`n-- firewall state --" -ForegroundColor Cyan
  netsh advfirewall show allprofiles | Out-String | Write-Host

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

  Write-Host "`n-- Windows Update policy --" -ForegroundColor Cyan
  $wuAU = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
  if(Test-Path $wuAU){
    Get-ItemProperty -Path $wuAU | Select-Object NoAutoUpdate,AUOptions,ScheduledInstallDay,ScheduledInstallTime | Format-List | Out-String | Write-Host
  } else { Write-Host "No local WU policy key found." }
}

# ------------------- Main -------------------
try {
  Assert-Admin
  New-Folder -Path $WorkingDir

  Apply-PasswordAndLockoutPolicy
  Write-SecurityOptionsRegistry
  Set-AdvancedAuditPolicy
  Enable-FirewallAllProfiles -Skip:$NoFirewall
  Ensure-AutomaticUpdates

  try { gpupdate /target:computer /force | Out-Null } catch {}

  Write-Host "`nBaseline applied. Running verification..." -ForegroundColor Green
  Verify-And-Report
}
catch {
  Write-Error $_.Exception.Message
}
