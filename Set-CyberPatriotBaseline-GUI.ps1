<# 
Set-CyberPatriotBaseline-GUI.ps1  (PowerShell 5.1, ISE-friendly, no-secedit)

Adds a simple GUI with checkboxes for selecting which baseline features to apply.

Features (each can be toggled):
- Password policy & lockout via 'net accounts' (MaxAge=90, MinLen=14, History=24, Lockout=10/15/15)
- Password policy registry reinforcement (MinLen=14, Complexity=Enabled, Reversible=Disabled)
- Security options (blank passwords console-only, restrict anonymous, NoLMHash, ForceGuest=0, SMB signing client/server, require CTRL+ALT+DEL)
- WinRM: disallow unencrypted traffic (client & service)
- Advanced Audit Policy (success+failure for common cats/subcats)
- Firewall ON (all profiles)
- Disable Remote Desktop connections
- Windows Update policy (Configure Automatic Updates = Enabled, AUOptions=4, 3am, service auto+delayed)
- GPUpdate /force
- Verification report (prints effective state)

Run as Administrator.
#>

[CmdletBinding()]
param(
  [string]$WorkingDir = "C:\CyberPatriotBaseline"
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
  if (-not (Test-Path -Path $Path)) { New-Item -Path $Path -Force | Out-Null }
}

# ------------------- Baseline setters -------------------
function Apply-PasswordAndLockoutPolicy {
  Write-Host "Applying password/lockout policy via 'net accounts'..." -ForegroundColor Cyan
  & net accounts /maxpwage:90 /minpwlen:14 /uniquepw:24 | Out-Null
  & net accounts /lockoutthreshold:10 /lockoutduration:15 /lockoutwindow:15 | Out-Null
}

function Enforce-PasswordPolicyRegistry {
  Write-Host "Reinforcing password policy in LSA registry (MinLen=14, Complexity=On, Reversible=Off)..." -ForegroundColor Cyan
  $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
  Ensure-RegistryKey -Path $lsa
  New-ItemProperty -Path $lsa -Name "MinimumPasswordLength" -Value 14 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $lsa -Name "PasswordComplexity"    -Value 1  -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $lsa -Name "ClearTextPassword"     -Value 0  -PropertyType DWord -Force | Out-Null
}

function Write-SecurityOptionsRegistry {
  Write-Host "Writing Security Options to registry..." -ForegroundColor Cyan
  $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
  Ensure-RegistryKey -Path $lsa
  New-ItemProperty -Path $lsa -Name "LimitBlankPasswordUse" -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $lsa -Name "restrictanonymous"     -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $lsa -Name "RestrictAnonymousSAM"  -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $lsa -Name "NoLMHash"              -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $lsa -Name "ForceGuest"            -Value 0 -PropertyType DWord -Force | Out-Null

  # Require CTRL+ALT+DEL (DisableCAD=0)
  $polSys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
  Ensure-RegistryKey -Path $polSys
  New-ItemProperty -Path $polSys -Name "DisableCAD" -Value 0 -PropertyType DWord -Force | Out-Null

  # SMB signing (client/server) + client "always sign"
  $wk = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
  $sv = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
  Ensure-RegistryKey -Path $wk
  Ensure-RegistryKey -Path $sv
  New-ItemProperty -Path $wk -Name "RequireSecuritySignature" -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $wk -Name "EnableSecuritySignature"  -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $sv -Name "RequireSecuritySignature" -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $sv -Name "EnableSecuritySignature"  -Value 1 -PropertyType DWord -Force | Out-Null
}

function Configure-WinRM-DisallowUnencrypted {
  Write-Host "Configuring WinRM to disallow unencrypted traffic..." -ForegroundColor Cyan
  $base = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM"
  $svc  = Join-Path $base "Service"
  $cli  = Join-Path $base "Client"
  Ensure-RegistryKey -Path $base
  Ensure-RegistryKey -Path $svc
  Ensure-RegistryKey -Path $cli
  New-ItemProperty -Path $svc -Name "AllowUnencryptedTraffic" -Value 0 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $cli -Name "AllowUnencryptedTraffic" -Value 0 -PropertyType DWord -Force | Out-Null
}

function Disable-RemoteDesktop {
  Write-Host "Disabling Remote Desktop connections..." -ForegroundColor Cyan
  $sysTS = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
  $polTS = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
  Ensure-RegistryKey -Path $sysTS
  Ensure-RegistryKey -Path $polTS
  New-ItemProperty -Path $sysTS -Name "fDenyTSConnections" -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $polTS -Name "fDenyTSConnections" -Value 1 -PropertyType DWord -Force | Out-Null
  try { Stop-Service -Name TermService -ErrorAction SilentlyContinue } catch {}
}

function Set-AdvancedAuditPolicy {
  Write-Host "Configuring Advanced Audit Policy..." -ForegroundColor Cyan
  $cats=@("Account Logon","Account Management","DS Access","Logon/Logoff","Object Access","Policy Change","Privilege Use","System","Detailed Tracking")
  foreach($c in $cats){ try{ auditpol /set /category:"$c" /success:enable /failure:enable | Out-Null }catch{} }
  $subs=@("Credential Validation","Computer Account Management","User Account Management","Logon","Logoff","Account Lockout","Security Group Management","Process Creation","Process Termination","Removable Storage")
  foreach($s in $subs){ try{ auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null }catch{} }
}

function Enable-FirewallAllProfiles {
  Write-Host "Enabling Windows Firewall (all profiles)..." -ForegroundColor Cyan
  try{ netsh advfirewall set allprofiles state on | Out-Null }catch{
    Write-Warning "Firewall enable failed: $($_.Exception.Message)"
  }
}

function Ensure-AutomaticUpdates {
  Write-Host "Configuring Windows Update policy (Configure Automatic Updates = Enabled)..." -ForegroundColor Cyan
  $wu   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
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

function Run-GPUpdate {
  Write-Host "Running gpupdate /force ..." -ForegroundColor Cyan
  try { gpupdate /target:computer /force | Out-Null } catch {}
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
  $polSys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
  $winRMsvc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
  $winRMcli = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"

  "MinimumPasswordLength  = " + (Get-ItemProperty -Path $lsa -Name MinimumPasswordLength -ErrorAction SilentlyContinue).MinimumPasswordLength | Write-Host
  "PasswordComplexity     = " + (Get-ItemProperty -Path $lsa -Name PasswordComplexity    -ErrorAction SilentlyContinue).PasswordComplexity    | Write-Host
  "ClearTextPassword      = " + (Get-ItemProperty -Path $lsa -Name ClearTextPassword     -ErrorAction SilentlyContinue).ClearTextPassword     | Write-Host
  "LimitBlankPasswordUse  = " + (Get-ItemProperty -Path $lsa -Name LimitBlankPasswordUse -ErrorAction SilentlyContinue).LimitBlankPasswordUse | Write-Host
  "restrictanonymous      = " + (Get-ItemProperty -Path $lsa -Name restrictanonymous     -ErrorAction SilentlyContinue).restrictanonymous     | Write-Host
  "RestrictAnonymousSAM   = " + (Get-ItemProperty -Path $lsa -Name RestrictAnonymousSAM  -ErrorAction SilentlyContinue).RestrictAnonymousSAM  | Write-Host
  "NoLMHash               = " + (Get-ItemProperty -Path $lsa -Name NoLMHash              -ErrorAction SilentlyContinue).NoLMHash              | Write-Host
  "ForceGuest             = " + (Get-ItemProperty -Path $lsa -Name ForceGuest            -ErrorAction SilentlyContinue).ForceGuest            | Write-Host
  "DisableCAD (0=require CAD) = " + (Get-ItemProperty -Path $polSys -Name DisableCAD -ErrorAction SilentlyContinue).DisableCAD | Write-Host
  "Workstation RequireSecuritySignature = " + (Get-ItemProperty -Path $wk -Name RequireSecuritySignature -ErrorAction SilentlyContinue).RequireSecuritySignature | Write-Host
  "Server     RequireSecuritySignature = " + (Get-ItemProperty -Path $sv -Name RequireSecuritySignature -ErrorAction SilentlyContinue).RequireSecuritySignature | Write-Host
  "WinRM Service AllowUnencryptedTraffic = " + (Get-ItemProperty -Path $winRMsvc -Name AllowUnencryptedTraffic -ErrorAction SilentlyContinue).AllowUnencryptedTraffic | Write-Host
  "WinRM Client  AllowUnencryptedTraffic = " + (Get-ItemProperty -Path $winRMcli -Name AllowUnencryptedTraffic -ErrorAction SilentlyContinue).AllowUnencryptedTraffic | Write-Host
  $sysTS = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
  "RDP fDenyTSConnections (1 = disabled) = " + (Get-ItemProperty -Path $sysTS -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections | Write-Host

  Write-Host "`n-- Windows Update policy --" -ForegroundColor Cyan
  $wuAU = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
  if(Test-Path $wuAU){
    Get-ItemProperty -Path $wuAU | Select-Object NoAutoUpdate,AUOptions,ScheduledInstallDay,ScheduledInstallTime | Format-List | Out-String | Write-Host
  } else { Write-Host "No local WU policy key found." }
}

# ------------------- GUI -------------------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Show-BaselineGui {
  Assert-Admin
  New-Folder -Path $WorkingDir

  $form = New-Object System.Windows.Forms.Form
  $form.Text = "CyberPatriot Baseline - Select Features"
  $form.Size = New-Object System.Drawing.Size(640, 520)
  $form.StartPosition = "CenterScreen"

  $y = 20
  $x = 20
  $width = 580
  $rowH = 26

  # Checkboxes
  $cb = @{}

  function NewCB($name,$text,$checked=$true){
    $chk = New-Object System.Windows.Forms.CheckBox
    $chk.Text = $text
    $chk.AutoSize = $false
    $chk.Size = New-Object System.Drawing.Size($width, $rowH)
    $chk.Location = New-Object System.Drawing.Point($x, $script:y)
    $chk.Checked = $checked
    $form.Controls.Add($chk)
    $script:y += $rowH
    $cb[$name] = $chk
  }

  NewCB 'PwdLockout'   "Password policy & lockout (net accounts: MaxAge=90, MinLen=14, History=24; Lockout=10/15/15)"
  NewCB 'PwdRegistry'  "Password policy registry (MinLen=14, Complexity=On, Reversible=Off)"
  NewCB 'SecOptions'   "Security options (blank pw console-only, restrict anonymous, NoLMHash, ForceGuest=0, SMB signing, require CTRL+ALT+DEL)"
  NewCB 'WinRM'        "WinRM: disallow unencrypted traffic (client & service)"
  NewCB 'Audit'        "Advanced Audit Policy (success+failure common categories)"
  NewCB 'Firewall'     "Firewall ON (all profiles)"
  NewCB 'DisableRDP'   "Disable Remote Desktop connections"
  NewCB 'WU'           "Windows Update policy (Configure Automatic Updates=Enabled; AUOptions=4; 3 AM; service auto)"
  NewCB 'GPUpdate'     "Run gpupdate /force at the end"
  NewCB 'Verify'       "Show verification report"

  # Buttons
  $btnApply = New-Object System.Windows.Forms.Button
  $btnApply.Text = "Apply Selected"
  $btnApply.Size = New-Object System.Drawing.Size(140, 32)
  $btnApply.Location = New-Object System.Drawing.Point(20, 420)
  $form.Controls.Add($btnApply)

  $btnVerify = New-Object System.Windows.Forms.Button
  $btnVerify.Text = "Verify Only"
  $btnVerify.Size = New-Object System.Drawing.Size(140, 32)
  $btnVerify.Location = New-Object System.Drawing.Point(180, 420)
  $form.Controls.Add($btnVerify)

  $btnAll = New-Object System.Windows.Forms.Button
  $btnAll.Text = "Select All"
  $btnAll.Size = New-Object System.Drawing.Size(120, 32)
  $btnAll.Location = New-Object System.Drawing.Point(340, 420)
  $form.Controls.Add($btnAll)

  $btnNone = New-Object System.Windows.Forms.Button
  $btnNone.Text = "Deselect All"
  $btnNone.Size = New-Object System.Drawing.Size(120, 32)
  $btnNone.Location = New-Object System.Drawing.Point(470, 420)
  $form.Controls.Add($btnNone)

  # Output textbox (read-only log)
  $txt = New-Object System.Windows.Forms.TextBox
  $txt.Multiline = $true
  $txt.ReadOnly  = $true
  $txt.ScrollBars = "Vertical"
  $txt.Size = New-Object System.Drawing.Size(600, 140)
  $txt.Location = New-Object System.Drawing.Point(20, 260)
  $form.Controls.Add($txt)

  function Log($s){
    $line = ("[{0}] {1}" -f (Get-Date).ToString("HH:mm:ss"), $s)
    $txt.AppendText($line + [Environment]::NewLine)
    Write-Host $s
  }

  # Wire up buttons
  $btnAll.Add_Click({
    foreach($k in $cb.Keys){ $cb[$k].Checked = $true }
  })
  $btnNone.Add_Click({
    foreach($k in $cb.Keys){ $cb[$k].Checked = $false }
  })

  $btnApply.Add_Click({
    try {
      Log "Applying selected features..."
      if($cb.PwdLockout.Checked){ Log " - Password & Lockout"; Apply-PasswordAndLockoutPolicy }
      if($cb.PwdRegistry.Checked){ Log " - Password Registry";  Enforce-PasswordPolicyRegistry }
      if($cb.SecOptions.Checked){ Log " - Security Options";    Write-SecurityOptionsRegistry }
      if($cb.WinRM.Checked){      Log " - WinRM Harden";        Configure-WinRM-DisallowUnencrypted }
      if($cb.Audit.Checked){      Log " - Audit Policy";        Set-AdvancedAuditPolicy }
      if($cb.Firewall.Checked){   Log " - Firewall";            Enable-FirewallAllProfiles }
      if($cb.DisableRDP.Checked){ Log " - Disable RDP";         Disable-RemoteDesktop }
      if($cb.WU.Checked){         Log " - Windows Update";      Ensure-AutomaticUpdates }
      if($cb.GPUpdate.Checked){   Log " - GPUpdate";            Run-GPUpdate }
      if($cb.Verify.Checked){     Log " - Verification...";     Verify-And-Report }
      Log "Done."
      [System.Windows.Forms.MessageBox]::Show("Selected items applied.", "Baseline", 'OK', 'Information') | Out-Null
    } catch {
      [System.Windows.Forms.MessageBox]::Show("Error: $($_.Exception.Message)", "Baseline", 'OK', 'Error') | Out-Null
    }
  })

  $btnVerify.Add_Click({
    try {
      Log "Verification only..."
      Verify-And-Report
      Log "Done."
    } catch {
      [System.Windows.Forms.MessageBox]::Show("Error: $($_.Exception.Message)", "Verify", 'OK', 'Error') | Out-Null
    }
  })

  # Show the form
  $form.Add_Shown({ $form.Activate() })
  [void]$form.ShowDialog()
}

# ------------------- Main (launch GUI) -------------------
try {
  Assert-Admin
  New-Folder -Path $WorkingDir
  Show-BaselineGui
}
catch {
  Write-Error $_.Exception.Message
}
