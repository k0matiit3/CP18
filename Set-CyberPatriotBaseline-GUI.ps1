<# 
Set-CyberPatriotBaseline-GUI.ps1
PowerShell 5.1, ISE-friendly, no-secedit. Adds a WinForms GUI to apply hardening items individually.

Covers:
- Password policy & lockout (net accounts) + registry (min length, complexity, reversible)
- Security options (blank pw console-only, restrict anonymous, NoLMHash, ForceGuest=0, SMB signing, require CTRL+ALT+DEL)
- WinRM disallow unencrypted, Advanced Audit Policy, Firewall ON, Disable RDP, Windows Update policy
- EXTRA hardening buckets common to CyberPatriot:
  * Accounts/Auth: NTLMv2 only, disable anonymous SID/Name translation, disable Guest
  * RDP/Remote: Require NLA (if RDP later enabled), disable Remote Assistance
  * Network/SMB/Legacy: disable SMBv1, lock down null sessions, disable LLMNR, (optional) disable NetBIOS
  * OS/UX: UAC strict, disable AutoRun/AutoPlay, optional screen lock
  * Defender/SmartScreen: enable Defender, update sigs, enable SmartScreen
  * TLS/SChannel: disable SSL2/3, TLS1.0/1.1; enable TLS1.2
  * Services: disable Remote Registry, SSDP, UPnP
  * Logging: increase Security log size, retention policy

NOTE: Some settings may require restart or policy refresh to fully take effect.
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

function Set-RegDWORD {
  param([string]$Path,[string]$Name,[int]$Value)
  Ensure-RegistryKey -Path $Path
  New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
}

function Set-RegString {
  param([string]$Path,[string]$Name,[string]$Value)
  Ensure-RegistryKey -Path $Path
  New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType String -Force | Out-Null
}

function Set-RegMultiSz {
  param([string]$Path,[string]$Name,[string[]]$Values)
  Ensure-RegistryKey -Path $Path
  New-ItemProperty -Path $Path -Name $Name -Value $Values -PropertyType MultiString -Force | Out-Null
}

# ------------------- Baseline setters (core) -------------------
function Apply-PasswordAndLockoutPolicy {
  & net accounts /maxpwage:90 /minpwlen:14 /uniquepw:24 | Out-Null
  & net accounts /lockoutthreshold:10 /lockoutduration:15 /lockoutwindow:15 | Out-Null
}

function Enforce-PasswordPolicyRegistry {
  $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
  Set-RegDWORD $lsa "MinimumPasswordLength" 14     # >=10 required
  Set-RegDWORD $lsa "PasswordComplexity" 1         # complexity ON
  Set-RegDWORD $lsa "ClearTextPassword" 0          # reversible OFF
}

function Write-SecurityOptionsRegistry {
  $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
  Set-RegDWORD $lsa "LimitBlankPasswordUse" 1
  Set-RegDWORD $lsa "restrictanonymous" 1
  Set-RegDWORD $lsa "RestrictAnonymousSAM" 1
  Set-RegDWORD $lsa "NoLMHash" 1
  Set-RegDWORD $lsa "ForceGuest" 0

  # Require CTRL+ALT+DEL
  $polSys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
  Set-RegDWORD $polSys "DisableCAD" 0

  # SMB signing (client/server) + "always sign" implied by Require=1
  $wk = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
  $sv = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
  Set-RegDWORD $wk "RequireSecuritySignature" 1
  Set-RegDWORD $wk "EnableSecuritySignature" 1
  Set-RegDWORD $sv "RequireSecuritySignature" 1
  Set-RegDWORD $sv "EnableSecuritySignature" 1
}

function Configure-WinRM-DisallowUnencrypted {
  $base = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM"
  Set-RegDWORD (Join-Path $base "Service") "AllowUnencryptedTraffic" 0
  Set-RegDWORD (Join-Path $base "Client")  "AllowUnencryptedTraffic" 0
}

function Disable-RemoteDesktop {
  $sysTS = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
  $polTS = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
  Set-RegDWORD $sysTS "fDenyTSConnections" 1
  Set-RegDWORD $polTS "fDenyTSConnections" 1
  try { Stop-Service -Name TermService -ErrorAction SilentlyContinue } catch {}
}

function Set-AdvancedAuditPolicy {
  $cats=@("Account Logon","Account Management","DS Access","Logon/Logoff","Object Access","Policy Change","Privilege Use","System","Detailed Tracking")
  foreach($c in $cats){ try{ auditpol /set /category:"$c" /success:enable /failure:enable | Out-Null }catch{} }
  $subs=@("Credential Validation","Computer Account Management","User Account Management","Logon","Logoff","Account Lockout","Security Group Management","Process Creation","Process Termination","Removable Storage")
  foreach($s in $subs){ try{ auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null }catch{} }
}

function Enable-FirewallAllProfiles {
  try{ netsh advfirewall set allprofiles state on | Out-Null }catch{}
}

function Ensure-AutomaticUpdates {
  $wu   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
  $wuAU = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
  Set-RegDWORD $wuAU "NoAutoUpdate" 0
  Set-RegDWORD $wuAU "AUOptions" 4
  Set-RegDWORD $wuAU "ScheduledInstallDay" 0
  Set-RegDWORD $wuAU "ScheduledInstallTime" 3
  $svc = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
  if($svc){ try{ Set-Service -Name wuauserv -StartupType Automatic }catch{}; try{ Start-Service wuauserv -ErrorAction SilentlyContinue }catch{}; try{ & sc.exe config wuauserv start= delayed-auto | Out-Null }catch{} }
}

function Run-GPUpdate { try { gpupdate /target:computer /force | Out-Null } catch {} }

# ------------------- EXTRA hardening buckets -------------------
# Accounts & Auth
function Harden-NTLM {
  $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
  Set-RegDWORD $lsa "LmCompatibilityLevel" 5   # NTLMv2 only, refuse LM/NTLM
  Set-RegDWORD $lsa "DisableAnonymousSidNameTranslation" 1
  # Explicitly disable Guest
  try { & net user guest /active:no | Out-Null } catch {}
}

# RDP extras
function Require-RDP-NLA {
  $rdpTcp = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
  Set-RegDWORD $rdpTcp "UserAuthentication" 1   # NLA
}

function Disable-RemoteAssistance {
  $ra = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
  Set-RegDWORD $ra "fAllowToGetHelp" 0
}

# Network & SMB/Legacy
function Disable-SMBv1 {
  try { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null } catch {}
  try { Set-RegDWORD "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" "Start" 4 } catch {}
  try { Set-RegDWORD "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1" 0 } catch {}
}

function Lockdown-NullSessions {
  $srv = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
  Set-RegDWORD $srv "RestrictNullSessAccess" 1
  Set-RegMultiSz $srv "NullSessionShares" @()
  Set-RegMultiSz $srv "NullSessionPipes"  @()
}

function Disable-LLMNR {
  $dnsCli = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
  Set-RegDWORD $dnsCli "EnableMulticast" 0
}

function Disable-NetBIOS {
  # Iterate network interfaces and set NetbiosOptions=2 (disable)
  $base = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
  if (Test-Path $base) {
    Get-ChildItem $base | ForEach-Object {
      try { Set-RegDWORD $_.PSPath "NetbiosOptions" 2 } catch {}
    }
  }
}

# OS Hardening / UX
function UAC-Strict {
  $polSys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
  Set-RegDWORD $polSys "EnableLUA" 1
  Set-RegDWORD $polSys "ConsentPromptBehaviorAdmin" 2  # Prompt for consent on secure desktop
}

function Disable-AutoRunAutoPlay {
  Set-RegDWORD "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" 255
}

function Enable-ScreenLock {
  # Current user only; if running as different admin, this affects that account
  $desk = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
  Ensure-RegistryKey -Path $desk
  Set-RegString $desk "ScreenSaveActive" "1"
  Set-RegString $desk "ScreenSaverIsSecure" "1"
  Set-RegString $desk "ScreenSaveTimeOut" "900"
}

# Defender / SmartScreen
function Configure-DefenderSmartScreen {
  try {
    Set-MpPreference -DisableRealtimeMonitoring $false -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -ErrorAction SilentlyContinue
    Update-MpSignature -ErrorAction SilentlyContinue
  } catch {}
  $sys = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
  Set-RegDWORD  $sys "EnableSmartScreen" 1
  Set-RegString $sys "ShellSmartScreenLevel" "Block"
}

# TLS & crypto
function Harden-SChannel {
  $root = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
  $pairs = @(
    @{Proto="SSL 2.0"; En=0},
    @{Proto="SSL 3.0"; En=0},
    @{Proto="TLS 1.0"; En=0},
    @{Proto="TLS 1.1"; En=0},
    @{Proto="TLS 1.2"; En=1}
  )
  foreach($p in $pairs){
    $server = Join-Path $root ($p.Proto + "\Server")
    $client = Join-Path $root ($p.Proto + "\Client")
    Set-RegDWORD $server "Enabled" $p.En
    Set-RegDWORD $client "Enabled" $p.En
    # Also ensure DisabledByDefault where appropriate (0 when enabled, 1 when disabled)
    $dbd = ($p.En -eq 1) ? 0 : 1
    Set-RegDWORD $server "DisabledByDefault" $dbd
    Set-RegDWORD $client "DisabledByDefault" $dbd
  }
}

# Services
function Disable-ProblemServices {
  foreach($svc in @("RemoteRegistry","SSDPSRV","upnphost")){
    try { Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue } catch {}
    try { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue } catch {}
  }
}

# Logging / Auditing polish
function Tune-EventLog {
  $sec = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security"
  Set-RegDWORD $sec "MaxSize" 196608  # ~192 MB
  Set-RegDWORD $sec "Retention" 0     # Overwrite as needed (or set 1 for do not overwrite)
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

  Write-Host "`n-- key registry checks --" -ForegroundColor Cyan
  function ShowVal($Path,$Name){ try{ $v=(Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }catch{$v=$null}; "{0} : {1}" -f "$Path\$Name",$v | Write-Host }

  # Password policy (LSA), security options
  $lsa="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
  foreach($n in "MinimumPasswordLength","PasswordComplexity","ClearTextPassword","LimitBlankPasswordUse","restrictanonymous","RestrictAnonymousSAM","NoLMHash","ForceGuest","LmCompatibilityLevel","DisableAnonymousSidNameTranslation"){ ShowVal $lsa $n }

  # CAD
  ShowVal "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD"

  # SMB signing, null sessions
  ShowVal "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature"
  ShowVal "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature"
  ShowVal "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RestrictNullSessAccess"

  # LLMNR
  ShowVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast"

  # RDP & NLA
  ShowVal "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections"
  ShowVal "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication"

  # Remote Assistance
  ShowVal "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" "fAllowToGetHelp"

  # WinRM
  ShowVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowUnencryptedTraffic"
  ShowVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"  "AllowUnencryptedTraffic"

  # Defender/SmartScreen
  ShowVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen"
  ShowVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "ShellSmartScreenLevel"

  # SChannel TLS
  foreach($p in "SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1","TLS 1.2"){
    ShowVal ("HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\{0}\Server" -f $p) "Enabled"
    ShowVal ("HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\{0}\Client" -f $p) "Enabled"
  }

  # Services state
  foreach($svc in "RemoteRegistry","SSDPSRV","upnphost"){ try{ ("Service {0} : {1}" -f $svc, (Get-Service $svc -ErrorAction Stop).Status) | Write-Host }catch{} }

  # Event log tuning
  ShowVal "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" "MaxSize"
  ShowVal "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" "Retention"

  # Windows Update policy quick check
  ShowVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUOptions"
}

# ------------------- GUI -------------------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Show-BaselineGui {
  Assert-Admin
  New-Folder -Path $WorkingDir

  $form = New-Object System.Windows.Forms.Form
  $form.Text = "CyberPatriot Baseline - Select Features"
  $form.Size = New-Object System.Drawing.Size(780, 700)
  $form.StartPosition = "CenterScreen"

  $y = 10; $x = 10; $width = 740; $rowH = 22
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

  # Core items
  NewCB 'PwdLockout'   "Password policy & lockout (net accounts: MaxAge=90, MinLen=14, Hist=24; Lockout=10/15/15)"
  NewCB 'PwdRegistry'  "Password policy registry (MinLen=14, Complexity=On, Reversible=Off)"
  NewCB 'SecOptions'   "Security options (blank pw console-only, restrict anonymous, NoLMHash, ForceGuest=0, SMB signing, require CTRL+ALT+DEL)"
  NewCB 'WinRM'        "WinRM: disallow unencrypted traffic (client & service)"
  NewCB 'Audit'        "Advanced Audit Policy (success+failure common categories)"
  NewCB 'Firewall'     "Firewall ON (all profiles)"
  NewCB 'DisableRDP'   "Disable Remote Desktop connections"
  NewCB 'WU'           "Windows Update policy (Configure Automatic Updates=Enabled; AUOptions=4; 3 AM; service auto)"

  # Extras
  NewCB 'NTLM'         "NTLM hardening (LmCompatibilityLevel=5), disable anonymous SID/Name translation, disable Guest"
  NewCB 'RDP_NLA'      "Require Network Level Authentication (NLA) for RDP (if enabled)"
  NewCB 'RemoteAssist' "Disable Remote Assistance"
  NewCB 'SMB1'         "Disable SMBv1"
  NewCB 'NullSess'     "Lock down null sessions (RestrictNullSessAccess, clear NullSessionShares/Pipes)"
  NewCB 'LLMNR'        "Disable LLMNR"
  NewCB 'NetBIOS'      "Disable NetBIOS over TCP/IP on all adapters"
  NewCB 'UAC'          "UAC strict (EnableLUA=1, Admin consent on secure desktop)"
  NewCB 'AutoRun'      "Disable AutoRun/AutoPlay"
  NewCB 'ScreenLock'   "Enable screen lock (current user): 15 min, secure"
  NewCB 'Defender'     "Windows Defender on + update signatures; SmartScreen=On"
  NewCB 'TLS'          "SChannel: disable SSL2/3, TLS1.0/1.1; enable TLS1.2"
  NewCB 'BadServices'  "Disable services: RemoteRegistry, SSDPSRV, upnphost"
  NewCB 'EventLog'     "Security log: ~192MB, overwrite as needed"

  # Spacing
  $y += 6

  # Buttons
  $btnApply = New-Object System.Windows.Forms.Button
  $btnApply.Text = "Apply Selected"
  $btnApply.Size = New-Object System.Drawing.Size(150, 32)
  $btnApply.Location = New-Object System.Drawing.Point(10, $y)
  $form.Controls.Add($btnApply)

  $btnVerify = New-Object System.Windows.Forms.Button
  $btnVerify.Text = "Verify Only"
  $btnVerify.Size = New-Object System.Drawing.Size(150, 32)
  $btnVerify.Location = New-Object System.Drawing.Point(170, $y)
  $form.Controls.Add($btnVerify)

  $btnAll = New-Object System.Windows.Forms.Button
  $btnAll.Text = "Select All"
  $btnAll.Size = New-Object System.Drawing.Size(120, 32)
  $btnAll.Location = New-Object System.Drawing.Point(330, $y)
  $form.Controls.Add($btnAll)

  $btnNone = New-Object System.Windows.Forms.Button
  $btnNone.Text = "Deselect All"
  $btnNone.Size = New-Object System.Drawing.Size(120, 32)
  $btnNone.Location = New-Object System.Drawing.Point(460, $y)
  $form.Controls.Add($btnNone)

  $btnGP = New-Object System.Windows.Forms.Button
  $btnGP.Text = "gpupdate /force"
  $btnGP.Size = New-Object System.Drawing.Size(120, 32)
  $btnGP.Location = New-Object System.Drawing.Point(590, $y)
  $form.Controls.Add($btnGP)

  $y += 42

  # Output textbox (log)
  $txt = New-Object System.Windows.Forms.TextBox
  $txt.Multiline = $true
  $txt.ReadOnly  = $true
  $txt.ScrollBars = "Vertical"
  $txt.Size = New-Object System.Drawing.Size(740, 180)
  $txt.Location = New-Object System.Drawing.Point(10, $y)
  $form.Controls.Add($txt)

  function Log($s){
    $line = ("[{0}] {1}" -f (Get-Date).ToString("HH:mm:ss"), $s)
    $txt.AppendText($line + [Environment]::NewLine)
    Write-Host $s
  }

  # Events
  $btnAll.Add_Click({ foreach($k in $cb.Keys){ $cb[$k].Checked = $true } })
  $btnNone.Add_Click({ foreach($k in $cb.Keys){ $cb[$k].Checked = $false } })
  $btnGP.Add_Click({ Log "Running gpupdate /force ..."; Run-GPUpdate; Log "gpupdate complete." })

  $btnApply.Add_Click({
    try{
      Log "Applying selected features..."
      if($cb.PwdLockout.Checked){   Log " - Password & Lockout";         Apply-PasswordAndLockoutPolicy }
      if($cb.PwdRegistry.Checked){  Log " - Password Registry";          Enforce-PasswordPolicyRegistry }
      if($cb.SecOptions.Checked){   Log " - Security Options";           Write-SecurityOptionsRegistry }
      if($cb.WinRM.Checked){        Log " - WinRM Harden";               Configure-WinRM-DisallowUnencrypted }
      if($cb.Audit.Checked){        Log " - Audit Policy";               Set-AdvancedAuditPolicy }
      if($cb.Firewall.Checked){     Log " - Firewall";                   Enable-FirewallAllProfiles }
      if($cb.DisableRDP.Checked){   Log " - Disable RDP";                Disable-RemoteDesktop }
      if($cb.WU.Checked){           Log " - Windows Update";             Ensure-AutomaticUpdates }

      if($cb.NTLM.Checked){         Log " - NTLM hardening";             Harden-NTLM }
      if($cb.RDP_NLA.Checked){      Log " - RDP NLA";                    Require-RDP-NLA }
      if($cb.RemoteAssist.Checked){ Log " - Disable Remote Assistance";  Disable-RemoteAssistance }
      if($cb.SMB1.Checked){         Log " - Disable SMBv1";              Disable-SMBv1 }
      if($cb.NullSess.Checked){     Log " - Lockdown null sessions";     Lockdown-NullSessions }
      if($cb.LLMNR.Checked){        Log " - Disable LLMNR";              Disable-LLMNR }
      if($cb.NetBIOS.Checked){      Log " - Disable NetBIOS";            Disable-NetBIOS }
      if($cb.UAC.Checked){          Log " - UAC strict";                 UAC-Strict }
      if($cb.AutoRun.Checked){      Log " - Disable AutoRun/AutoPlay";   Disable-AutoRunAutoPlay }
      if($cb.ScreenLock.Checked){   Log " - Screen lock (current user)"; Enable-ScreenLock }
      if($cb.Defender.Checked){     Log " - Defender/SmartScreen";       Configure-DefenderSmartScreen }
      if($cb.TLS.Checked){          Log " - SChannel TLS hardening";     Harden-SChannel }
      if($cb.BadServices.Checked){  Log " - Disable services";           Disable-ProblemServices }
      if($cb.EventLog.Checked){     Log " - Tune Security log";          Tune-EventLog }

      Log "Applying gpupdate (recommended)..."
      Run-GPUpdate
      Log "Done. Consider reboot for TLS/SMB/protocol changes."
      [System.Windows.Forms.MessageBox]::Show("Selected items applied.", "Baseline", 'OK', 'Information') | Out-Null
    } catch {
      [System.Windows.Forms.MessageBox]::Show("Error: $($_.Exception.Message)", "Baseline", 'OK', 'Error') | Out-Null
    }
  })

  $btnVerify.Add_Click({
    try{
      Log "Verification only..."
      Verify-And-Report
      Log "Done."
    } catch {
      [System.Windows.Forms.MessageBox]::Show("Error: $($_.Exception.Message)", "Verify", 'OK', 'Error') | Out-Null
    }
  })

  $form.Add_Shown({ $form.Activate() })
  [void]$form.ShowDialog()
}

# ------------------- Main -------------------
try {
  Assert-Admin
  New-Folder -Path $WorkingDir
  Show-BaselineGui
}
catch {
  Write-Error $_.Exception.Message
}
