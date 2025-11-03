<# 
Set-CyberPatriotBaseline-GUI.ps1
PowerShell 5.1, ISE-friendly, no-secedit. WinForms GUI to apply Windows hardening items individually.

This build:
- Action/Notification Center toggle included and ON in the Recommended CP Defaults preset.
- STRICT preset for NetBIOS + LLMNR (both disabled in preset).

Some settings (SChannel/TLS, SMB protocol, some services) require a reboot/sign-out.
#>

[CmdletBinding()]
param(
  [string]$WorkingDir = "C:\CyberPatriotBaseline"
)

# ------------------- Helpers -------------------
function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script in an elevated PowerShell session (Run as Administrator)."
  }
}
function New-Folder { param([string]$Path) if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null } }
function Ensure-RegistryKey { param([Parameter(Mandatory)][string]$Path) if (-not (Test-Path -Path $Path)) { New-Item -Path $Path -Force | Out-Null } }
function Set-RegDWORD { param([string]$Path,[string]$Name,[int]$Value) Ensure-RegistryKey -Path $Path; New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null }
function Set-RegString { param([string]$Path,[string]$Name,[string]$Value) Ensure-RegistryKey -Path $Path; New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType String -Force | Out-Null }
function Set-RegMultiSz { param([string]$Path,[string]$Name,[string[]]$Values) Ensure-RegistryKey -Path $Path; New-ItemProperty -Path $Path -Name $Name -Value $Values -PropertyType MultiString -Force | Out-Null }
function Run-GPUpdate { try { gpupdate /target:computer /force | Out-Null } catch {} }

# ------------------- Baseline setters (core) -------------------
function Apply-PasswordAndLockoutPolicy {
  Write-Host "Applying password/lockout policy via 'net accounts'..." -ForegroundColor Cyan
  & net accounts /maxpwage:90 /minpwlen:14 /uniquepw:24 | Out-Null
  & net accounts /lockoutthreshold:10 /lockoutduration:15 /lockoutwindow:15 | Out-Null
}
function Enforce-PasswordPolicyRegistry {
  Write-Host "Reinforcing password policy in LSA registry (MinLen=14, Complexity=On, Reversible=Off)..." -ForegroundColor Cyan
  $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
  Set-RegDWORD $lsa "MinimumPasswordLength" 14
  Set-RegDWORD $lsa "PasswordComplexity"    1
  Set-RegDWORD $lsa "ClearTextPassword"     0
}
function Write-SecurityOptionsRegistry {
  Write-Host "Writing Security Options to registry..." -ForegroundColor Cyan
  $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
  Set-RegDWORD $lsa "LimitBlankPasswordUse" 1
  Set-RegDWORD $lsa "restrictanonymous"     1
  Set-RegDWORD $lsa "RestrictAnonymousSAM"  1
  Set-RegDWORD $lsa "NoLMHash"              1
  Set-RegDWORD $lsa "ForceGuest"            0
  $polSys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
  Set-RegDWORD $polSys "DisableCAD" 0
  $wk = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
  $sv = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
  Set-RegDWORD $wk "RequireSecuritySignature" 1
  Set-RegDWORD $wk "EnableSecuritySignature"  1
  Set-RegDWORD $sv "RequireSecuritySignature" 1
  Set-RegDWORD $sv "EnableSecuritySignature"  1
}
function Configure-WinRM-DisallowUnencrypted {
  Write-Host "Configuring WinRM to disallow unencrypted traffic..." -ForegroundColor Cyan
  $base = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM"
  Set-RegDWORD (Join-Path $base "Service") "AllowUnencryptedTraffic" 0
  Set-RegDWORD (Join-Path $base "Client")  "AllowUnencryptedTraffic" 0
}
function Disable-RemoteDesktop {
  Write-Host "Disabling Remote Desktop connections..." -ForegroundColor Cyan
  $sysTS = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
  $polTS = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
  Set-RegDWORD $sysTS "fDenyTSConnections" 1
  Set-RegDWORD $polTS "fDenyTSConnections" 1
  try { Stop-Service -Name TermService -ErrorAction SilentlyContinue } catch {}
}
function Set-AdvancedAuditPolicy {
  Write-Host "Configuring Advanced Audit Policy..." -ForegroundColor Cyan
  $cats=@("Account Logon","Account Management","DS Access","Logon/Logoff","Object Access","Policy Change","Privilege Use","System","Detailed Tracking")
  foreach($c in $cats){ try{ auditpol /set /category:"$c" /success:enable /failure:enable | Out-Null } catch {} }
  $subs=@("Credential Validation","Computer Account Management","User Account Management","Logon","Logoff","Account Lockout","Security Group Management","Process Creation","Process Termination","Removable Storage")
  foreach($s in $subs){ try{ auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null } catch {} }
}
function Enable-FirewallAllProfiles { Write-Host "Enabling Windows Firewall (all profiles)..." -ForegroundColor Cyan; try { netsh advfirewall set allprofiles state on | Out-Null } catch {} }
function Ensure-AutomaticUpdates {
  Write-Host "Configuring Windows Update policy (Configure Automatic Updates = Enabled)..." -ForegroundColor Cyan
  $wuAU = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
  Set-RegDWORD $wuAU "NoAutoUpdate" 0
  Set-RegDWORD $wuAU "AUOptions" 4
  Set-RegDWORD $wuAU "ScheduledInstallDay" 0
  Set-RegDWORD $wuAU "ScheduledInstallTime" 3
  $svc = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
  if ($svc) {
    try { Set-Service -Name wuauserv -StartupType Automatic } catch {}
    try { Start-Service wuauserv -ErrorAction SilentlyContinue } catch {}
    try { & sc.exe config wuauserv start= delayed-auto | Out-Null } catch {}
  }
}

# ------------------- EXTRA hardening buckets -------------------
function Harden-NTLM {
  Write-Host "Applying NTLM hardening..." -ForegroundColor Cyan
  $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
  Set-RegDWORD $lsa "LmCompatibilityLevel" 5
  Set-RegDWORD $lsa "DisableAnonymousSidNameTranslation" 1
  try { & net user guest /active:no | Out-Null } catch {}
}
function Require-RDP-NLA { Write-Host "Requiring NLA for RDP..." -ForegroundColor Cyan; Set-RegDWORD "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication" 1 }
function Disable-RemoteAssistance { Write-Host "Disabling Remote Assistance..." -ForegroundColor Cyan; Set-RegDWORD "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" "fAllowToGetHelp" 0 }
function Disable-SMBv1 {
  Write-Host "Disabling SMBv1..." -ForegroundColor Cyan
  try { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null } catch {}
  try { Set-RegDWORD "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" "Start" 4 } catch {}
  try { Set-RegDWORD "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1" 0 } catch {}
}
function Lockdown-NullSessions {
  Write-Host "Locking down null sessions..." -ForegroundColor Cyan
  $srv = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
  Set-RegDWORD $srv "RestrictNullSessAccess" 1
  Set-RegMultiSz $srv "NullSessionShares" @()
  Set-RegMultiSz $srv "NullSessionPipes"  @()
}
function Disable-LLMNR { Write-Host "Disabling LLMNR..." -ForegroundColor Cyan; Set-RegDWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" 0 }
function Disable-NetBIOS {
  Write-Host "Disabling NetBIOS on all interfaces..." -ForegroundColor Cyan
  $base = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
  if (Test-Path $base) { Get-ChildItem $base | ForEach-Object { try { Set-RegDWORD $_.PSPath "NetbiosOptions" 2 } catch {} } }
}
function UAC-Strict { Write-Host "Enabling UAC strict mode..." -ForegroundColor Cyan; $k="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Set-RegDWORD $k "EnableLUA" 1; Set-RegDWORD $k "ConsentPromptBehaviorAdmin" 2 }
function Disable-AutoRunAutoPlay { Write-Host "Disabling AutoRun/AutoPlay..." -ForegroundColor Cyan; Set-RegDWORD "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" 255 }
function Enable-ScreenLock {
  Write-Host "Enabling screen lock for current user..." -ForegroundColor Cyan
  $desk = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
  Ensure-RegistryKey -Path $desk
  Set-RegString $desk "ScreenSaveActive" "1"
  Set-RegString $desk "ScreenSaverIsSecure" "1"
  Set-RegString $desk "ScreenSaveTimeOut" "900"
}
function Configure-DefenderSmartScreen {
  Write-Host "Configuring Defender & SmartScreen..." -ForegroundColor Cyan
  try { Set-MpPreference -DisableRealtimeMonitoring $false -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -ErrorAction SilentlyContinue; Update-MpSignature -ErrorAction SilentlyContinue } catch {}
  $sys = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
  Set-RegDWORD $sys "EnableSmartScreen" 1
  Set-RegString $sys "ShellSmartScreenLevel" "Block"
}
function Harden-SChannel {
  Write-Host "Hardening SChannel/TLS settings..." -ForegroundColor Cyan
  $root = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
  $pairs = @(
    @{Proto="SSL 2.0"; En=0}, @{Proto="SSL 3.0"; En=0},
    @{Proto="TLS 1.0"; En=0}, @{Proto="TLS 1.1"; En=0},
    @{Proto="TLS 1.2"; En=1}
  )
  foreach ($p in $pairs) {
    $server = Join-Path $root ($p.Proto + "\Server")
    $client = Join-Path $root ($p.Proto + "\Client")
    Set-RegDWORD $server "Enabled" $p.En
    Set-RegDWORD $client "Enabled" $p.En
    if ($p.En -eq 1) { $dbd = 0 } else { $dbd = 1 }
    Set-RegDWORD $server "DisabledByDefault" $dbd
    Set-RegDWORD $client "DisabledByDefault" $dbd
  }
}
function Disable-ProblemServices {
  Write-Host "Disabling RemoteRegistry, SSDPSRV, upnphost..." -ForegroundColor Cyan
  foreach ($svc in @("RemoteRegistry","SSDPSRV","upnphost")) {
    try { Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue } catch {}
    try { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue } catch {}
  }
}
function Tune-EventLog { Write-Host "Tuning Security event log..." -ForegroundColor Cyan; $sec="HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security"; Set-RegDWORD $sec "MaxSize" 196608; Set-RegDWORD $sec "Retention" 0 }

# ------------------- NEW: Action/Notification Center enablement -------------------
function Enable-ActionCenter {
  Write-Host "Enabling Action/Notification Center..." -ForegroundColor Cyan

  # Remove policy-based disables
  foreach ($hive in @('HKCU:\Software\Policies\Microsoft\Windows\Explorer','HKLM:\Software\Policies\Microsoft\Windows\Explorer')) {
    if (Test-Path $hive) {
      try { Remove-ItemProperty -Path $hive -Name 'DisableNotificationCenter' -ErrorAction SilentlyContinue } catch {}
    }
  }

  # Ensure toasts are enabled
  $push = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications'
  Ensure-RegistryKey -Path $push
  Set-RegDWORD $push 'ToastEnabled' 1

  # Unhide Security/Action Center icon if hidden by policy
  $pol = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
  if (Test-Path $pol) {
    try { Remove-ItemProperty -Path $pol -Name 'HideSCAHealth' -ErrorAction SilentlyContinue } catch {}
  }

  # Make sure required services are Automatic and running
  foreach ($svc in @('WpnService','wscsvc')) {
    try {
      Set-Service -Name $svc -StartupType Automatic -ErrorAction SilentlyContinue
      Start-Service -Name $svc -ErrorAction SilentlyContinue
    } catch {}
  }
  # Per-user push notification service (name has a suffix)
  Get-Service -Name 'WpnUserService*' -ErrorAction SilentlyContinue | ForEach-Object {
    try {
      Set-Service -Name $_.Name -StartupType Automatic -ErrorAction SilentlyContinue
      Start-Service -Name $_.Name -ErrorAction SilentlyContinue
    } catch {}
  }

  Write-Host "Action/Notification Center enabled. If the icon is still missing, sign out/in or reboot." -ForegroundColor Green
}

# ------------------- Verification -------------------
function Verify-And-Report {
  Write-Host "`n===== Verification =====" -ForegroundColor White
  $dom = (Get-WmiObject Win32_ComputerSystem).PartOfDomain
  Write-Host ("Domain joined: " + ($dom -as [bool])) -ForegroundColor Yellow
  if ($dom) { Write-Host "NOTE: Domain GPOs may override local policy." -ForegroundColor DarkYellow }

  Write-Host "`n-- net accounts --" -ForegroundColor Cyan
  cmd /c net accounts

  Write-Host "`n-- auditpol (summary) --" -ForegroundColor Cyan
  auditpol /get /category:* | Out-String | Write-Host

  Write-Host "`n-- firewall state --" -ForegroundColor Cyan
  netsh advfirewall show allprofiles | Out-String | Write-Host

  Write-Host "`n-- key registry checks --" -ForegroundColor Cyan
  function ShowVal($Path,$Name){ try { $v=(Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $v=$null }; "{0}\{1} : {2}" -f $Path,$Name,$v | Write-Host }
  $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
  foreach ($n in "MinimumPasswordLength","PasswordComplexity","ClearTextPassword","LimitBlankPasswordUse","restrictanonymous","RestrictAnonymousSAM","NoLMHash","ForceGuest","LmCompatibilityLevel","DisableAnonymousSidNameTranslation"){ ShowVal $lsa $n }
  ShowVal "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD"
  ShowVal "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature"
  ShowVal "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature"
  ShowVal "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RestrictNullSessAccess"
  ShowVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast"
  ShowVal "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections"
  ShowVal "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication"
  ShowVal "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" "fAllowToGetHelp"
  ShowVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowUnencryptedTraffic"
  ShowVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"  "AllowUnencryptedTraffic"
  ShowVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen"
  ShowVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "ShellSmartScreenLevel"
  foreach ($p in "SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1","TLS 1.2") {
    ShowVal ("HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\{0}\Server" -f $p) "Enabled"
    ShowVal ("HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\{0}\Client" -f $p) "Enabled"
  }
  foreach ($svc in "RemoteRegistry","SSDPSRV","upnphost","WpnService","wscsvc") { 
    try { ("Service {0} : {1}" -f $svc, (Get-Service $svc -ErrorAction Stop).Status) | Write-Host } catch {} 
  }
  $wpnUser = Get-Service -Name 'WpnUserService*' -ErrorAction SilentlyContinue
  if ($wpnUser) { $wpnUser | ForEach-Object { "Service $($_.Name) : $($_.Status)" | Write-Host } }

  ShowVal "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" "ToastEnabled"
  ShowVal "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "HideSCAHealth"
  ShowVal "HKCU:\Software\Policies\Microsoft\Windows\Explorer" "DisableNotificationCenter"
  ShowVal "HKLM:\Software\Policies\Microsoft\Windows\Explorer" "DisableNotificationCenter"

  ShowVal "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" "MaxSize"
  ShowVal "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" "Retention"
  ShowVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUOptions"
}

# ------------------- GUI (scrollable panel + pinned buttons + presets) -------------------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Show-BaselineGui {
  Assert-Admin
  New-Folder -Path $WorkingDir

  $form = New-Object System.Windows.Forms.Form
  $form.Text = "CyberPatriot Baseline - Select Features"
  $form.Size = New-Object System.Drawing.Size(860, 860)
  $form.MinimumSize = New-Object System.Drawing.Size(860, 860)
  $form.StartPosition = "CenterScreen"

  # Anchor flags (PS 5.1 safe)
  $anchorTopLeftRight    = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
  $anchorBottomLeft      = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
  $anchorBottomLeftRight = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right

  # Scrollable checkbox panel
  $panel = New-Object System.Windows.Forms.Panel
  $panel.Location  = New-Object System.Drawing.Point(10, 10)
  $panel.Size      = New-Object System.Drawing.Size(820, 560)
  $panel.AutoScroll = $true
  $panel.Anchor     = $anchorTopLeftRight
  $form.Controls.Add($panel)

  $y = 10; $x = 10; $width = 780; $rowH = 22
  $cb = @{}

  function NewCB($name,$text,$checked=$true){
    $chk = New-Object System.Windows.Forms.CheckBox
    $chk.Text = $text
    $chk.AutoSize = $false
    $chk.Size = New-Object System.Drawing.Size($width, $rowH)
    $chk.Location = New-Object System.Drawing.Point($x, $script:y)
    $chk.Checked = $checked
    $panel.Controls.Add($chk)
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

  # NEW: Action/Notification Center
  NewCB 'ActionCenter' "Enable Action/Notification Center (unblock policies, enable toasts, start Wpn* and wscsvc)" $true

  # Buttons row
  $btnApply  = New-Object System.Windows.Forms.Button
  $btnVerify = New-Object System.Windows.Forms.Button
  $btnAll    = New-Object System.Windows.Forms.Button
  $btnNone   = New-Object System.Windows.Forms.Button
  $btnGP     = New-Object System.Windows.Forms.Button
  $btnPreset = New-Object System.Windows.Forms.Button

  foreach($b in @($btnApply,$btnVerify,$btnAll,$btnNone,$btnGP,$btnPreset)){ $b.Anchor = $anchorBottomLeft }

  $btnApply.Text  = "Apply Selected"
  $btnVerify.Text = "Verify Only"
  $btnAll.Text    = "Select All"
  $btnNone.Text   = "Deselect All"
  $btnGP.Text     = "gpupdate /force"
  $btnPreset.Text = "Recommended CP Defaults (STRICT)"

  $buttonsTop = 580
  $btnApply.Location  = New-Object System.Drawing.Point(10,  $buttonsTop)
  $btnVerify.Location = New-Object System.Drawing.Point(170, $buttonsTop)
  $btnPreset.Location = New-Object System.Drawing.Point(330, $buttonsTop)
  $btnAll.Location    = New-Object System.Drawing.Point(570, $buttonsTop)
  $btnNone.Location   = New-Object System.Drawing.Point(690, $buttonsTop)
  $buttonsTop2 = $buttonsTop + 40
  $btnGP.Location     = New-Object System.Drawing.Point(10,  $buttonsTop2)

  $btnApply.Size  = New-Object System.Drawing.Size(150,32)
  $btnVerify.Size = New-Object System.Drawing.Size(150,32)
  $btnPreset.Size = New-Object System.Drawing.Size(220,32)
  $btnAll.Size    = New-Object System.Drawing.Size(120,32)
  $btnNone.Size   = New-Object System.Drawing.Size(120,32)
  $btnGP.Size     = New-Object System.Drawing.Size(150,32)

  $form.Controls.Add($btnApply)
  $form.Controls.Add($btnVerify)
  $form.Controls.Add($btnPreset)
  $form.Controls.Add($btnAll)
  $form.Controls.Add($btnNone)
  $form.Controls.Add($btnGP)

  # Output textbox (log)
  $txt = New-Object System.Windows.Forms.TextBox
  $txt.Multiline = $true
  $txt.ReadOnly  = $true
  $txt.ScrollBars = "Vertical"
  $txt.Size = New-Object System.Drawing.Size(820, 200)
  $txt.Location = New-Object System.Drawing.Point(10, 620)
  $txt.Anchor = $anchorBottomLeftRight
  $form.Controls.Add($txt)

  function Log($s){ $line = ("[{0}] {1}" -f (Get-Date).ToString("HH:mm:ss"), $s); $txt.AppendText($line + [Environment]::NewLine); Write-Host $s }

  # Preset selector (STRICT: LLMNR OFF, NetBIOS OFF, ActionCenter ON)
  function Select-Recommended {
    foreach($k in $cb.Keys){ $cb[$k].Checked = $false }
    foreach($k in @(
      # Core
      'PwdLockout','PwdRegistry','SecOptions','WinRM','Audit','Firewall','WU','DisableRDP',
      # Extras commonly scored
      'NTLM','RemoteAssist','SMB1','NullSess','UAC','AutoRun','Defender','TLS','BadServices','EventLog','ScreenLock',
      # STRICT networking
      'LLMNR','NetBIOS',
      # Keep notifications usable
      'ActionCenter'
    )) { $cb[$k].Checked = $true }
  }

  # Button events
  $btnAll.Add_Click({ foreach($k in $cb.Keys){ $cb[$k].Checked = $true } })
  $btnNone.Add_Click({ foreach($k in $cb.Keys){ $cb[$k].Checked = $false } })
  $btnPreset.Add_Click({ Select-Recommended })
  $btnGP.Add_Click({ Log "Running gpupdate /force ..."; Run-GPUpdate; Log "gpupdate complete." })

  $btnApply.Add_Click({
    try {
      Log "Applying selected features..."
      if ($cb.PwdLockout.Checked)   { Log " - Password & Lockout";         Apply-PasswordAndLockoutPolicy }
      if ($cb.PwdRegistry.Checked)  { Log " - Password Registry";          Enforce-PasswordPolicyRegistry }
      if ($cb.SecOptions.Checked)   { Log " - Security Options";           Write-SecurityOptionsRegistry }
      if ($cb.WinRM.Checked)        { Log " - WinRM Harden";               Configure-WinRM-DisallowUnencrypted }
      if ($cb.Audit.Checked)        { Log " - Audit Policy";               Set-AdvancedAuditPolicy }
      if ($cb.Firewall.Checked)     { Log " - Firewall";                   Enable-FirewallAllProfiles }
      if ($cb.DisableRDP.Checked)   { Log " - Disable RDP";                Disable-RemoteDesktop }
      if ($cb.WU.Checked)           { Log " - Windows Update";             Ensure-AutomaticUpdates }

      if ($cb.NTLM.Checked)         { Log " - NTLM hardening";             Harden-NTLM }
      if ($cb.RDP_NLA.Checked)      { Log " - RDP NLA";                    Require-RDP-NLA }
      if ($cb.RemoteAssist.Checked) { Log " - Disable Remote Assistance";  Disable-RemoteAssistance }
      if ($cb.SMB1.Checked)         { Log " - Disable SMBv1";              Disable-SMBv1 }
      if ($cb.NullSess.Checked)     { Log " - Lockdown null sessions";     Lockdown-NullSessions }
      if ($cb.LLMNR.Checked)        { Log " - Disable LLMNR";              Disable-LLMNR }
      if ($cb.NetBIOS.Checked)      { Log " - Disable NetBIOS";            Disable-NetBIOS }
      if ($cb.UAC.Checked)          { Log " - UAC strict";                 UAC-Strict }
      if ($cb.AutoRun.Checked)      { Log " - Disable AutoRun/AutoPlay";   Disable-AutoRunAutoPlay }
      if ($cb.ScreenLock.Checked)   { Log " - Screen lock (current user)"; Enable-ScreenLock }
      if ($cb.Defender.Checked)     { Log " - Defender/SmartScreen";       Configure-DefenderSmartScreen }
      if ($cb.TLS.Checked)          { Log " - SChannel TLS hardening";     Harden-SChannel }
      if ($cb.BadServices.Checked)  { Log " - Disable services";           Disable-ProblemServices }
      if ($cb.EventLog.Checked)     { Log " - Tune Security log";          Tune-EventLog }
      if ($cb.ActionCenter.Checked) { Log " - Enable Action/Notification Center"; Enable-ActionCenter }

      Log "Applying gpupdate (recommended)..."
      Run-GPUpdate
      Log "Done. Some changes may require sign-out/reboot (TLS/SMB/protocols, tray icons)."
      [System.Windows.Forms.MessageBox]::Show("Selected items applied.", "Baseline", 'OK', 'Information') | Out-Null
    } catch {
      [System.Windows.Forms.MessageBox]::Show("Error: $($_.Exception.Message)", "Baseline", 'OK', 'Error') | Out-Null
    }
  })

  $btnVerify.Add_Click({
    try { Log "Verification only..."; Verify-And-Report; Log "Done." }
    catch { [System.Windows.Forms.MessageBox]::Show("Error: $($_.Exception.Message)", "Verify", 'OK', 'Error') | Out-Null }
  })

  $form.Add_Shown({ $form.Activate() })
  [void]$form.ShowDialog()
}

# ------------------- Main -------------------
try { Assert-Admin; New-Folder -Path $WorkingDir; Show-BaselineGui }
catch { Write-Error $_.Exception.Message }
