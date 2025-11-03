<# 
Sync-LocalUsers-GUI.ps1  (PowerShell 5.1, ISE-friendly)

FEATURES
- Paste users or Load CSV into grid (UserName, FullName, Role, Description, ForceChangeAtNextLogon).
- Toggle each user's target group: Administrators or Users.
- Default password for NEW accounts.
- Enforce password expiration: clears "Password never expires" and can force change at next logon (per-user or global).
- Enforce group membership for Administrators and Users.
- Optional deletion of local users not in the list (safe exclusions applied).
- WhatIf (dry-run) switch.
- Import current local users into the grid (to start from what's on the box).

SAFE EXCLUSIONS (never deleted)
- Administrator, DefaultAccount, Guest, WDAGUtilityAccount, defaultuser0
- The currently logged-in local account

REQUIREMENTS
- Run as Administrator.
- Windows 10+/Server 2016+ (LocalAccounts module available).
#>

[CmdletBinding()]
param()

# ------------------- Helpers -------------------
function Assert-Admin {
  $id=[Security.Principal.WindowsIdentity]::GetCurrent()
  $p =New-Object Security.Principal.WindowsPrincipal($id)
  if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw "Run this script in an elevated PowerShell session (Run as Administrator)."
  }
}

function To-SecureStringFromPlain([string]$s){
  $ss = New-Object System.Security.SecureString
  if ([string]::IsNullOrWhiteSpace($s)) { return $ss }
  $s.ToCharArray() | ForEach-Object { $ss.AppendChar($_) }
  return $ss
}

function Normalize-Role([string]$role){
  if ([string]::IsNullOrWhiteSpace($role)) { return "Users" }
  $r = $role.Trim().ToLower()
  if ($r -in @("admin","admins","administrator","administrators")) { return "Administrators" }
  return "Users"
}

function Read-DesiredUsersFromText([string]$text){
  $list = @()
  if ([string]::IsNullOrWhiteSpace($text)) { return $list }

  $lines = $text -split "(`r`n|`n|`r)"
  if ($lines.Count -eq 0) { return $list }

  # Detect headers
  $first = $lines | Where-Object { $_.Trim() -ne "" } | Select-Object -First 1
  $hasHeader = $false
  if ($first -match "UserName" -or $first -match "FullName" -or $first -match "Role") { $hasHeader = $true }

  $idxStart = 0
  if ($hasHeader) { $idxStart = [Array]::IndexOf($lines, $first) + 1 }

  for ($i = $idxStart; $i -lt $lines.Count; $i++) {
    $line = $lines[$i].Trim()
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    $parts = $line -split ","
    while ($parts.Count -lt 5) { $parts += "" }

    $u   = $parts[0].Trim()
    $fn  = $parts[1].Trim()
    $rol = Normalize-Role($parts[2])
    $des = $parts[3].Trim()
    $fc  = $parts[4].Trim()

    if ([string]::IsNullOrWhiteSpace($u)) { continue }

    $force = $false
    if ($fc) {
      $fcLower = $fc.ToLower()
      if ($fcLower -in @("true","1","yes","y")) { $force = $true }
    }

    $list += [PSCustomObject]@{
      UserName               = $u
      FullName               = $fn
      Description            = $des
      Role                   = $rol
      ForceChangeAtNextLogon = $force
    }
  }
  return $list
}

function Read-DesiredUsersFromCsvFile([string]$path){
  if (-not (Test-Path $path)) { throw "File not found: $path" }
  $rows = Import-Csv -Path $path
  $list = @()
  foreach ($row in $rows) {
    $u   = ("" + $row.UserName).Trim()
    if ([string]::IsNullOrWhiteSpace($u)) { continue }
    $fn  = ("" + $row.FullName).Trim()
    $des = ("" + $row.Description).Trim()
    $rol = Normalize-Role(("" + $row.Role))
    $fc  = $false
    if ($row.PSObject.Properties.Name -contains 'ForceChangeAtNextLogon') {
      $v = ("" + $row.ForceChangeAtNextLogon).Trim().ToLower()
      if ($v -in @("true","1","yes","y")) { $fc = $true }
    }
    $list += [PSCustomObject]@{
      UserName               = $u
      FullName               = $fn
      Description            = $des
      Role                   = $rol
      ForceChangeAtNextLogon = $fc
    }
  }
  return $list
}

function Get-SafeExclusions {
  $builtIns = @("Administrator","DefaultAccount","Guest","WDAGUtilityAccount","defaultuser0")
  $current  = $env:USERNAME
  return ($builtIns + $current) | Sort-Object -Unique
}

function Ensure-LocalGroup([string]$group){
  if (-not (Get-LocalGroup -Name $group -ErrorAction SilentlyContinue)) {
    throw "Local group not found: $group"
  }
}

function Ensure-User-ExistsOrCreate($row, [SecureString]$defaultPwd, [bool]$forceChangeGlobally, [bool]$whatIf=$false) {
  $u    = $row.UserName
  $fn   = $row.FullName
  $desc = $row.Description
  $exists = Get-LocalUser -Name $u -ErrorAction SilentlyContinue

  if (-not $exists) {
    if ($defaultPwd.Length -eq 0) { throw "No default password provided for new user '$u'." }
    Write-Host "  -> Creating local user '$u'..." -ForegroundColor Cyan
    if (-not $whatIf) {
      New-LocalUser -Name $u -Password $defaultPwd -FullName $fn -Description $desc -PasswordNeverExpires:$false | Out-Null
    }
  } else {
    # Update profile fields if changed
    $needUpdate = $false
    if ($fn  -and $exists.FullName    -ne $fn)  { $needUpdate = $true }
    if ($desc -and $exists.Description -ne $desc) { $needUpdate = $true }
    if ($needUpdate) {
      Write-Host "  -> Updating FullName/Description for '$u'..." -ForegroundColor Cyan
      if (-not $whatIf) { Set-LocalUser -Name $u -FullName $fn -Description $desc | Out-Null }
    }
    # Always clear "password never expires"
    if ($exists.PasswordNeverExpires) {
      Write-Host "  -> Clearing 'Password never expires' for '$u'..." -ForegroundColor Cyan
      if (-not $whatIf) { Set-LocalUser -Name $u -PasswordNeverExpires:$false | Out-Null }
    }
  }

  # Enforce force-change-at-next-logon if requested (row or global)
  $force = $false
  if ($row.ForceChangeAtNextLogon -or $forceChangeGlobally) { $force = $true }
  if ($force) {
    Write-Host "  -> Forcing '$u' to change password at next logon..." -ForegroundColor Yellow
    if (-not $whatIf) { cmd /c "net user `"$u`" /logonpasswordchg:yes" | Out-Null }
  }
}

function Enforce-GroupMembership($desired, [string]$groupName, [bool]$whatIf=$false) {
  Ensure-LocalGroup $groupName
  $members = Get-LocalGroupMember -Group $groupName -ErrorAction SilentlyContinue | Where-Object { $_.ObjectClass -eq 'User' }
  $desiredSet = $desired | Where-Object { $_.Role -eq $groupName } | Select-Object -ExpandProperty UserName -Unique

  # Add missing
  foreach ($u in $desiredSet) {
    $present = $false
    foreach ($m in $members) {
      if ($m.Name -match "^[^\\]+\\$u$") { $present = $true; break }
    }
    if (-not $present) {
      Write-Host "  -> Ensuring '$u' IN '$groupName'" -ForegroundColor Green
      if (-not $whatIf) {
        try { Add-LocalGroupMember -Group $groupName -Member $u -ErrorAction Stop }
        catch { Write-Warning "    Failed to add $($u): $($_.Exception.Message)" }
      }
    }
  }

  # Remove extra local users (but keep safe exclusions & non-local principals)
  $safe = Get-SafeExclusions
  foreach ($m in $members) {
    if ($m.Name -notmatch "^[^\\]+\\") { continue } # ignore domain/unknown principals
    $u = ($m.Name -split "\\")[-1]
    if ($safe -contains $u) { continue }
    if ($desiredSet -notcontains $u) {
      Write-Host "  -> Removing '$($m.Name)' FROM '$groupName'" -ForegroundColor DarkYellow
      if (-not $whatIf) {
        try { Remove-LocalGroupMember -Group $groupName -Member $m.Name -ErrorAction Stop }
        catch { Write-Warning "    Failed to remove $($m.Name): $($_.Exception.Message)" }
      }
    }
  }
}

function Enforce-Deletions($desiredNames, [bool]$whatIf=$false){
  $safe = Get-SafeExclusions
  $all = Get-LocalUser
  foreach ($acct in $all) {
    $u = $acct.Name
    if ($safe -contains $u) { continue }
    if ($desiredNames -notcontains $u) {
      Write-Host "  -> Deleting local user '$u' (not on list)..." -ForegroundColor Magenta
      if (-not $whatIf) {
        try { Remove-LocalUser -Name $u -ErrorAction Stop }
        catch { Write-Warning "     Failed to delete $($u): $($_.Exception.Message)" }
      }
    }
  }
}

# ------------------- GUI (Docked layout so buttons are always visible) -------------------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Show-SyncGui {
  Assert-Admin

  $form = New-Object System.Windows.Forms.Form
  $form.Text = "Sync Local Users"
  $form.Size = New-Object System.Drawing.Size(1100, 800)
  $form.MinimumSize = New-Object System.Drawing.Size(1000, 720)
  $form.StartPosition = "CenterScreen"

  $dockFill   = [System.Windows.Forms.DockStyle]::Fill
  $dockTop    = [System.Windows.Forms.DockStyle]::Top
  $dockBottom = [System.Windows.Forms.DockStyle]::Bottom
  $anchorBLR  = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right

  # ===== Top panel (paste + controls) =====
  $top = New-Object System.Windows.Forms.Panel
  $top.Dock = $dockTop
  $top.Height = 230
  $form.Controls.Add($top)

  $lblPaste = New-Object System.Windows.Forms.Label
  $lblPaste.Text = "Paste users (CSV or lines: UserName,FullName,Role,Description,ForceChangeAtNextLogon):"
  $lblPaste.AutoSize = $true
  $lblPaste.Location = New-Object System.Drawing.Point(8,8)
  $top.Controls.Add($lblPaste)

  $txtPaste = New-Object System.Windows.Forms.TextBox
  $txtPaste.Multiline = $true
  $txtPaste.ScrollBars = "Vertical"
  $txtPaste.Location = New-Object System.Drawing.Point(8, 28)
  $txtPaste.Size = New-Object System.Drawing.Size(1060, 140)
  $txtPaste.Anchor = $anchorBLR -bor [System.Windows.Forms.AnchorStyles]::Top
  $top.Controls.Add($txtPaste)

  $btnParse   = New-Object System.Windows.Forms.Button
  $btnLoadCsv = New-Object System.Windows.Forms.Button
  $btnSaveCsv = New-Object System.Windows.Forms.Button

  $btnParse.Text   = "Parse from Paste"
  $btnLoadCsv.Text = "Load CSV..."
  $btnSaveCsv.Text = "Export CSV..."

  $btnParse.Location   = New-Object System.Drawing.Point(8, 176)
  $btnLoadCsv.Location = New-Object System.Drawing.Point(150, 176)
  $btnSaveCsv.Location = New-Object System.Drawing.Point(270, 176)

  foreach($b in @($btnParse,$btnLoadCsv,$btnSaveCsv)){ $b.Size = New-Object System.Drawing.Size(130,28); $top.Controls.Add($b) }

  $lblPwd = New-Object System.Windows.Forms.Label
  $lblPwd.Text = "Default password for NEW accounts:"
  $lblPwd.AutoSize = $true
  $lblPwd.Location = New-Object System.Drawing.Point(430,176)
  $top.Controls.Add($lblPwd)

  $txtPwd = New-Object System.Windows.Forms.MaskedTextBox
  $txtPwd.UseSystemPasswordChar = $true
  $txtPwd.Location = New-Object System.Drawing.Point(670,173)
  $txtPwd.Size = New-Object System.Drawing.Size(180,24)
  $top.Controls.Add($txtPwd)

  $chkForceAll = New-Object System.Windows.Forms.CheckBox
  $chkForceAll.Text = "Force PW change at next logon (all listed users)"
  $chkForceAll.AutoSize = $true
  $chkForceAll.Location = New-Object System.Drawing.Point(8, 206)
  $top.Controls.Add($chkForceAll)

  $chkDelete = New-Object System.Windows.Forms.CheckBox
  $chkDelete.Text = "Delete local users NOT in the list (safe exclusions apply)"
  $chkDelete.AutoSize = $true
  $chkDelete.Location = New-Object System.Drawing.Point(330, 206)
  $top.Controls.Add($chkDelete)

  # ===== Middle: grid (fills remaining space) =====
  $grid = New-Object System.Windows.Forms.DataGridView
  $grid.Dock = $dockFill
  $grid.AllowUserToAddRows = $false
  $grid.AutoSizeColumnsMode = 'Fill'
  $form.Controls.Add($grid)

  # ===== Bottom panel (buttons + log) =====
  $bottom = New-Object System.Windows.Forms.Panel
  $bottom.Dock = $dockBottom
  $bottom.Height = 180
  $form.Controls.Add($bottom)

  # Buttons strip (top of bottom panel)
  $btnStrip = New-Object System.Windows.Forms.FlowLayoutPanel
  $btnStrip.Dock = $dockTop
  $btnStrip.Height = 42
  $btnStrip.WrapContents = $false
  $btnStrip.AutoScroll = $false
  $btnStrip.Padding = New-Object System.Windows.Forms.Padding(6,6,6,6)
  $bottom.Controls.Add($btnStrip)

  $btnApply = New-Object System.Windows.Forms.Button
  $btnApply.Text = "APPLY (Create/Update/Delete/Enforce)"
  $btnApply.Width = 300

  $btnImportLocal = New-Object System.Windows.Forms.Button
  $btnImportLocal.Text = "Import Current Local Users → Grid"
  $btnImportLocal.Width = 240

  $btnWhatIf = New-Object System.Windows.Forms.CheckBox
  $btnWhatIf.Text = "Dry-run (WhatIf)"
  $btnWhatIf.AutoSize = $true
  $btnWhatIf.Margin = '12,10,12,0'

  $btnStrip.Controls.AddRange(@($btnApply,$btnImportLocal,$btnWhatIf))

  # Log (fills rest of bottom panel)
  $txtLog = New-Object System.Windows.Forms.TextBox
  $txtLog.Multiline = $true
  $txtLog.ReadOnly = $true
  $txtLog.ScrollBars = "Vertical"
  $txtLog.Dock = $dockFill
  $bottom.Controls.Add($txtLog)

  function Log($s){
    $txtLog.AppendText( ("[{0}] {1}" -f (Get-Date).ToString("HH:mm:ss"), $s) + [Environment]::NewLine )
    Write-Host $s
  }

  # ===== Data backing for grid =====
  $dt = New-Object System.Data.DataTable
  foreach($col in @("UserName","FullName","Role","Description","ForceChangeAtNextLogon")){
    [void]$dt.Columns.Add($col)
  }
  $grid.DataSource = $dt

  # Replace 'Role' with dropdown
  $roleCol = New-Object System.Windows.Forms.DataGridViewComboBoxColumn
  $roleCol.HeaderText = "Role"
  $roleCol.DataPropertyName = "Role"
  $roleCol.Items.AddRange(@("Administrators","Users"))

  for($idx=0; $idx -lt $grid.Columns.Count; $idx++){
    if ($grid.Columns[$idx].HeaderText -eq "Role") {
      $grid.Columns.RemoveAt($idx)
      $grid.Columns.Insert($idx, $roleCol)
      break
    }
  }

  # File dialogs
  $ofd = New-Object System.Windows.Forms.OpenFileDialog
  $ofd.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
  $sfd = New-Object System.Windows.Forms.SaveFileDialog
  $sfd.Filter = "CSV files (*.csv)|*.csv"

  # ===== Event wiring =====
  $btnParse.Add_Click({
    try{
      $dt.Rows.Clear()
      $rows = Read-DesiredUsersFromText $txtPaste.Text
      foreach($r in $rows){
        $row = $dt.NewRow()
        $row.UserName = $r.UserName
        $row.FullName = $r.FullName
        $row.Role = $r.Role
        $row.Description = $r.Description
        $row.ForceChangeAtNextLogon = [string]$r.ForceChangeAtNextLogon
        $dt.Rows.Add($row)
      }
      Log "Parsed $($dt.Rows.Count) user(s) from pasted text."
    } catch { Log "ERROR parsing: $($_.Exception.Message)" }
  })

  $btnLoadCsv.Add_Click({
    if ($ofd.ShowDialog() -eq 'OK') {
      try {
        $dt.Rows.Clear()
        $rows = Read-DesiredUsersFromCsvFile $ofd.FileName
        foreach($r in $rows){
          $row = $dt.NewRow()
          $row.UserName = $r.UserName
          $row.FullName = $r.FullName
          $row.Role = $r.Role
          $row.Description = $r.Description
          $row.ForceChangeAtNextLogon = [string]$r.ForceChangeAtNextLogon
          $dt.Rows.Add($row)
        }
        Log "Loaded $($dt.Rows.Count) user(s) from CSV."
      } catch { Log "ERROR loading CSV: $($_.Exception.Message)" }
    }
  })

  $btnSaveCsv.Add_Click({
    if ($sfd.ShowDialog() -eq 'OK') {
      try {
        $out = @()
        foreach($r in $dt.Rows){
          $out += [PSCustomObject]@{
            UserName               = "" + $r.UserName
            FullName               = "" + $r.FullName
            Role                   = "" + $r.Role
            Description            = "" + $r.Description
            ForceChangeAtNextLogon = "" + $r.ForceChangeAtNextLogon
          }
        }
        $out | Export-Csv -NoTypeInformation -Path $sfd.FileName -Encoding UTF8
        Log "Exported CSV to $($sfd.FileName)."
      } catch { Log "ERROR exporting CSV: $($_.Exception.Message)" }
    }
  })

  # Import current local users into the grid
  $btnImportLocal.Add_Click({
    try{
      $dt.Rows.Clear()
      $locals = Get-LocalUser
      foreach($u in $locals){
        $row = $dt.NewRow()
        $row.UserName = $u.Name
        $row.FullName = $u.FullName
        $row.Description = $u.Description
        # Determine role from current Admins membership
        $isAdmin = $false
        try {
          $adms = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Where-Object {
            $_.ObjectClass -eq 'User' -and $_.Name -match "^[^\\]+\\$($u.Name)$"
          }
          if ($adms) { $isAdmin = $true }
        } catch {}
        $row.Role = if ($isAdmin) { "Administrators" } else { "Users" }
        $row.ForceChangeAtNextLogon = "False"
        $dt.Rows.Add($row)
      }
      Log "Imported $($dt.Rows.Count) current local user(s) into grid."
    } catch { Log "ERROR importing local users: $($_.Exception.Message)" }
  })

  $btnApply.Add_Click({
    try{
      $desired = @()
      foreach($r in $dt.Rows){
        $desired += [PSCustomObject]@{
          UserName               = ("" + $r.UserName).Trim()
          FullName               = ("" + $r.FullName).Trim()
          Role                   = Normalize-Role(("" + $r.Role))
          Description            = ("" + $r.Description).Trim()
          ForceChangeAtNextLogon = (("" + $r.ForceChangeAtNextLogon).Trim().ToLower() -in @("true","1","yes","y"))
        }
      }
      $invalid = $desired | Where-Object { [string]::IsNullOrWhiteSpace($_.UserName) }
      if ($invalid.Count -gt 0) { throw "One or more entries are missing UserName." }

      $defaultPwdPlain = "" + $txtPwd.Text
      $defaultPwd = To-SecureStringFromPlain $defaultPwdPlain
      $whatIf = $btnWhatIf.Checked

      Log "=== Sync starting ==="
      Log "Users in grid: $($desired.Count)"
      Log "Delete non-listed users: $($chkDelete.Checked)"
      Log "Force change at next logon (global): $($chkForceAll.Checked)"
      Log "WhatIf: $whatIf"

      foreach($row in $desired){
        Ensure-User-ExistsOrCreate -row $row -defaultPwd $defaultPwd -forceChangeGlobally:$chkForceAll.Checked -whatIf:$whatIf
      }

      Log "Enforcing membership for 'Administrators'..."
      Enforce-GroupMembership -desired $desired -groupName "Administrators" -whatIf:$whatIf
      Log "Enforcing membership for 'Users'..."
      Enforce-GroupMembership -desired $desired -groupName "Users" -whatIf:$whatIf

      if ($chkDelete.Checked) {
        $names = $desired | Select-Object -ExpandProperty UserName -Unique
        Log "Deleting non-listed local users (safe exclusions kept)..."
        Enforce-Deletions -desiredNames $names -whatIf:$whatIf
      }

      Log "=== Sync complete ==="
      if (-not $whatIf) {
        [System.Windows.Forms.MessageBox]::Show("Sync complete.", "Sync Local Users", 'OK', 'Information') | Out-Null
      } else {
        [System.Windows.Forms.MessageBox]::Show("Dry-run finished. No changes were made.", "Sync Local Users", 'OK', 'Information') | Out-Null
      }
    } catch {
      $msg = $_.Exception.Message
      Log "ERROR during apply: $msg"
      [System.Windows.Forms.MessageBox]::Show("Error: $msg", "Sync Local Users", 'OK', 'Error') | Out-Null
    }
  })

  $form.Add_Shown({ $form.Activate() })
  [void]$form.ShowDialog()
}

# ------------------- Main -------------------
try { Assert-Admin; Show-SyncGui } catch { Write-Error $_.Exception.Message }
