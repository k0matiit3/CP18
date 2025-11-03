<# 
Sync-LocalUsers-GUI.ps1  (PowerShell 5.1, ISE-friendly)

INPUT OPTIONS
- Paste users (one per line) into the big text box   OR   Load a CSV.
- Accepted formats:
  1) With headers (recommended):
       UserName,FullName,Role,Description,ForceChangeAtNextLogon
       dovahkiin,Dovah Kiin,Administrators,Dragonborn,TRUE
  2) Headerless CSV (username,fullname,role,description):
       lydia,Lydia,Users,Housecarl
  3) Minimal (username,role):
       balgruuf,Administrators

WHAT IT DOES
- Creates missing users (using the Default Password you supply).
- Updates FullName/Description if changed.
- Clears "Password never expires" for managed users.
- If "Force PW change" is ticked per user or globally, triggers change-at-next-logon.
- Enforces group membership for 'Administrators' and 'Users'.
- (Optional) Deletes local users that are not on the list (safe exclusions applied).

SAFE EXCLUSIONS (never deleted)
- Built-ins: Administrator, DefaultAccount, Guest, WDAGUtilityAccount, defaultuser0
- The currently logged-in local account
- Any account that is clearly NOT a local user (e.g., domain SIDs)

NOTES
- Requires: Microsoft.PowerShell.LocalAccounts module (Win 10+/Server 2016+).
- Run as Administrator.
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

  # Try to detect headers
  $first = $lines | Where-Object { $_.Trim() -ne "" } | Select-Object -First 1
  $hasHeader = $false
  if ($first -match "UserName" -or $first -match "FullName" -or $first -match "Role") { $hasHeader = $true }

  $idxStart = 0
  if ($hasHeader) { 
    # Skip header row
    $idxStart = [Array]::IndexOf($lines, $first) + 1
  }

  for ($i = $idxStart; $i -lt $lines.Count; $i++) {
    $line = $lines[$i].Trim()
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    $parts = $line -split ","
    # Pad to 5 fields
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
  $builtIns = @(
    "Administrator","DefaultAccount","Guest","WDAGUtilityAccount","defaultuser0"
  )
  $current = $env:USERNAME
  return ($builtIns + $current) | Sort-Object -Unique
}

function Ensure-LocalGroup([string]$group){ if (-not (Get-LocalGroup -Name $group -ErrorAction SilentlyContinue)) { throw "Local group not found: $group" } }

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
    if ($fn  -and $exists.FullName   -ne $fn)  { $needUpdate = $true }
    if ($desc -and $exists.Description -ne $desc) { $needUpdate = $true }
    if ($needUpdate) {
      Write-Host "  -> Updating FullName/Description for '$u'..." -ForegroundColor Cyan
      if (-not $whatIf) {
        Set-LocalUser -Name $u -FullName $fn -Description $desc | Out-Null
      }
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
    if (-not $whatIf) {
      cmd /c "net user `"$u`" /logonpasswordchg:yes" | Out-Null
    }
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
        try {
          Add-LocalGroupMember -Group $groupName -Member $u -ErrorAction Stop
        } catch {
          Write-Warning "    Failed to add $($u): $($_.Exception.Message)"
        }
      }
    }
  }

  # Remove extra local users (but keep safe exclusions & non-local principals)
  $safe = Get-SafeExclusions
  foreach ($m in $members) {
    # Only local users like COMPUTER\User
    if ($m.Name -notmatch "^[^\\]+\\") { continue }
    $u = ($m.Name -split "\\")[-1]
    if ($safe -contains $u) { continue }
    if ($desiredSet -notcontains $u) {
      Write-Host "  -> Removing '$($m.Name)' FROM '$groupName'" -ForegroundColor DarkYellow
      if (-not $whatIf) {
        try {
          Remove-LocalGroupMember -Group $groupName -Member $m.Name -ErrorAction Stop
        } catch {
          Write-Warning "    Failed to remove $($m.Name): $($_.Exception.Message)"
        }
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
        try {
          Remove-LocalUser -Name $u -ErrorAction Stop
        } catch {
          Write-Warning "     Failed to delete $($u): $($_.Exception.Message)"
        }
      }
    }
  }
}

# ------------------- GUI -------------------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Show-SyncGui {
  Assert-Admin

  $form = New-Object System.Windows.Forms.Form
  $form.Text = "Sync Local Users"
  $form.Size = New-Object System.Drawing.Size(980, 720)
  $form.StartPosition = "CenterScreen"

  $anchorTopLeftRight  = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
  $anchorBottomLeftRight = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
  $anchorBottomLeft = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left

  # Paste box
  $lblPaste = New-Object System.Windows.Forms.Label
  $lblPaste.Text = "Paste users (CSV or lines: UserName,FullName,Role,Description,ForceChangeAtNextLogon):"
  $lblPaste.Location = New-Object System.Drawing.Point(10,10)
  $lblPaste.Size = New-Object System.Drawing.Size(820,20)
  $form.Controls.Add($lblPaste)

  $txtPaste = New-Object System.Windows.Forms.TextBox
  $txtPaste.Multiline = $true
  $txtPaste.ScrollBars = "Vertical"
  $txtPaste.Location = New-Object System.Drawing.Point(10, 30)
  $txtPaste.Size = New-Object System.Drawing.Size(940, 160)
  $txtPaste.Anchor = $anchorTopLeftRight
  $form.Controls.Add($txtPaste)

  # Buttons row 1
  $btnParse = New-Object System.Windows.Forms.Button
  $btnParse.Text = "Parse from Paste"
  $btnParse.Location = New-Object System.Drawing.Point(10, 200)
  $btnParse.Size = New-Object System.Drawing.Size(140,28)
  $form.Controls.Add($btnParse)

  $btnLoadCsv = New-Object System.Windows.Forms.Button
  $btnLoadCsv.Text = "Load CSV..."
  $btnLoadCsv.Location = New-Object System.Drawing.Point(160, 200)
  $btnLoadCsv.Size = New-Object System.Drawing.Size(120,28)
  $form.Controls.Add($btnLoadCsv)

  $btnSaveCsv = New-Object System.Windows.Forms.Button
  $btnSaveCsv.Text = "Export CSV..."
  $btnSaveCsv.Location = New-Object System.Drawing.Point(290, 200)
  $btnSaveCsv.Size = New-Object System.Drawing.Size(120,28)
  $form.Controls.Add($btnSaveCsv)

  # Default password + options
  $lblPwd = New-Object System.Windows.Forms.Label
  $lblPwd.Text = "Default password for NEW accounts:"
  $lblPwd.Location = New-Object System.Drawing.Point(430, 205)
  $lblPwd.Size = New-Object System.Drawing.Size(240,20)
  $form.Controls.Add($lblPwd)

  $txtPwd = New-Object System.Windows.Forms.MaskedTextBox
  $txtPwd.UseSystemPasswordChar = $true
  $txtPwd.Location = New-Object System.Drawing.Point(670, 202)
  $txtPwd.Size = New-Object System.Drawing.Size(160,24)
  $form.Controls.Add($txtPwd)

  $chkForceAll = New-Object System.Windows.Forms.CheckBox
  $chkForceAll.Text = "Force PW change at next logon (all listed users)"
  $chkForceAll.Location = New-Object System.Drawing.Point(10, 235)
  $chkForceAll.Size = New-Object System.Drawing.Size(380,20)
  $form.Controls.Add($chkForceAll)

  $chkDelete = New-Object System.Windows.Forms.CheckBox
  $chkDelete.Text = "Delete local users NOT in the list (safe exclusions apply)"
  $chkDelete.Location = New-Object System.Drawing.Point(400, 235)
  $chkDelete.Size = New-Object System.Drawing.Size(390,20)
  $form.Controls.Add($chkDelete)

  # Grid
  $grid = New-Object System.Windows.Forms.DataGridView
  $grid.Location = New-Object System.Drawing.Point(10, 265)
  $grid.Size = New-Object System.Drawing.Size(940, 330)
  $grid.Anchor = $anchorBottomLeftRight
  $grid.AllowUserToAddRows = $false
  $grid.AutoSizeColumnsMode = 'Fill'
  $form.Controls.Add($grid)

  # Log
  $txtLog = New-Object System.Windows.Forms.TextBox
  $txtLog.Multiline = $true
  $txtLog.ReadOnly  = $true
  $txtLog.ScrollBars = "Vertical"
  $txtLog.Location = New-Object System.Drawing.Point(10, 600)
  $txtLog.Size = New-Object System.Drawing.Size(940, 80)
  $txtLog.Anchor = $anchorBottomLeftRight
  $form.Controls.Add($txtLog)

  function Log($s){
    $txtLog.AppendText( ("[{0}] {1}" -f (Get-Date).ToString("HH:mm:ss"), $s) + [Environment]::NewLine )
    Write-Host $s
  }

  # Build DataTable for grid
  $dt = New-Object System.Data.DataTable
  foreach($col in @("UserName","FullName","Role","Description","ForceChangeAtNextLogon")){
    [void]$dt.Columns.Add($col)
  }
  $grid.DataSource = $dt

  # Role column as dropdown
  $roleCol = New-Object System.Windows.Forms.DataGridViewComboBoxColumn
  $roleCol.HeaderText = "Role"
  $roleCol.DataPropertyName = "Role"
  $roleCol.Items.AddRange(@("Administrators","Users"))
  foreach($c in @($grid.Columns)){}

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

  # Events
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

  # --- APPLY button ---
  $btnApply = New-Object System.Windows.Forms.Button
  $btnApply.Text = "APPLY (Create/Update/Delete/Enforce)"
  $btnApply.Location = New-Object System.Drawing.Point(10, 560)
  $btnApply.Size = New-Object System.Drawing.Size(310,32)
  $btnApply.Anchor = $anchorBottomLeft
  $form.Controls.Add($btnApply)

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

      # Basic validation
      $invalid = $desired | Where-Object { [string]::IsNullOrWhiteSpace($_.UserName) }
      if ($invalid.Count -gt 0) { throw "One or more entries missing UserName." }

      $defaultPwdPlain = "" + $txtPwd.Text
      $defaultPwd = To-SecureStringFromPlain $defaultPwdPlain

      Log "=== Sync starting ==="
      Log "Users in grid: $($desired.Count)"
      Log "Delete non-listed users: $($chkDelete.Checked)"
      Log "Force change at next logon (global): $($chkForceAll.Checked)"

      # Create / update each desired user
      foreach($row in $desired){
        Ensure-User-ExistsOrCreate -row $row -defaultPwd $defaultPwd -forceChangeGlobally:$chkForceAll.Checked -whatIf:$false
      }

      # Enforce Admins & Users group
      Log "Enforcing membership for 'Administrators'..."
      Enforce-GroupMembership -desired $desired -groupName "Administrators" -whatIf:$false
      Log "Enforcing membership for 'Users'..."
      Enforce-GroupMembership -desired $desired -groupName "Users" -whatIf:$false

      # Deletions (if selected)
      if ($chkDelete.Checked) {
        $names = $desired | Select-Object -ExpandProperty UserName -Unique
        Log "Deleting non-listed local users (safe exclusions kept)..."
        Enforce-Deletions -desiredNames $names -whatIf:$false
      }

      Log "=== Sync complete ==="
      [System.Windows.Forms.MessageBox]::Show("Sync complete.", "Sync Local Users", 'OK', 'Information') | Out-Null
    } catch {
      $msg = $_.Exception.Message
      Log "ERROR during apply: $msg"
      [System.Windows.Forms.MessageBox]::Show("Error: $msg", "Sync Local Users", 'OK', 'Error') | Out-Null
    }
  })

  # Show the form
  $form.Add_Shown({ $form.Activate() })
  [void]$form.ShowDialog()
}

# ------------------- Main -------------------
try { Assert-Admin; Show-SyncGui } catch { Write-Error $_.Exception.Message }
