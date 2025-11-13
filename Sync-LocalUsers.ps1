<# 
Sync-LocalUsers.ps1
Strict CyberPatriot-style local account sync with GUI.

Features:
- GUI with:
  - Paste area
  - Load CSV / Save CSV
  - Import current local users
  - Scrollable DataGridView of all parsed users
  - Apply (create/update/delete/enforce)
  - Dry-run (WhatIf) mode
- Enforces:
  - Only specified users exist (optional delete others)
  - Group membership for Administrators / Users
  - Passwords required (no blank password accounts in list)
  - Passwords do not never-expire
  - Optional force-change-at-next-logon

Columns:
  UserName (required)
  FullName
  Role (Administrators / Users)
  Description
  ForceChangeAtNextLogon (True/False/Yes/No/1/0)
#>

[CmdletBinding()]
param()

# ----------------- Helpers -----------------
function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script in an elevated PowerShell session (Run as Administrator)."
  }
}

function Normalize-Role {
  param([string]$Role)
  $r = ("" + $Role).Trim().ToLower()
  switch ($r) {
    'admin'          { 'Administrators' ; break }
    'administrator'  { 'Administrators' ; break }
    'administrators' { 'Administrators' ; break }
    'user'           { 'Users'          ; break }
    'users'          { 'Users'          ; break }
    default          { 'Users' }
  }
}

function Normalize-ForceBool {
  param($Value)
  $s = ("" + $Value).Trim().ToLower()
  return ($s -in @('true','1','yes','y','force','on'))
}

function To-SecureStringFromPlain {
  param([string]$Plain)
  if ([string]::IsNullOrWhiteSpace($Plain)) {
    throw "Default password cannot be empty."
  }
  return (ConvertTo-SecureString -String $Plain -AsPlainText -Force)
}

# ----------------- Parsing desired users -----------------
function Read-DesiredUsersFromCsvFile {
  param(
    [Parameter(Mandatory)][string]$Path
  )
  if (-not (Test-Path $Path)) {
    throw "CSV file '$Path' not found."
  }
  $rows = Import-Csv -Path $Path
  $out = @()
  foreach ($r in $rows) {
    $out += [PSCustomObject]@{
      UserName               = ("" + $r.UserName).Trim()
      FullName               = ("" + $r.FullName).Trim()
      Role                   = Normalize-Role $r.Role
      Description            = ("" + $r.Description).Trim()
      ForceChangeAtNextLogon = Normalize-ForceBool $r.ForceChangeAtNextLogon
    }
  }
  return $out
}

function Read-DesiredUsersFromText {
  param(
    [string]$Text
  )
  if ([string]::IsNullOrWhiteSpace($Text)) { return @() }

  $lines = $Text -split "`r?`n" | Where-Object { $_.Trim() -ne "" }
  if (-not $lines -or $lines.Count -eq 0) { return @() }

  $first = $lines[0]
  if ($first -match 'UserName') {
    # treat as CSV with header
    $csv = $lines -join "`r`n"
    $rows = $csv | ConvertFrom-Csv
    $out = @()
    foreach ($r in $rows) {
      $out += [PSCustomObject]@{
        UserName               = ("" + $r.UserName).Trim()
        FullName               = ("" + $r.FullName).Trim()
        Role                   = Normalize-Role $r.Role
        Description            = ("" + $r.Description).Trim()
        ForceChangeAtNextLogon = Normalize-ForceBool $r.ForceChangeAtNextLogon
      }
    }
    return $out
  }
  else {
    # simple line-based: UserName,FullName,Role,Description,ForceChange
    $out = @()
    foreach ($line in $lines) {
      $parts = $line.Split(",")
      if ($parts.Count -lt 1) { continue }
      $u = $parts[0].Trim()
      if ([string]::IsNullOrWhiteSpace($u)) { continue }

      $full  = if ($parts.Count -gt 1) { $parts[1].Trim() } else { "" }
      $role  = if ($parts.Count -gt 2) { Normalize-Role $parts[2] } else { "Users" }
      $desc  = if ($parts.Count -gt 3) { $parts[3].Trim() } else { "" }
      $force = if ($parts.Count -gt 4) { Normalize-ForceBool $parts[4] } else { $false }

      $out += [PSCustomObject]@{
        UserName               = $u
        FullName               = $full
        Role                   = $role
        Description            = $desc
        ForceChangeAtNextLogon = $force
      }
    }
    return $out
  }
}

# ----------------- Core operations -----------------
function Ensure-User-ExistsOrCreate {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][psobject]$Row,
    [Parameter(Mandatory)][securestring]$DefaultPwd,
    [bool]$ForceChangeGlobally = $false,
    [bool]$WhatIf = $false
  )

  $u     = $Row.UserName
  $full  = $Row.FullName
  $desc  = $Row.Description
  $force = $ForceChangeGlobally -or [bool]$Row.ForceChangeAtNextLogon

  if ([string]::IsNullOrWhiteSpace($u)) {
    throw "UserName cannot be empty."
  }

  $existing = Get-LocalUser -Name $u -ErrorAction SilentlyContinue
  if (-not $existing) {
    if ($WhatIf) {
      Write-Host "Would create local user '$u'" -ForegroundColor Yellow
    }
    else {
      Write-Host "Creating local user '$u'..." -ForegroundColor Cyan
      New-LocalUser -Name $u `
                    -Password $DefaultPwd `
                    -FullName $full `
                    -Description $desc `
                    -PasswordNeverExpires:$false `
                    -UserMayNotChangePassword:$false `
                    -AccountNeverExpires:$false `
                    -ErrorAction Stop | Out-Null
    }
  }
  else {
    if ($WhatIf) {
      Write-Host "Would update local user '$u'" -ForegroundColor Yellow
    }
    else {
      Write-Host "Updating local user '$u'..." -ForegroundColor Cyan
      try {
        Set-LocalUser -Name $u -FullName $full -Description $desc -ErrorAction Stop
      } catch {
        Write-Warning "  !! Failed to update '$u' metadata: $($_.Exception.Message)"
      }

      if ($existing.Enabled -eq $false) {
        try { Enable-LocalUser -Name $u -ErrorAction SilentlyContinue } catch {}
      }

      # Enforce: password required, not "never expires"
      try {
        & net user $u /passwordreq:yes | Out-Null
        & net user $u /expires:never  | Out-Null
      } catch {
        Write-Warning "  !! Failed to enforce password requirements for '$u': $($_.Exception.Message)"
      }
    }
  }

  # Force password change at next logon if requested
  if (-not $WhatIf -and $force) {
    try {
      & net user $u /logonpasswordchg:yes | Out-Null
      Write-Host "  -> Will force password change at next logon for '$u'" -ForegroundColor DarkCyan
    }
    catch {
      Write-Warning "  !! Couldn't set force-change-password for '$u': $($_.Exception.Message)"
    }
  }
}

function Enforce-GroupMembership {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][array]$Desired,
    [Parameter(Mandatory)][string]$GroupName,
    [bool]$WhatIf = $false
  )

  $desiredNames = $Desired |
    Where-Object { $_.Role -eq $GroupName } |
    Select-Object -ExpandProperty UserName -Unique

  if (-not $desiredNames) { $desiredNames = @() }

  $localGroup = Get-LocalGroup -Name $GroupName -ErrorAction SilentlyContinue
  if (-not $localGroup) {
    Write-Warning "Local group '$GroupName' not found."
    return
  }

  $members = Get-LocalGroupMember -Group $GroupName -ErrorAction SilentlyContinue
  $localUserMembers = $members | Where-Object {
    $_.ObjectClass -eq 'User'
  }

  $builtinKeep = @('Administrator','Guest','DefaultAccount','WDAGUtilityAccount')
  $currentUser = [Environment]::UserName

  # Add desired
  foreach ($u in $desiredNames) {
    $present = $localUserMembers | Where-Object { $_.Name -match "^[^\\]+\\$u$" }
    if (-not $present) {
      if ($WhatIf) {
        Write-Host "Would add '$u' to '$GroupName'" -ForegroundColor Yellow
      }
      else {
        try {
          Add-LocalGroupMember -Group $GroupName -Member $u -ErrorAction Stop
          Write-Host "Added '$u' to '$GroupName'" -ForegroundColor Green
        }
        catch {
          Write-Warning "Failed to add '$u' to '$GroupName': $($_.Exception.Message)"
        }
      }
    }
  }

  # Remove extras
  foreach ($m in $localUserMembers) {
    $shortName = $m.Name.Split('\')[-1]
    if ($shortName -in $desiredNames) { continue }
    if ($shortName -in $builtinKeep)  { continue }
    if ($shortName -eq $currentUser)  { continue }

    if ($WhatIf) {
      Write-Host "Would remove '$($m.Name)' from '$GroupName'" -ForegroundColor Yellow
    }
    else {
      try {
        Remove-LocalGroupMember -Group $GroupName -Member $m.Name -ErrorAction Stop
        Write-Host "Removed '$($m.Name)' from '$GroupName'" -ForegroundColor DarkYellow
      }
      catch {
        Write-Warning "Failed to remove '$($m.Name)' from '$GroupName': $($_.Exception.Message)"
      }
    }
  }
}

function Enforce-Deletions {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string[]]$DesiredNames,
    [bool]$WhatIf = $false
  )

  $builtinKeep = @('Administrator','Guest','DefaultAccount','WDAGUtilityAccount')
  $currentUser = [Environment]::UserName

  $locals = Get-LocalUser
  foreach ($u in $locals) {
    $name = $u.Name
    if ($name -in $builtinKeep) { continue }
    if ($name -eq $currentUser) { continue }
    if ($DesiredNames -contains $name) { continue }

    if ($WhatIf) {
      Write-Host "Would DELETE local user '$name'" -ForegroundColor Yellow
    }
    else {
      try {
        Remove-LocalUser -Name $name -ErrorAction Stop
        Write-Host "Deleted local user '$name'" -ForegroundColor Red
      }
      catch {
        Write-Warning "Failed to delete '$name': $($_.Exception.Message)"
      }
    }
  }
}

# ----------------- GUI -----------------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Show-SyncGui {
  Assert-Admin

  $form = New-Object System.Windows.Forms.Form
  $form.Text = "Sync Local Users (CyberPatriot Strict)"
  $form.Size = New-Object System.Drawing.Size(1200, 850)
  $form.MinimumSize = New-Object System.Drawing.Size(1100, 760)
  $form.StartPosition = "CenterScreen"

  # Main split: top (paste+controls), bottom (grid+log)
  $splitMain = New-Object System.Windows.Forms.SplitContainer
  $splitMain.Dock = 'Fill'
  $splitMain.Orientation = 'Horizontal'
  $splitMain.SplitterWidth = 6
  $splitMain.FixedPanel = 'Panel1'
  $splitMain.Panel1MinSize = 220
  $splitMain.Panel2MinSize = 300
  # don't touch SplitterDistance until form is shown
  $form.Controls.Add($splitMain)

  # ---------- TOP panel ----------
  $pTop = $splitMain.Panel1

  $lblPaste = New-Object System.Windows.Forms.Label
  $lblPaste.Text = "Paste users (CSV or lines: UserName,FullName,Role,Description,ForceChangeAtNextLogon):"
  $lblPaste.AutoSize = $true
  $lblPaste.Location = '8,8'
  $pTop.Controls.Add($lblPaste)

  $txtPaste = New-Object System.Windows.Forms.TextBox
  $txtPaste.Multiline = $true
  $txtPaste.ScrollBars = "Vertical"
  $txtPaste.Location = '8,28'
  $txtPaste.Size = New-Object System.Drawing.Size(1160, 130)
  $txtPaste.Anchor = 'Top,Left,Right'
  $pTop.Controls.Add($txtPaste)

  $btnParse   = New-Object System.Windows.Forms.Button
  $btnLoadCsv = New-Object System.Windows.Forms.Button
  $btnSaveCsv = New-Object System.Windows.Forms.Button
  foreach ($b in @($btnParse,$btnLoadCsv,$btnSaveCsv)) { $b.Size = '130,28' }

  $btnParse.Text   = "Parse from Paste"
  $btnLoadCsv.Text = "Load CSV..."
  $btnSaveCsv.Text = "Export CSV..."

  $btnParse.Location   = '8,166'
  $btnLoadCsv.Location = '150,166'
  $btnSaveCsv.Location = '290,166'
  $pTop.Controls.AddRange(@($btnParse,$btnLoadCsv,$btnSaveCsv))

  $lblPwd = New-Object System.Windows.Forms.Label
  $lblPwd.Text = "Default password for NEW accounts:"
  $lblPwd.AutoSize = $true
  $lblPwd.Location = '450,171'
  $pTop.Controls.Add($lblPwd)

  $txtPwd = New-Object System.Windows.Forms.MaskedTextBox
  $txtPwd.UseSystemPasswordChar = $true
  $txtPwd.Location = '700,168'
  $txtPwd.Size = '200,24'
  $pTop.Controls.Add($txtPwd)

  $chkForceAll = New-Object System.Windows.Forms.CheckBox
  $chkForceAll.Text = "Force PW change at next logon (all listed users)"
  $chkForceAll.AutoSize = $true
  $chkForceAll.Location = '8,196'
  $pTop.Controls.Add($chkForceAll)

  $chkDelete = New-Object System.Windows.Forms.CheckBox
  $chkDelete.Text = "Delete local users NOT in the list (safe exclusions apply)"
  $chkDelete.AutoSize = $true
  $chkDelete.Location = '330,196'
  $pTop.Controls.Add($chkDelete)

  # ---------- BOTTOM split: grid + log ----------
  $splitBottom = New-Object System.Windows.Forms.SplitContainer
  $splitBottom.Dock = 'Fill'
  $splitBottom.Orientation = 'Horizontal'
  $splitBottom.FixedPanel = 'Panel2'
  $splitBottom.Panel1MinSize = 150
  $splitBottom.Panel2MinSize = 220
  $splitBottom.SplitterWidth = 6
  # DO NOT set SplitterDistance here; we’ll do it after the form is shown
  $splitMain.Panel2.Controls.Add($splitBottom)

  # ----- Middle: GRID -----
  $grid = New-Object System.Windows.Forms.DataGridView
  $grid.Dock = 'Fill'
  $grid.AllowUserToAddRows = $false
  $grid.AllowUserToOrderColumns = $true
  $grid.AutoSizeColumnsMode = 'Fill'
  $grid.RowHeadersVisible = $false
  $grid.SelectionMode = 'FullRowSelect'
  $grid.MultiSelect = $true
  $grid.ScrollBars = 'Both'
  $grid.AutoGenerateColumns = $true
  $splitBottom.Panel1.Controls.Add($grid)

  # Row count label (top-right over grid)
  $lblCount = New-Object System.Windows.Forms.Label
  $lblCount.AutoSize = $true
  $lblCount.Text = "0 users"
  $lblCount.BackColor = [System.Drawing.Color]::FromArgb(230,230,230)
  $lblCount.Padding = '6,3,6,3'
  $lblCount.Anchor = 'Top,Right'
  $lblCount.Location = New-Object System.Drawing.Point(($grid.Width - 100), 8)
  $grid.Add_SizeChanged({
    $lblCount.Location = New-Object System.Drawing.Point(($grid.Width - 100), 8)
  })
  $splitBottom.Panel1.Controls.Add($lblCount)

  # ----- Bottom: buttons + log -----
  $pBottom = $splitBottom.Panel2

  $btnStrip = New-Object System.Windows.Forms.FlowLayoutPanel
  $btnStrip.Dock = 'Top'
  $btnStrip.Height = 44
  $btnStrip.WrapContents = $false
  $btnStrip.Padding = '6,6,6,6'
  $pBottom.Controls.Add($btnStrip)

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

  $txtLog = New-Object System.Windows.Forms.TextBox
  $txtLog.Multiline = $true
  $txtLog.ReadOnly = $true
  $txtLog.ScrollBars = "Vertical"
  $txtLog.Dock = 'Fill'
  $pBottom.Controls.Add($txtLog)

  function Log([string]$s) {
    $line = "[{0}] {1}" -f (Get-Date).ToString("HH:mm:ss"), $s
    $txtLog.AppendText($line + [Environment]::NewLine)
    Write-Host $s
  }

  # Data backing table
  $dt = New-Object System.Data.DataTable
  foreach ($col in @("UserName","FullName","Role","Description","ForceChangeAtNextLogon")) {
    [void]$dt.Columns.Add($col)
  }
  $grid.DataSource = $dt

  # Replace Role column with dropdown
  $roleCol = New-Object System.Windows.Forms.DataGridViewComboBoxColumn
  $roleCol.HeaderText = "Role"
  $roleCol.DataPropertyName = "Role"
  $roleCol.Items.AddRange(@("Administrators","Users"))

  for ($idx = 0; $idx -lt $grid.Columns.Count; $idx++) {
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

  $updateCount = {
    $lblCount.Text = ("{0} user{1}" -f $dt.Rows.Count, $(if ($dt.Rows.Count -eq 1) { "" } else { "s" }))
  }

  # -------- Event handlers --------
  $btnParse.Add_Click({
    try {
      $dt.Rows.Clear()
      $rows = Read-DesiredUsersFromText $txtPaste.Text
      foreach ($r in $rows) {
        $row = $dt.NewRow()
        $row.UserName = $r.UserName
        $row.FullName = $r.FullName
        $row.Role = $r.Role
        $row.Description = $r.Description
        $row.ForceChangeAtNextLogon = [string]$r.ForceChangeAtNextLogon
        [void]$dt.Rows.Add($row)
      }
      & $updateCount
      if ($grid.Rows.Count -gt 0) { $grid.FirstDisplayedScrollingRowIndex = 0 }
      Log "Parsed $($dt.Rows.Count) user(s) from pasted text."
    }
    catch {
      Log "ERROR parsing: $($_.Exception.Message)"
    }
  })

  $btnLoadCsv.Add_Click({
    if ($ofd.ShowDialog() -eq 'OK') {
      try {
        $dt.Rows.Clear()
        $rows = Read-DesiredUsersFromCsvFile $ofd.FileName
        foreach ($r in $rows) {
          $row = $dt.NewRow()
          $row.UserName = $r.UserName
          $row.FullName = $r.FullName
          $row.Role = $r.Role
          $row.Description = $r.Description
          $row.ForceChangeAtNextLogon = [string]$r.ForceChangeAtNextLogon
          [void]$dt.Rows.Add($row)
        }
        & $updateCount
        if ($grid.Rows.Count -gt 0) { $grid.FirstDisplayedScrollingRowIndex = 0 }
        Log "Loaded $($dt.Rows.Count) user(s) from CSV '$($ofd.FileName)'."
      }
      catch {
        Log "ERROR loading CSV: $($_.Exception.Message)"
      }
    }
  })

  $btnSaveCsv.Add_Click({
    if ($sfd.ShowDialog() -eq 'OK') {
      try {
        $out = @()
        foreach ($r in $dt.Rows) {
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
      }
      catch {
        Log "ERROR exporting CSV: $($_.Exception.Message)"
      }
    }
  })

  $btnImportLocal.Add_Click({
    try {
      $dt.Rows.Clear()
      $locals = Get-LocalUser
      foreach ($u in $locals) {
        $row = $dt.NewRow()
        $row.UserName    = $u.Name
        $row.FullName    = $u.FullName
        $row.Description = $u.Description

        $isAdmin = $false
        try {
          $adms = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
                  Where-Object { $_.ObjectClass -eq 'User' -and $_.Name -match "^[^\\]+\\$($u.Name)$" }
          if ($adms) { $isAdmin = $true }
        }
        catch {}

        $row.Role = if ($isAdmin) { "Administrators" } else { "Users" }
        $row.ForceChangeAtNextLogon = "False"
        [void]$dt.Rows.Add($row)
      }
      & $updateCount
      if ($grid.Rows.Count -gt 0) { $grid.FirstDisplayedScrollingRowIndex = 0 }
      Log "Imported $($dt.Rows.Count) current local user(s) into grid."
    }
    catch {
      Log "ERROR importing local users: $($_.Exception.Message)"
    }
  })

  $btnApply.Add_Click({
    try {
      $desired = @()
      foreach ($r in $dt.Rows) {
        $desired += [PSCustomObject]@{
          UserName               = ("" + $r.UserName).Trim()
          FullName               = ("" + $r.FullName).Trim()
          Role                   = Normalize-Role ("" + $r.Role)
          Description            = ("" + $r.Description).Trim()
          ForceChangeAtNextLogon = Normalize-ForceBool ("" + $r.ForceChangeAtNextLogon)
        }
      }

      if (-not $desired -or $desired.Count -eq 0) {
        throw "No users in grid. Nothing to apply."
      }

      if ($desired | Where-Object { [string]::IsNullOrWhiteSpace($_.UserName) }) {
        throw "One or more entries are missing UserName."
      }

      $defaultPwdPlain = "" + $txtPwd.Text
      $defaultPwd = To-SecureStringFromPlain $defaultPwdPlain
      $whatIf = $btnWhatIf.Checked

      Log "=== Sync starting ==="
      Log "Users in grid: $($desired.Count)"
      Log "Delete non-listed users: $($chkDelete.Checked)"
      Log "Force change at next logon (global): $($chkForceAll.Checked)"
      Log "WhatIf (dry-run): $whatIf"

      foreach ($row in $desired) {
        Ensure-User-ExistsOrCreate -Row $row -DefaultPwd $defaultPwd -ForceChangeGlobally:$chkForceAll.Checked -WhatIf:$whatIf
      }

      Log "Enforcing membership for 'Administrators'..."
      Enforce-GroupMembership -Desired $desired -GroupName "Administrators" -WhatIf:$whatIf

      Log "Enforcing membership for 'Users'..."
      Enforce-GroupMembership -Desired $desired -GroupName "Users" -WhatIf:$whatIf

      if ($chkDelete.Checked) {
        $names = $desired | Select-Object -ExpandProperty UserName -Unique
        Log "Deleting local users not in list..."
        Enforce-Deletions -DesiredNames $names -WhatIf:$whatIf
      }

      Log "=== Sync complete ==="
      if ($whatIf) {
        [System.Windows.Forms.MessageBox]::Show("Dry-run finished. No changes were made.", "Sync Local Users", 'OK', 'Information') | Out-Null
      }
      else {
        [System.Windows.Forms.MessageBox]::Show("Sync complete.", "Sync Local Users", 'OK', 'Information') | Out-Null
      }
    }
    catch {
      $msg = $_.Exception.Message
      Log "ERROR during apply: $msg"
      [System.Windows.Forms.MessageBox]::Show("Error: $msg", "Sync Local Users", 'OK', 'Error') | Out-Null
    }
  })

  # After form is shown, we can safely set splitter distances
  $form.Add_Shown({
    # ~25% top, 75% bottom for main
    $splitMain.SplitterDistance = [int]($form.ClientSize.Height * 0.26)
    # ~60% grid, 40% log
    $splitBottom.SplitterDistance = [int]($splitMain.Panel2.ClientSize.Height * 0.6)
    $form.Activate()
  })

  [void]$form.ShowDialog()
}

# ----------------- Main -----------------
try {
  Assert-Admin
  Show-SyncGui
}
catch {
  Write-Error $_.Exception.Message
}
