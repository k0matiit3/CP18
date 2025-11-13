<# 
Sync-LocalUsers.ps1
CyberPatriot-hardened edition with GUI.

Features:
- GUI for managing local users from pasted text or CSV.
- Users have Role: Administrators or Users.
- Creates missing accounts (with a single default password for NEW users).
- Updates FullName/Description for existing accounts.
- Enforces group membership for Administrators and Users.
- Optionally deletes local users not present in the list (with safe exclusions).
- Enforces password expiration (PasswordNeverExpires = $false) for managed users.
- Optional per-user or global “force password change at next logon”.

STRICT/HARDENED:
- Validates usernames (no blanks, no backslashes, etc.).
- Never deletes built-in/special accounts or the currently logged-on account.
- Never removes built-in Administrator / current user from Administrators.
#>

[CmdletBinding()]
param(
  [string]$WorkingDir = "C:\SyncLocalUsers"
)

# -------------------- Basic helpers --------------------
function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script in an elevated PowerShell session (Run as Administrator)."
  }
}

function New-Folder {
  param([string]$Path)
  if (-not (Test-Path $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function To-SecureStringFromPlain {
  param([string]$Plain)
  if ([string]::IsNullOrWhiteSpace($Plain)) {
    throw "Default password cannot be blank. Please provide a strong password."
  }
  return (ConvertTo-SecureString -String $Plain -AsPlainText -Force)
}

# Make sure LocalAccounts module is available
function Import-LocalAccountsModule {
  try {
    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop
  } catch {
    # On some builds it auto-loads when calling Get-LocalUser; ignore
  }
}

# -------------------- Username & role validation --------------------
function Validate-UserName {
  param([string]$UserName)
  if ([string]::IsNullOrWhiteSpace($UserName)) {
    throw "UserName cannot be blank."
  }
  if ($UserName.Length -gt 20) {
    throw "UserName '$UserName' is too long (max 20 characters recommended)."
  }
  if ($UserName -match '[\\/:*?"<>|]') {
    throw "UserName '$UserName' contains invalid characters (\ / : * ? "" < > |)."
  }
  if ($UserName -match '\s') {
    throw "UserName '$UserName' contains whitespace. Use a name without spaces."
  }
}

function Normalize-Role {
  param([string]$Role)
  $r = ("" + $Role).Trim()
  if ([string]::IsNullOrWhiteSpace($r)) { return "Users" }
  switch -Regex ($r.ToLower()) {
    '^(admin|admins|administrator|administrators)$' { return "Administrators" }
    default { return "Users" }
  }
}

function Normalize-ForceBool {
  param([string]$Value)
  $v = ("" + $Value).Trim().ToLower()
  if ($v -in @("true","1","yes","y")) { return $true }
  return $false
}

# -------------------- System/built-in account protection --------------------
function Is-SystemUserName {
  param([string]$UserName)
  if (-not $UserName) { return $true }
  $u = $UserName.ToLower()
  switch ($u) {
    "administrator"      { return $true }
    "guest"              { return $true }
    "defaultaccount"     { return $true }
    "wdagutilityaccount" { return $true }
    "defaultuser0"       { return $true }
    default              { return $false }
  }
}

# -------------------- Input parsing (CSV / text) --------------------
function Map-RowToUserObject {
  param([object]$Row)

  $userName  = ("" + $Row.UserName).Trim()
  $fullName  = ("" + $Row.FullName).Trim()
  $role      = Normalize-Role ("" + $Row.Role)
  $desc      = ("" + $Row.Description).Trim()
  $forceFlag = Normalize-ForceBool ("" + $Row.ForceChangeAtNextLogon)

  Validate-UserName -UserName $userName

  return [PSCustomObject]@{
    UserName               = $userName
    FullName               = $fullName
    Role                   = $role
    Description            = $desc
    ForceChangeAtNextLogon = $forceFlag
  }
}

function Read-DesiredUsersFromCsvFile {
  param([string]$CsvPath)

  if (-not (Test-Path $CsvPath)) {
    throw "CSV file '$CsvPath' not found."
  }

  $raw = Import-Csv -Path $CsvPath
  $out = @()

  foreach ($row in $raw) {
    if (-not $row.UserName) { continue }
    $out += Map-RowToUserObject -Row $row
  }

  # Detect duplicates
  $dups = $out | Group-Object UserName | Where-Object { $_.Count -gt 1 }
  if ($dups) {
    $names = ($dups | Select-Object -ExpandProperty Name) -join ", "
    throw "Duplicate UserName(s) in CSV: $names"
  }

  return $out
}

function Read-DesiredUsersFromText {
  param([string]$Text)

  $t = $Text
  if ([string]::IsNullOrWhiteSpace($t)) {
    return @()
  }
  $t = $t.Trim()

  # Try CSV parse first if it looks like it has headers
  if ($t -match 'UserName') {
    try {
      $raw = $t | ConvertFrom-Csv -ErrorAction Stop
      $out = @()
      foreach ($row in $raw) {
        if (-not $row.UserName) { continue }
        $out += Map-RowToUserObject -Row $row
      }
      if ($out.Count -gt 0) { return $out }
    } catch {
      # Fall through to manual parsing
    }
  }

  # Manual: one user per line, simple CSV-ish: UserName,FullName,Role,Description,ForceChangeAtNextLogon
  $out2 = @()
  $lines = $t -split "`r?`n"
  foreach ($line in $lines) {
    $trim = $line.Trim()
    if (-not $trim) { continue }
    if ($trim.StartsWith("#")) { continue }

    $parts = $trim -split ","
    # pad to 5
    while ($parts.Count -lt 5) { $parts += "" }

    $obj = [PSCustomObject]@{
      UserName               = $parts[0]
      FullName               = $parts[1]
      Role                   = $parts[2]
      Description            = $parts[3]
      ForceChangeAtNextLogon = $parts[4]
    }

    $out2 += Map-RowToUserObject -Row $obj
  }

  # Check duplicates
  $dups = $out2 | Group-Object UserName | Where-Object { $_.Count -gt 1 }
  if ($dups) {
    $names = ($dups | Select-Object -ExpandProperty Name) -join ", "
    throw "Duplicate UserName(s) in pasted text: $names"
  }

  return $out2
}

# -------------------- Core sync logic --------------------
function Ensure-User-ExistsOrCreate {
  param(
    [Parameter(Mandatory)][pscustomobject]$row,
    [Parameter(Mandatory)][System.Security.SecureString]$defaultPwd,
    [bool]$forceChangeGlobally,
    [bool]$whatIf
  )

  $u    = $row.UserName
  $full = $row.FullName
  $desc = $row.Description
  $role = $row.Role
  $forceThisUser = $forceChangeGlobally -or [bool]$row.ForceChangeAtNextLogon

  Import-LocalAccountsModule

  try {
    $localUser = Get-LocalUser -Name $u -ErrorAction SilentlyContinue
  } catch {
    $localUser = $null
  }

  if ($null -ne $localUser) {
    Write-Host "  -> Updating existing local user '$u'..." -ForegroundColor Cyan

    try {
      $params = @{
        Name                 = $u
        ErrorAction          = 'Stop'
        WhatIf               = $whatIf
      }
      if ($full) { $params['FullName'] = $full }
      if ($desc) { $params['Description'] = $desc }

      Set-LocalUser @params

      # Ensure account is enabled and password expires
      Set-LocalUser -Name $u -Enabled $true -PasswordNeverExpires $false -WhatIf:$whatIf -ErrorAction SilentlyContinue

      if ($forceThisUser -and -not $whatIf) {
        Write-Host "    -> Forcing password change at next logon for '$u'..."
        cmd /c "net user `"$u`" /logonpasswordchg:yes /passwordchg:yes /y" | Out-Null
      }
    } catch {
      Write-Warning ("    Failed to update user {0} - {1}" -f $u, $_.Exception.Message)
    }

  } else {
    # Create new user
    Write-Host "  -> Creating local user '$u'..." -ForegroundColor Yellow

    if ($null -eq $defaultPwd) {
      throw "Default password is required to create new users. Supply it in the GUI."
    }

    try {
      $createParams = @{
        Name                 = $u
        Password             = $defaultPwd
        PasswordNeverExpires = $false
        AccountNeverExpires  = $false
        ErrorAction          = 'Stop'
        WhatIf               = $whatIf
      }
      if ($full) { $createParams['FullName'] = $full }
      if ($desc) { $createParams['Description'] = $desc }

      New-LocalUser @createParams | Out-Null

      if ($forceThisUser -and -not $whatIf) {
        Write-Host "    -> Forcing password change at next logon for '$u'..."
        cmd /c "net user `"$u`" /logonpasswordchg:yes /passwordchg:yes /y" | Out-Null
      }
    } catch {
      Write-Warning ("    Failed to create user {0} - {1}" -f $u, $_.Exception.Message)
    }
  }

  # Ensure expiration is enabled even if we didn't change anything
  try {
    Set-LocalUser -Name $u -PasswordNeverExpires $false -WhatIf:$whatIf -ErrorAction SilentlyContinue
  } catch {}
}

function Enforce-GroupMembership {
  param(
    [Parameter(Mandatory)][pscustomobject[]]$desired,
    [Parameter(Mandatory)][string]$groupName,
    [bool]$whatIf
  )

  Import-LocalAccountsModule

  Write-Host "  >> Enforcing membership for group '$groupName'..." -ForegroundColor Green

  $shouldNames = @(
    $desired |
    Where-Object { $_.Role -eq $groupName } |
    Select-Object -ExpandProperty UserName -Unique
  )

  $currentComputer = $env:COMPUTERNAME
  $currentUser     = $env:USERNAME

  # Ensure required users are in the group
  foreach ($u in $shouldNames) {
    try {
      $already = Get-LocalGroupMember -Group $groupName -ErrorAction SilentlyContinue | Where-Object {
        $_.ObjectClass -eq 'User' -and $_.Name -match ("^$currentComputer\\$u$")
      }
      if (-not $already) {
        Write-Host "    -> Adding '$u' to '$groupName'..."
        try {
          Add-LocalGroupMember -Group $groupName -Member $u -WhatIf:$whatIf -ErrorAction Stop
        } catch {
          Write-Warning ("      Failed to add {0} to group {1} - {2}" -f $u, $groupName, $_.Exception.Message)
        }
      } else {
        Write-Host "    -> '$u' already in '$groupName'."
      }
    } catch {
      Write-Warning ("    Error while checking/adding {0} - {1}" -f $u, $_.Exception.Message)
    }
  }

  # Remove users that should not be in the group
  try {
    $members = Get-LocalGroupMember -Group $groupName -ErrorAction SilentlyContinue
  } catch {
    Write-Warning ("    Could not enumerate members of group {0} - {1}" -f $groupName, $_.Exception.Message)
    return
  }

  foreach ($m in $members) {
    if ($m.ObjectClass -ne 'User') { continue }

    # m.Name is like COMPUTER\user; extract simple username
    $parts = $m.Name -split '\\', 2
    $mUser = if ($parts.Count -eq 2) { $parts[1] } else { $m.Name }

    # Protection rules
    if (Is-SystemUserName $mUser) { continue }
    if ($mUser -eq $currentUser) { continue } # never drop current logged-on user
    if ($mUser -eq "Administrator") { continue }

    if ($mUser -notin $shouldNames) {
      Write-Host "    -> Removing '$mUser' from '$groupName'..."
      try {
        Remove-LocalGroupMember -Group $groupName -Member $mUser -WhatIf:$whatIf -ErrorAction Stop
      } catch {
        Write-Warning ("      Failed to remove {0} from group {1} - {2}" -f $mUser, $groupName, $_.Exception.Message)
      }
    }
  }
}

function Enforce-Deletions {
  param(
    [string[]]$desiredNames,
    [bool]$whatIf
  )

  Import-LocalAccountsModule

  $desiredSet = $desiredNames | Select-Object -Unique
  $currentUser = $env:USERNAME

  Write-Host "  >> Evaluating local accounts for deletion..." -ForegroundColor Green

  $locals = Get-LocalUser
  foreach ($u in $locals) {
    $name = $u.Name

    # Never delete system / special / current user
    if (Is-SystemUserName $name) { continue }
    if ($name -eq $currentUser) { continue }

    if ($name -notin $desiredSet) {
      Write-Host "    -> Deleting extraneous local user '$name'..."
      try {
        Remove-LocalUser -Name $name -WhatIf:$whatIf -ErrorAction Stop
      } catch {
        Write-Warning ("      Failed to delete user {0} - {1}" -f $name, $_.Exception.Message)
      }
    }
  }
}

# -------------------- GUI --------------------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Show-SyncGui {
  Assert-Admin
  Import-LocalAccountsModule
  New-Folder -Path $WorkingDir

  $form = New-Object System.Windows.Forms.Form
  $form.Text = "Sync Local Users (CyberPatriot Hardened)"
  $form.Size = New-Object System.Drawing.Size(1200, 850)
  $form.MinimumSize = New-Object System.Drawing.Size(1100, 760)
  $form.StartPosition = "CenterScreen"

  # Splits: main vertical (top: inputs, bottom: grid+log)
  $splitMain = New-Object System.Windows.Forms.SplitContainer
  $splitMain.Dock = 'Fill'
  $splitMain.Orientation = 'Horizontal'
  $splitMain.SplitterWidth = 6
  $splitMain.FixedPanel = 'Panel1'
  $splitMain.IsSplitterFixed = $false
  $splitMain.Panel1MinSize = 220
  $splitMain.Panel2MinSize = 300
  $splitMain.SplitterDistance = 220
  $form.Controls.Add($splitMain)

  # ===== TOP: paste/inputs =====
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
  foreach($b in @($btnParse,$btnLoadCsv,$btnSaveCsv)){ $b.Size = '130,28' }

  $btnParse.Text   = "Parse from Paste"
  $btnLoadCsv.Text = "Load CSV..."
  $btnSaveCsv.Text = "Export CSV..."

  $btnParse.Location   = '8,166'
  $btnLoadCsv.Location = '150,166'
  $btnSaveCsv.Location = '290,166'
  $pTop.Controls.AddRange(@($btnParse,$btnLoadCsv,$btnSaveCsv))

  $lblPwd = New-Object System.Windows.Forms.Label
  $lblPwd.Text = "Default password for NEW accounts (required):"
  $lblPwd.AutoSize = $true
  $lblPwd.Location = '450,171'
  $pTop.Controls.Add($lblPwd)

  $txtPwd = New-Object System.Windows.Forms.MaskedTextBox
  $txtPwd.UseSystemPasswordChar = $true
  $txtPwd.Location = '780,168'
  $txtPwd.Size = '200,24'
  $pTop.Controls.Add($txtPwd)

  $chkForceAll = New-Object System.Windows.Forms.CheckBox
  $chkForceAll.Text = "Force PW change at next logon (ALL listed users)"
  $chkForceAll.AutoSize = $true
  $chkForceAll.Location = '8,196'
  $pTop.Controls.Add($chkForceAll)

  $chkDelete = New-Object System.Windows.Forms.CheckBox
  $chkDelete.Text = "Delete local users NOT in the list (safe exclusions apply)"
  $chkDelete.AutoSize = $true
  $chkDelete.Location = '400,196'
  $pTop.Controls.Add($chkDelete)

  # ===== Bottom split: top grid, bottom log =====
  $splitBottom = New-Object System.Windows.Forms.SplitContainer
  $splitBottom.Dock = 'Fill'
  $splitBottom.Orientation = 'Horizontal'
  $splitBottom.FixedPanel = 'Panel2'
  $splitBottom.Panel2MinSize = 220
  $splitBottom.SplitterWidth = 6
  $splitBottom.SplitterDistance = 360
  $splitMain.Panel2.Controls.Add($splitBottom)

  # ===== Grid =====
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

  # ===== Bottom: buttons + log =====
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
  $btnImportLocal.Width = 260

  $btnWhatIf = New-Object System.Windows.Forms.CheckBox
  $btnWhatIf.Text = "Dry-run (WhatIf: show actions, no changes)"
  $btnWhatIf.AutoSize = $true
  $btnWhatIf.Margin = '12,10,12,0'

  $btnStrip.Controls.AddRange(@($btnApply,$btnImportLocal,$btnWhatIf))

  $txtLog = New-Object System.Windows.Forms.TextBox
  $txtLog.Multiline = $true
  $txtLog.ReadOnly = $true
  $txtLog.ScrollBars = "Vertical"
  $txtLog.Dock = 'Fill'
  $pBottom.Controls.Add($txtLog)

  function Log {
    param([string]$s)
    $txtLog.AppendText( ("[{0}] {1}" -f (Get-Date).ToString("HH:mm:ss"), $s) + [Environment]::NewLine )
    Write-Host $s
  }

  # Data backing
  $dt = New-Object System.Data.DataTable
  foreach($col in @("UserName","FullName","Role","Description","ForceChangeAtNextLogon")){
    [void]$dt.Columns.Add($col)
  }
  $grid.DataSource = $dt

  # Replace 'Role' column with dropdown
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

  $updateCount = {
    $lblCount.Text = ("{0} user{1}" -f $dt.Rows.Count, $(if($dt.Rows.Count -eq 1) {""} else {"s"}))
  }

  # ----- Button events -----
  $btnParse.Add_Click({
    try {
      $dt.Rows.Clear()
      $rows = Read-DesiredUsersFromText -Text $txtPaste.Text
      foreach($r in $rows){
        $row = $dt.NewRow()
        $row.UserName = $r.UserName
        $row.FullName = $r.FullName
        $row.Role = $r.Role
        $row.Description = $r.Description
        $row.ForceChangeAtNextLogon = [string]$r.ForceChangeAtNextLogon
        $dt.Rows.Add($row)
      }
      & $updateCount
      if ($grid.Rows.Count -gt 0) { $grid.FirstDisplayedScrollingRowIndex = 0 }
      Log "Parsed $($dt.Rows.Count) user(s) from pasted text."
    } catch {
      Log ("ERROR parsing: {0}" -f $_.Exception.Message)
    }
  })

  $btnLoadCsv.Add_Click({
    if ($ofd.ShowDialog() -eq 'OK') {
      try {
        $dt.Rows.Clear()
        $rows = Read-DesiredUsersFromCsvFile -CsvPath $ofd.FileName
        foreach($r in $rows){
          $row = $dt.NewRow()
          $row.UserName = $r.UserName
          $row.FullName = $r.FullName
          $row.Role = $r.Role
          $row.Description = $r.Description
          $row.ForceChangeAtNextLogon = [string]$r.ForceChangeAtNextLogon
          $dt.Rows.Add($row)
        }
        & $updateCount
        if ($grid.Rows.Count -gt 0) { $grid.FirstDisplayedScrollingRowIndex = 0 }
        Log "Loaded $($dt.Rows.Count) user(s) from CSV '$($ofd.FileName)'."
      } catch {
        Log ("ERROR loading CSV: {0}" -f $_.Exception.Message)
      }
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
      } catch {
        Log ("ERROR exporting CSV: {0}" -f $_.Exception.Message)
      }
    }
  })

  $btnImportLocal.Add_Click({
    try {
      $dt.Rows.Clear()
      $locals = Get-LocalUser
      foreach($u in $locals){
        $row = $dt.NewRow()
        $row.UserName = $u.Name
        $row.FullName = $u.FullName
        $row.Description = $u.Description

        # Determine role by group membership
        $isAdmin = $false
        try {
          $adms = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Where-Object {
            $_.ObjectClass -eq 'User' -and $_.Name -match ("^[^\\]+\\$($u.Name)$")
          }
          if ($adms) { $isAdmin = $true }
        } catch {}

        $row.Role = if ($isAdmin) { "Administrators" } else { "Users" }
        $row.ForceChangeAtNextLogon = "False"
        $dt.Rows.Add($row)
      }
      & $updateCount
      if ($grid.Rows.Count -gt 0) { $grid.FirstDisplayedScrollingRowIndex = 0 }
      Log "Imported $($dt.Rows.Count) current local user(s) into grid."
    } catch {
      Log ("ERROR importing local users: {0}" -f $_.Exception.Message)
    }
  })

  $btnApply.Add_Click({
    try {
      # Build desired list from grid
      $desired = @()
      foreach($r in $dt.Rows){
        $desired += [PSCustomObject]@{
          UserName               = ("" + $r.UserName).Trim()
          FullName               = ("" + $r.FullName).Trim()
          Role                   = Normalize-Role ("" + $r.Role)
          Description            = ("" + $r.Description).Trim()
          ForceChangeAtNextLogon = Normalize-ForceBool ("" + $r.ForceChangeAtNextLogon)
