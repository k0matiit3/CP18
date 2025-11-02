<# 
.SYNOPSIS
  Reconciles local Windows users to match a CSV "source of truth":
  - Creates users that are in CSV but not on the machine
  - Deletes local users that are on the machine but not in CSV (skips built-ins)
  - Optionally adds new users to local groups

.PARAMETER CsvPath
  Path to the CSV file (see format in header)

.PARAMETER Apply
  Actually perform changes. If omitted, runs in Preview (WhatIf) mode.

.PARAMETER BackupPath
  Optional path to save a snapshot of current local users before changes (CSV).

.PARAMETER ExtraProtectedAccounts
  Optional additional account names to protect from deletion (array of strings).

.EXAMPLE
  .\Sync-LocalUsers.ps1 -CsvPath .\valid_users.csv   # Preview only
  .\Sync-LocalUsers.ps1 -CsvPath .\valid_users.csv -Apply -BackupPath .\prechange-users.csv
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ })]
    [string]$CsvPath,

    [switch]$Apply,

    [string]$BackupPath,

    [string[]]$ExtraProtectedAccounts = @()
)

function New-RandomSecurePassword {
    param([int]$Length = 16)
    # Mixed, strong, with punctuation
    $chars = (48..57 + 65..90 + 97..122 + 33,35,36,37,38,42,64) | ForEach-Object {[char]$_}
    -join (1..$Length | ForEach-Object { $chars | Get-Random }) | 
        ForEach-Object { ConvertTo-SecureString $_ -AsPlainText -Force }
}

# Built-in / system-managed locals to never delete
$protectedBuiltIns = @(
    'Administrator', 'DefaultAccount', 'Guest', 'WDAGUtilityAccount',
    'sshd', 'ssh-agent', 'defaultuser0'
) + $ExtraProtectedAccounts

Write-Host "=== Sync-LocalUsers starting ===" -ForegroundColor Cyan
Write-Host "CSV: $CsvPath"
Write-Host ("Mode: " + ($(if ($Apply) { "APPLY (changes WILL be made)" } else { "PREVIEW (no changes)" }))) -ForegroundColor Yellow

# Read desired users from CSV
$desired = Import-Csv -Path $CsvPath
if (-not $desired) { throw "CSV appears empty: $CsvPath" }

# Normalize and validate CSV rows
$desired = $desired | ForEach-Object {
    $_.UserName = ($_.UserName ?? '').Trim()
    $_.FullName = ($_.FullName ?? '').Trim()
    $_.Description = ($_.Description ?? '').Trim()
    $_.Password = ($_.Password ?? '') # may be blank
    $_.Groups = ($_.Groups ?? '')     # may be blank or "G1;G2"
    $_
} | Where-Object { $_.UserName -ne '' }

if (-not $desired) { throw "No rows with a non-empty UserName were found in the CSV." }

# Snapshot existing local users
$existing = Get-LocalUser | Select-Object Name, Enabled, FullName, Description, SID, LastLogon

if ($BackupPath) {
    try {
        $existing | Export-Csv -Path $BackupPath -NoTypeInformation -Encoding UTF8
        Write-Host "Backed up current local users to: $BackupPath" -ForegroundColor DarkGray
    } catch {
        Write-Warning "Failed to write backup CSV to '$BackupPath': $($_.Exception.Message)"
    }
}

$existingNames = $existing.Name
$desiredNames  = $desired.UserName

# Deletions: local users present but NOT in desired list (excluding protected & default/builtin)
$toDelete = $existing |
    Where-Object {
        $name = $_.Name
        # Don't touch built-ins or obviously system accounts
        ($protectedBuiltIns -notcontains $name) -and
        ($desiredNames -notcontains $name)
    }

# Creations: desired users missing locally
$toCreate = $desired | Where-Object { $existingNames -notcontains $_.UserName }

# Info splash
Write-Host ""
Write-Host "Planned deletions (excluding built-ins): $($toDelete.Count)" -ForegroundColor Magenta
$toDelete | Select-Object Name, Enabled, Description | Format-Table -AutoSize

Write-Host ""
Write-Host "Planned creations: $($toCreate.Count)" -ForegroundColor Green
$toCreate | Select-Object UserName, FullName, Description, Groups | Format-Table -AutoSize

# --- APPLY CHANGES ---

# Deletions
foreach ($usr in $toDelete) {
    if ($PSCmdlet.ShouldProcess("LOCAL USER '$($usr.Name)'", "Remove-LocalUser")) {
        try {
            if ($Apply) {
                Remove-LocalUser -Name $usr.Name -ErrorAction Stop
            } else {
                # Preview mode
                Remove-LocalUser -Name $usr.Name -WhatIf
            }
            Write-Host "Deleted: $($usr.Name)" -ForegroundColor Magenta
        } catch {
            Write-Warning "Failed to delete '$($usr.Name)': $($_.Exception.Message)"
        }
    }
}

# Creations
foreach ($row in $toCreate) {
    $u = $row.UserName
    $full = if ($row.FullName) { $row.FullName } else { $null }
    $desc = if ($row.Description) { $row.Description } else { $null }

    # Password: from CSV (plain) -> SecureString, or random
    $secPwd = if ($row.Password) {
        try {
            ConvertTo-SecureString $row.Password -AsPlainText -Force
        } catch {
            Write-Warning "Password for '$u' couldn't be converted; using a random secure password."
            New-RandomSecurePassword
        }
    } else {
        New-RandomSecurePassword
    }

    if ($PSCmdlet.ShouldProcess("LOCAL USER '$u'", "New-LocalUser")) {
        try {
            if ($Apply) {
                New-LocalUser -Name $u -Password $secPwd -FullName $full -Description $desc -ErrorAction Stop
            } else {
                New-LocalUser -Name $u -Password $secPwd -FullName $full -Description $desc -WhatIf
            }
            Write-Host "Created: $u" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to create '$u': $($_.Exception.Message)"
            continue
        }
    }

    # Group membership
    if ($row.Groups) {
        $groups = $row.Groups -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        foreach ($g in $groups) {
            if ($PSCmdlet.ShouldProcess("Add '$u' to local group '$g'", "Add-LocalGroupMember")) {
                try {
                    if ($Apply) {
                        Add-LocalGroupMember -Group $g -Member $u -ErrorAction Stop
                    } else {
                        Add-LocalGroupMember -Group $g -Member $u -WhatIf
                    }
                    Write-Host "  -> Added '$u' to '$g'" -ForegroundColor DarkGreen
                } catch {
                    Write-Warning "  -> Failed to add '$u' to '$g': $($_.Exception.Message)"
                }
            }
        }
    }
}

Write-Host ""
Write-Host "=== Sync-LocalUsers complete ===" -ForegroundColor Cyan
if (-not $Apply) {
    Write-Host "No changes were made. Re-run with -Apply to enforce." -ForegroundColor Yellow
}
