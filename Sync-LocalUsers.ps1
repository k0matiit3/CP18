<# 
.SYNOPSIS
  Reconciles local Windows users to match a CSV "source of truth":
  - Creates users in CSV that are missing locally
  - Deletes local users not present in CSV (skips built-ins)
  - Optionally adds users to local groups
  - Preview by default; use -Apply to make changes

.PARAMETERS
  -CsvPath <path>   : CSV with headers: UserName,FullName,Description,Password,Groups
  -Apply            : Actually perform changes
  -BackupPath <path>: Save a snapshot of current users before changes
  -ExtraProtectedAccounts <string[]> : Additional accounts to never delete
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
    # Build a mixed character set
    $charCodes = (48..57 + 65..90 + 97..122 + 33,35,36,37,38,42,64)
    $chars = foreach ($c in $charCodes) { [char]$c }
    $plain = -join (1..$Length | ForEach-Object { $chars | Get-Random })
    ConvertTo-SecureString $plain -AsPlainText -Force
}

# Built-in / system-managed locals to never delete
$protectedBuiltIns = @(
    'Administrator','DefaultAccount','Guest','WDAGUtilityAccount',
    'sshd','ssh-agent','defaultuser0'
) + $ExtraProtectedAccounts

Write-Host "=== Sync-LocalUsers starting ===" -ForegroundColor Cyan
Write-Host "CSV: $CsvPath"
Write-Host ("Mode: " + ($(if ($Apply) { "APPLY (changes WILL be made)" } else { "PREVIEW (no changes)" }))) -ForegroundColor Yellow

# Read desired users from CSV
$desired = Import-Csv -Path $CsvPath
if (-not $desired) { throw "CSV appears empty: $CsvPath" }

# Normalize and validate CSV rows (PowerShell 5.1-safe)
$desired = $desired | ForEach-Object {
    # Safely coerce to string before Trim()
    $u = if ($_.UserName) { [string]$_.UserName } else { "" }
    $f = if ($_.FullName) { [string]$_.FullName } else { "" }
    $d = if ($_.Description) { [string]$_.Description } else { "" }
    $p = if ($_.Password) { [string]$_.Password } else { "" }
    $g = if ($_.Groups) { [string]$_.Groups } else { "" }

    $_.UserName   = $u.Trim()
    $_.FullName   = $f.Trim()
    $_.Description= $d.Trim()
    $_.Password   = $p   # may be empty
    $_.Groups     = $g   # may be empty or "G1;G2"
    $_
} | Where-Object { $_.UserName -and $_.UserName.Trim() -ne '' }

if (-not $desired) { throw "No rows with a non-empty UserName were found in the CSV." }

# Snapshot existing local users (requires Microsoft.PowerShell.LocalAccounts; run as admin)
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

# Deletions: local users present but NOT in desired list (excluding protected)
$toDelete = $existing | Where-Object {
    $name = $_.Name
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
    $u    = $row.UserName
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
