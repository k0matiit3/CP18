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
    $charCodes = (48..57 + 65..90 + 97..122 + 33,35,36,37,38,42,64)
    $chars = foreach ($c in $charCodes) { [char]$c }
    $plain = -join (1..$Length | ForEach-Object { $chars | Get-Random })
    ConvertTo-SecureString $plain -AsPlainText -Force
}

# Built-in / system-managed locals we never delete or force out of groups
$protectedBuiltIns = @(
    'Administrator','DefaultAccount','Guest','WDAGUtilityAccount',
    'sshd','ssh-agent','defaultuser0'
) + $ExtraProtectedAccounts

Write-Host "=== Sync-LocalUsers starting ===" -ForegroundColor Cyan
Write-Host "CSV: $CsvPath"
Write-Host ("Mode: " + ($(if ($Apply) { "APPLY (changes WILL be made)" } else { "PREVIEW (no changes)" }))) -ForegroundColor Yellow

# Read desired users
$desired = Import-Csv -Path $CsvPath
if (-not $desired) { throw "CSV appears empty: $CsvPath" }

# Normalize rows (5.1-safe)
$desired = $desired | ForEach-Object {
    $u = if ($_.UserName) { [string]$_.UserName } else { "" }
    $f = if ($_.FullName) { [string]$_.FullName } else { "" }
    $d = if ($_.Description) { [string]$_.Description } else { "" }
    $p = if ($_.Password) { [string]$_.Password } else { "" }
    $r = if ($_.Role) { [string]$_.Role } else { "" }

    $_.UserName    = $u.Trim()
    $_.FullName    = $f.Trim()
    $_.Description = $d.Trim()
    $_.Password    = $p
    $_.Role        = $r.Trim()
    $_
} | Where-Object { $_.UserName -and $_.UserName.Trim() -ne '' }

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

# Delete users not in CSV (excluding protected)
$toDelete = $existing | Where-Object {
    $name = $_.Name
    ($protectedBuiltIns -notcontains $name) -and
    ($desiredNames -notcontains $name)
}

# Create users in CSV that are missing
$toCreate = $desired | Where-Object { $existingNames -notcontains $_.UserName }

Write-Host ""
Write-Host "Planned deletions (excluding built-ins): $($toDelete.Count)" -ForegroundColor Magenta
$toDelete | Select-Object Name, Enabled, Description | Format-Table -AutoSize
Write-Host ""
Write-Host "Planned creations: $($toCreate.Count)" -ForegroundColor Green
$toCreate | Select-Object UserName, FullName, Description, Role | Format-Table -AutoSize

# --- APPLY: deletions ---
foreach ($usr in $toDelete) {
    if ($PSCmdlet.ShouldProcess("LOCAL USER '$($usr.Name)'", "Remove-LocalUser")) {
        try {
            if ($Apply) { Remove-LocalUser -Name $usr.Name -ErrorAction Stop }
            else { Remove-LocalUser -Name $usr.Name -WhatIf }
            Write-Host "Deleted: $($usr.Name)" -ForegroundColor Magenta
        } catch {
            Write-Warning "Failed to delete '$($usr.Name)': $($_.Exception.Message)"
        }
    }
}

# --- APPLY: creations ---
foreach ($row in $toCreate) {
    $u    = $row.UserName
    $full = if ($row.FullName) { $row.FullName } else { $null }
    $desc = if ($row.Description) { $row.Description } else { $null }

    $secPwd = if ($row.Password) {
        try { ConvertTo-SecureString $row.Password -AsPlainText -Force }
        catch { Write-Warning "Password for '$u' invalid; using a random password."; New-RandomSecurePassword }
    } else { New-RandomSecurePassword }

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
}

# -----------------------------
# ENFORCE GROUP MEMBERSHIP (SAFE)
# -----------------------------
# We will:
#  - Ensure CSV 'Administrator' users are members of Administrators
#  - Ensure CSV 'User' users are members of Users
#  - Remove any *local user* members (not protected) from those groups if they are not listed accordingly
#  - We DO NOT touch domain accounts, domain groups, or protected built-ins

function Get-DesiredSet {
    param([string]$rolePattern) # e.g., '^administrator$' or '^user$'
    $desired |
        Where-Object {
            $_.Role -and ($_.Role -match $rolePattern)
        } |
        Select-Object -ExpandProperty UserName
}

$desiredAdmins = Get-DesiredSet -rolePattern '^administrator(s)?$'
$desiredUsers  = Get-DesiredSet -rolePattern '^user(s)?$'

# Helper: add missing members
function Ensure-Members {
    param(
        [string]$GroupName,
        [string[]]$MemberNames
    )
    foreach ($name in $MemberNames) {
        # Only add if local user exists (was created or already present)
        if ($existingNames -notcontains $name) {
            # If it was just created above, it may not be in $existingNames yet; retrieve live list:
            $isLocal = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
            if (-not $isLocal) { continue }
        }
        if ($PSCmdlet.ShouldProcess("Add '$name' to '$GroupName'", "Add-LocalGroupMember")) {
            try {
                if ($Apply) { Add-LocalGroupMember -Group $GroupName -Member $name -ErrorAction Stop }
                else { Add-LocalGroupMember -Group $GroupName -Member $name -WhatIf }
                Write-Host "  -> Ensured '$name' in '$GroupName'" -ForegroundColor DarkGreen
            } catch {
                # Ignore if already a member / race conditions
            }
        }
    }
}

# Helper: remove extra *local user* members that shouldn't be there
function Prune-Extras {
    param(
        [string]$GroupName,
        [string[]]$AllowedLocalUsers # local usernames that are allowed to be in this group
    )

    $members = Get-LocalGroupMember -Group $GroupName -ErrorAction SilentlyContinue
    foreach ($m in $members) {
        # Only consider local users (skip domain and groups and built-ins)
        if ($m.ObjectClass -ne 'User' -or $m.PrincipalSource -ne 'Local') { continue }
        $name = $m.Name
        if ($protectedBuiltIns -contains $name) { continue }
        if ($AllowedLocalUsers -contains $name) { continue }

        if ($PSCmdlet.ShouldProcess("Remove '$name' from '$GroupName'", "Remove-LocalGroupMember")) {
            try {
                if ($Apply) { Remove-LocalGroupMember -Group $GroupName -Member $name -ErrorAction Stop }
                else { Remove-LocalGroupMember -Group $GroupName -Member $name -WhatIf }
                Write-Host "  -> Removed '$name' from '$GroupName'" -ForegroundColor DarkYellow
            } catch {
                Write-Warning "  -> Failed to remove '$name' from '$GroupName': $($_.Exception.Message)"
            }
        }
    }
}

Write-Host ""
Write-Host "Enforcing membership for 'Administrators' and 'Users'..." -ForegroundColor Cyan

# Ensure required members exist
Ensure-Members -GroupName 'Administrators' -MemberNames $desiredAdmins
Ensure-Members -GroupName 'Users'          -MemberNames $desiredUsers

# Prune extras (local user accounts only, non-protected)
Prune-Extras -GroupName 'Administrators' -AllowedLocalUsers $desiredAdmins
Prune-Extras -GroupName 'Users'          -AllowedLocalUsers $desiredUsers

Write-Host ""
Write-Host "=== Sync-LocalUsers complete (membership enforced) ===" -ForegroundColor Cyan
if (-not $Apply) {
    Write-Host "No changes were made. Re-run with -Apply to enforce." -ForegroundColor Yellow
}
