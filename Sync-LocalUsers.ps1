<# 
.SYNOPSIS
  Reconcile local Windows users to match a CSV "source of truth":
  - Create users that are in CSV but missing locally
  - Delete local users not present in CSV (skips built-ins & protected)
  - Enforce membership: Role=Administrator -> Administrators group; Role=User -> Users group
  - Preview-only by default; pass -Apply to make changes

.CSV FORMAT
  Headers: UserName,FullName,Description,Password,Role
  Role should be 'Administrator' or 'User' (case-insensitive)

.EXAMPLES
  .\Sync-LocalUsers.ps1 -CsvPath "C:\path\valid_users.csv"           # Preview
  .\Sync-LocalUsers.ps1 -CsvPath "C:\path\valid_users.csv" -Apply    # Apply
  .\Sync-LocalUsers.ps1 -CsvPath "C:\path\valid_users.csv" -Apply -BackupPath "C:\path\prechange.csv"
  .\Sync-LocalUsers.ps1 -CsvPath "C:\path\valid_users.csv" -Apply -ExtraProtectedAccounts breakglass

.NOTES
  - Run in elevated PowerShell (Run as Administrator)
  - Requires Microsoft.PowerShell.LocalAccounts (present on Win10/11)
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

# Built-in / system-managed locals to never delete or force out of groups
$protectedBuiltIns = @(
    'Administrator','DefaultAccount','Guest','WDAGUtilityAccount',
    'sshd','ssh-agent','defaultuser0'
) + $ExtraProtectedAccounts

# Also protect the currently logged-on user running this script
try {
    $currentSam = $env:USERNAME
    if ($currentSam -and ($protectedBuiltIns -notcontains $currentSam)) {
        $protectedBuiltIns += $currentSam
    }
} catch {}

Write-Host "=== Sync-LocalUsers starting ===" -ForegroundColor Cyan
Write-Host "CSV: $CsvPath"
Write-Host ("Mode: " + ($(if ($Apply) { "APPLY (changes WILL be made)" } else { "PREVIEW (no changes)" }))) -ForegroundColor Yellow

# Read desired users
$desired = Import-Csv -Path $CsvPath
if (-not $desired) { throw "CSV appears empty: $CsvPath" }

# Normalize rows (PowerShell 5.1 safe; avoid null-Trim)
$desired = $desired | ForEach-Object {
    $u = if ($_.UserName)    { [string]$_.UserName }    else { "" }
    $f = if ($_.FullName)    { [string]$_.FullName }    else { "" }
    $d = if ($_.Description) { [string]$_.Description } else { "" }
    $p = if ($_.Password)    { [string]$_.Password }    else { "" }
    $r = if ($_.Role)        { [string]$_.Role }        else { "" }

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

# Deletions: local users present but NOT in desired list (excluding protected)
$toDelete = $existing | Where-Object {
    $name = $_.Name
    ($protectedBuiltIns -notcontains $name) -and
    ($desiredNames -notcontains $name)
}

# Creations: desired users missing locally
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
            else        { Remove-LocalUser -Name $usr.Name -WhatIf }
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
# - Ensure CSV 'Administrator' users are members of Administrators
# - Ensure CSV 'User' users are members of Users
# - Remove any *local user* members (not protected) from those groups if they are not listed accordingly
# - Do NOT touch domain accounts/groups or protected built-ins

function Get-DesiredSet {
    param([string]$rolePattern) # e.g., '^administrator(s)?$' or '^user(s)?$'
    $desired |
        Where-Object { $_.Role -and ($_.Role -match $rolePattern) } |
        Select-Object -ExpandProperty UserName
}

$desiredAdmins = Get-DesiredSet -rolePattern '^administrator(s)?$'
$desiredUsers  = Get-DesiredSet -rolePattern '^user(s)?$'

# Normalize collection membership adds (use SAM name)
function Ensure-Members {
    param(
        [string]$GroupName,
        [string[]]$MemberNames
    )
    foreach ($name in $MemberNames) {
        if (-not $name) { continue }
        # Only add if a local user actually exists
        $local = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
        if (-not $local) { continue }

        if ($PSCmdlet.ShouldProcess("Add '$name' to '$GroupName'", "Add-LocalGroupMember")) {
            try {
                if ($Apply) { Add-LocalGroupMember -Group $GroupName -Member $name -ErrorAction Stop }
                else        { Add-LocalGroupMember -Group $GroupName -Member $name -WhatIf }
                Write-Host "  -> Ensured '$name' in '$GroupName'" -ForegroundColor DarkGreen
            } catch {
                # Already-a-member throws sometimes; ignore
            }
        }
    }
}

# Remove extra LOCAL USER members not in the allowed set (compare by SAM name)
function Prune-Extras {
    param(
        [string]$GroupName,
        [string[]]$AllowedLocalUsers
    )

    # Build lowercase allow-set of SAM names
    $allowSet = @{}
    foreach ($u in $AllowedLocalUsers) {
        if ($u) { $allowSet[$u.ToLower()] = $true }
    }

    $members = Get-LocalGroupMember -Group $GroupName -ErrorAction SilentlyContinue
    foreach ($m in $members) {
        # Only consider Local User principals
        if ($m.ObjectClass -ne 'User' -or $m.PrincipalSource -ne 'Local') { continue }

        # Extract SAM 'username' from 'MACHINE\username'
        $sam = ($m.Name -split '\\')[-1]
        if (-not $sam) { continue }

        # Skip protected accounts (compare by SAM)
        $isProtected = $false
        foreach ($p in $protectedBuiltIns) {
            if ($p -and ($p.ToLower() -eq $sam.ToLower())) { $isProtected = $true; break }
        }
        if ($isProtected) { continue }

        # If not allowed, remove
        if (-not $allowSet.ContainsKey($sam.ToLower())) {
            if ($PSCmdlet.ShouldProcess("Remove '$m.Name' from '$GroupName'", "Remove-LocalGroupMember")) {
                try {
                    if ($Apply) { Remove-LocalGroupMember -Group $GroupName -Member $sam -ErrorAction Stop }
                    else        { Remove-LocalGroupMember -Group $GroupName -Member $sam -WhatIf }
                    Write-Host "  -> Removed '$m.Name' from '$GroupName'" -ForegroundColor DarkYellow
                } catch {
                    Write-Warning "  -> Failed to remove '$m.Name' from '$GroupName': $($_.Exception.Message)"
                }
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
