<# 
.SYNOPSIS
  Reconcile local users to a CSV, enforce group membership, and ENFORCE PASSWORDS for all desired users.

.CSV FORMAT
  UserName,FullName,Description,Password,Role
  jsmith,John Smith,Support,P@ssw0rd!,Administrator
  ajones,Amy Jones,Service desk,,User

.PARAMETERS
  -CsvPath <path>                 : Source-of-truth CSV
  -Apply                          : Actually make changes (otherwise Preview)
  -BackupPath <path>              : Optional export of current local users to CSV
  -ExtraProtectedAccounts <arr>   : Additional local accounts to never delete or remove from groups
  -PasswordReportPath <path>      : If set, writes a CSV of passwords set/updated this run (restrictive ACL)
  -ExpireAtNextLogon              : Mark updated/created accounts to change password at next logon

.NOTES
  - PowerShell 5.1 compatible (uses ADSI for password resets)
  - Run elevated
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ })]
    [string]$CsvPath,

    [switch]$Apply,

    [string]$BackupPath,

    [string[]]$ExtraProtectedAccounts = @(),

    [string]$PasswordReportPath,

    [switch]$ExpireAtNextLogon
)

function New-RandomPassword {
    param([int]$Length = 20)
    $charCodes = (48..57 + 65..90 + 97..122 + 33,35,36,37,38,42,64) # 0-9 A-Z a-z !#%$&*@
    $chars = foreach ($c in $charCodes) { [char]$c }
    -join (1..$Length | ForEach-Object { $chars | Get-Random })
}

function To-SecureString($plain) {
    ConvertTo-SecureString $plain -AsPlainText -Force
}

# Built-ins / system accounts we never delete or force out of groups
$protectedBuiltIns = @(
    'Administrator','DefaultAccount','Guest','WDAGUtilityAccount','sshd','ssh-agent','defaultuser0'
) + $ExtraProtectedAccounts

# Also protect the currently logged-on SAM user from group removal
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

# Normalize rows (5.1 safe)
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

# Plan deletions (not in CSV) excluding protected
$toDelete = $existing | Where-Object {
    ($protectedBuiltIns -notcontains $_.Name) -and
    ($desiredNames -notcontains $_.Name)
}

# Plan creations (in CSV but not on box)
$toCreate = $desired | Where-Object { $existingNames -notcontains $_.UserName }

# Plan password enforcement (all desired that exist or will be created)
$toEnforcePwExisting = $desired | Where-Object {
    $existingNames -contains $_.UserName
} | Where-Object {
    $protectedBuiltIns -notcontains $_.UserName
}

$toEnforcePwNew = $toCreate

Write-Host ""
Write-Host "Planned deletions (excluding built-ins): $($toDelete.Count)" -ForegroundColor Magenta
$toDelete | Select-Object Name, Enabled, Description | Format-Table -AutoSize

Write-Host ""
Write-Host "Planned creations: $($toCreate.Count)" -ForegroundColor Green
$toCreate | Select-Object UserName, FullName, Description, Role | Format-Table -AutoSize

Write-Host ""
Write-Host "Planned password enforcement (existing accounts): $($toEnforcePwExisting.Count)" -ForegroundColor Yellow
$toEnforcePwExisting | Select-Object UserName, Role | Format-Table -AutoSize

# For outputting passwords set this run
$passwordReport = New-Object System.Collections.Generic.List[object]

# --- APPLY: deletions ---
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

# --- APPLY: creations + initial password ---
foreach ($row in $toCreate) {
    $u    = $row.UserName
    $full = if ($row.FullName) { $row.FullName } else { $null }
    $desc = if ($row.Description) { $row.Description } else { $null }

    $plainPwd = if ($row.Password) { $row.Password } else { New-RandomPassword }
    $secPwd = To-SecureString $plainPwd

    if ($PSCmdlet.ShouldProcess("LOCAL USER '$u'", "New-LocalUser (+password)")) {
        try {
            if ($Apply) {
                New-LocalUser -Name $u -Password $secPwd -FullName $full -Description $desc -ErrorAction Stop
            } else {
                New-LocalUser -Name $u -Password $secPwd -FullName $full -Description $desc -WhatIf
            }

            Write-Host "Created: $u" -ForegroundColor Green

            if ($Apply) {
                try {
                    $adsi = [ADSI]"WinNT://./$u,user"
                    $adsi.PasswordRequired = $true
                    if ($ExpireAtNextLogon) { $adsi.PasswordExpired = 1 }
                    $adsi.SetInfo()
                } catch {
                    Write-Warning "  -> Could not set PasswordRequired/Expired for '$u': $($_.Exception.Message)"
                }
            }

            $passwordReport.Add([pscustomobject]@{ UserName=$u; Password=$plainPwd; Action='Created' })
        } catch {
            Write-Warning "Failed to create '$u': $($_.Exception.Message)"
            continue
        }
    }
}

# --- APPLY: ENFORCE PASSWORDS for existing desired users ---
foreach ($row in $toEnforcePwExisting) {
    $u = $row.UserName
    if ($protectedBuiltIns -contains $u) { continue }

    $plainPwd = if ($row.Password) { $row.Password } else { New-RandomPassword }

    if ($PSCmdlet.ShouldProcess("LOCAL USER '$u'", "Reset password & enforce 'Password required'")) {
        try {
            if ($Apply) {
                $adsi = [ADSI]"WinNT://./$u,user"
                $adsi.SetPassword($plainPwd)
                $adsi.PasswordRequired = $true
                if ($ExpireAtNextLogon) { $adsi.PasswordExpired = 1 }
                $adsi.SetInfo()
            } else {
                Write-Host "WhatIf: would reset password for '$u' and enforce PasswordRequired" -ForegroundColor Yellow
            }

            Write-Host "Password enforced for: $u" -ForegroundColor DarkYellow
            $passwordReport.Add([pscustomobject]@{ UserName=$u; Password=$plainPwd; Action='PasswordReset' })
        } catch {
            Write-Warning "Failed to enforce password for '$u': $($_.Exception.Message)"
        }
    }
}

# -----------------------------
# ENFORCE GROUP MEMBERSHIP
# -----------------------------
function Get-DesiredSet {
    param([string]$rolePattern)
    $desired | Where-Object { $_.Role -and ($_.Role -match $rolePattern) } | Select-Object -ExpandProperty UserName
}

$desiredAdmins = Get-DesiredSet -rolePattern '^administrator(s)?$'
$desiredUsers  = Get-DesiredSet -rolePattern '^user(s)?$'

function Ensure-Members {
    param([string]$GroupName,[string[]]$MemberNames)
    foreach ($name in $MemberNames) {
        if (-not $name) { continue }
        $local = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
        if (-not $local) { continue }
        if
