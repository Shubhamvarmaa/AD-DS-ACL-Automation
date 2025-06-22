Import-Module ActiveDirectory

# -------------------------------
# Step 1: Create Users
# -------------------------------
$users = @(
    @{Name="rahul"; Password="Pass@123"},
    @{Name="sandeep"; Password="Pass@123"},
    @{Name="jainam"; Password="Pass@123"},
    @{Name="aakash"; Password="Password@123"},
    @{Name="himanshu"; Password="Password@123"},
    @{Name="ram"; Password="Password@12345"},
    @{Name="Shizuka"; Password="Password@1"},
    @{Name="Nobita"; Password="Password@1"},
    @{Name="doraemon"; Password="armour@123"},
    @{Name="Suneo"; Password="armour@123"},
    @{Name="sonu"; Password="Pass@123"},
    @{Name="kisan"; Password="Pass@123"},
    @{Name="raj"; Password="Pass@123"}
)

foreach ($user in $users) {
    $userName = $user["Name"]
    $userPass = $user["Password"]

    $existing = Get-ADUser -Filter "SamAccountName -eq '$userName'" -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-ADUser -Name $userName -SamAccountName $userName `
            -AccountPassword (ConvertTo-SecureString $userPass -AsPlainText -Force) `
            -Enabled $true
        Write-Output "Created user: $userName"
    } else {
        Write-Output "User $userName already exists"
    }
}

# -------------------------------
# Step 2: Grant-ADPermission Function
# -------------------------------
function Grant-ADPermission {
    param (
        [string]$TargetDN,
        [string]$Principal,
        [string]$AccessRight,
        [string]$ControlType = 'Allow',
        [System.Guid]$ObjectType = [Guid]::Empty
    )

    try {
        $adRights = switch ($AccessRight) {
            "WriteOwner"           { [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner }
            "WriteDacl"            { [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl }
            "GenericWrite"         { [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite }
            "AddSelf"              { [System.DirectoryServices.ActiveDirectoryRights]::Self }
            "GenericAll"           { [System.DirectoryServices.ActiveDirectoryRights]::GenericAll }
            "ForceChangePassword"  {
                $ObjectType = [Guid]"00299570-246d-11d0-a768-00aa006e0529"
                [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
            }
            "AllExtendedRights"    {
                [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
            }
            default { throw "Unknown AccessRight: $AccessRight" }
        }

        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
            (New-Object System.Security.Principal.NTAccount($Principal)),
            $adRights,
            [System.Security.AccessControl.AccessControlType]::$ControlType,
            $ObjectType
        )

        $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$TargetDN")
        $security = $entry.ObjectSecurity
        $security.AddAccessRule($ace)
        $entry.ObjectSecurity = $security
        $entry.CommitChanges()

        Write-Host "✔ Assigned $AccessRight to $Principal on $TargetDN"
    }
    catch {
        Write-Warning ("❌ Failed to assign {0} to {1} on {2}: {3}" -f $AccessRight, $Principal, $TargetDN, $_)
    }
}

# -------------------------------
# Step 3: Low-Level Permission Helpers
# -------------------------------

function Grant-ForceChangePassword {
    param (
        [string]$TargetUserCN,
        [string]$Principal
    )

    try {
        $User = [ADSI]"LDAP://$TargetUserCN"
        $acl = $User.psbase.ObjectSecurity

        $ResetPasswordGuid = [Guid]"00299570-246d-11d0-a768-00aa006e0529"
        $identity = New-Object System.Security.Principal.NTAccount($Principal)

        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
            ($identity, "ExtendedRight", "Allow", $ResetPasswordGuid, "None")

        $acl.AddAccessRule($ace)
        $User.psbase.ObjectSecurity = $acl
        $User.psbase.CommitChanges()

        Write-Host "✔ Granted 'ForceChangePassword' to $Principal on $TargetUserCN"
    }
    catch {
        Write-Warning ("❌ Failed to assign 'ForceChangePassword' to {0}: {1}" -f $Principal, $_)
    }
}

function Grant-GenericWrite {
    param (
        [string]$TargetUserCN,
        [string]$Principal
    )

    try {
        $user = [ADSI]"LDAP://$TargetUserCN"
        $acl = $user.psbase.ObjectSecurity

        $rights = [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite
        $aceType = [System.Security.AccessControl.AccessControlType]::Allow
        $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None

        $identity = New-Object System.Security.Principal.NTAccount($Principal)
        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
            ($identity, $rights, $aceType, $inheritanceType)

        $acl.AddAccessRule($ace)
        $user.psbase.ObjectSecurity = $acl
        $user.psbase.CommitChanges()

        Write-Host "✔ 'kisan' was granted GenericWrite permissions on 'sonu'"
    }
    catch {
        Write-Warning ("❌ Failed to grant GenericWrite to {0} on {1}: {2}" -f $Principal, $TargetUserCN, $_)
    }
}

function Grant-WriteDacl {
    param (
        [string]$TargetUserCN,
        [string]$Principal
    )

    try {
        $user = [ADSI]"LDAP://$TargetUserCN"
        $acl = $user.psbase.ObjectSecurity

        $rights = [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl
        $aceType = [System.Security.AccessControl.AccessControlType]::Allow
        $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None

        $identity = New-Object System.Security.Principal.NTAccount($Principal)
        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
            ($identity, $rights, $aceType, $inheritanceType)

        $acl.AddAccessRule($ace)
        $user.psbase.ObjectSecurity = $acl
        $user.psbase.CommitChanges()

        Write-Host "✔ 'jainam' was granted WriteDacl permission on 'sandeep'"
    }
    catch {
        Write-Warning ("❌ Failed to grant WriteDacl to {0} on {1}: {2}" -f $Principal, $TargetUserCN, $_)
    }
}

# -------------------------------
# Step 4: Get Distinguished Names
# -------------------------------
function Get-UserDN($username) {
    $user = Get-ADUser -Filter "SamAccountName -eq '$username'" -ErrorAction SilentlyContinue
    return $user?.DistinguishedName
}

$domainAdminsDN = (Get-ADGroup "Domain Admins").DistinguishedName
$domainDN       = (Get-ADDomain).DistinguishedName

$sandeepDN  = Get-UserDN "sandeep"
$shizukaDN  = Get-UserDN "Shizuka"
$doraemonDN = Get-UserDN "doraemon"
$sonuDN     = Get-UserDN "sonu"

# -------------------------------
# Step 5: Apply ACLs
# -------------------------------

# Domain and group level ACLs
Grant-ADPermission -TargetDN $domainAdminsDN -Principal "armour\rahul"     -AccessRight "WriteOwner"
Grant-ADPermission -TargetDN $domainAdminsDN -Principal "armour\aakash"    -AccessRight "GenericWrite"
Grant-ADPermission -TargetDN $domainAdminsDN -Principal "armour\aakash"    -AccessRight "AddSelf"
Grant-ADPermission -TargetDN $domainAdminsDN -Principal "armour\himanshu"  -AccessRight "AddSelf"
Grant-ADPermission -TargetDN $domainDN       -Principal "armour\ram"       -AccessRight "GenericAll"

# User-level ACLs
if ($doraemonDN) {
    Grant-ADPermission -TargetDN $doraemonDN -Principal "armour\Suneo" -AccessRight "AllExtendedRights"
}

# Low-level ACLs
Grant-ForceChangePassword -TargetUserCN "CN=Shizuka,CN=Users,DC=armour,DC=local" -Principal "armour\Nobita"
Grant-ForceChangePassword -TargetUserCN "CN=Shizuka,CN=Users,DC=armour,DC=local" -Principal "armour\raj"
Grant-GenericWrite        -TargetUserCN "CN=sonu,CN=Users,DC=armour,DC=local"    -Principal "armour\kisan"
Grant-WriteDacl           -TargetUserCN "CN=sandeep,CN=Users,DC=armour,DC=local" -Principal "armour\jainam"

Write-Host "`n[✔] All requested ACLs assigned successfully." -ForegroundColor Green

