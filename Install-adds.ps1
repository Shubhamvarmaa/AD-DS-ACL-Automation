# -------------------------------
# Step 0: Rename Server to DC1
# -------------------------------
$desiredName = "DC1"
$currentName = $env:COMPUTERNAME

if ($currentName -ne $desiredName) {
    Write-Host "[*] Renaming computer to $desiredName..." -ForegroundColor Yellow
    Rename-Computer -NewName $desiredName -Force -Restart
    exit  # Exit script now; it will resume after reboot
} else {
    Write-Host "[+] Computer name already set to $desiredName." -ForegroundColor Green
}

# -------------------------------
# Step 1: Install AD DS Role
# -------------------------------
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Write-Host "[+] AD DS role installed." -ForegroundColor Cyan

# -------------------------------
# Step 2: Promote to Domain Controller
# -------------------------------
$domainName = "armour.local"
$dsrmPassword = (ConvertTo-SecureString "Password@123" -AsPlainText -Force)

Install-ADDSForest `
    -DomainName $domainName `
    -SafeModeAdministratorPassword $dsrmPassword `
    -InstallDNS `
    -Force:$true

# Server will reboot automatically after promotion.

