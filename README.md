# 🛡️ ADDS and ACL Automation with PowerShell

This project automates the installation and configuration of **Active Directory Domain Services (AD DS)** and assigns **fine-grained permissions (ACLs)** to users and groups using PowerShell.

---

## 📂 Components

| File | Purpose |
|------|---------|
| `install-adds.ps1` | Sets up AD DS, renames server, installs role, promotes to Domain Controller |
| `Configure-AD-ACLs.ps1` | Creates users and configures Active Directory ACL permissions |

---

## 🧪 Lab Domain Setup

- **Domain Name**: `armour.local`
- **Users Created**: 13 AD users (rahul, sandeep, jainam, etc.)
- **Custom ACLs Applied**:
  - `WriteOwner` ➡️ Rahul on Domain Admins
  - `GenericWrite` ➡️ Aakash on Domain Admins
  - `AddSelf` ➡️ Himanshu on Domain Admins
  - `GenericAll` ➡️ Ram on the domain root
  - `ForceChangePassword` ➡️ Nobita and raj on Shizuka
  - `GenericWrite` ➡️ Kisan on sonu
  - `WriteDacl` ➡️ Jainam on sandeep

---

## 🚀 Usage Instructions

### 1. Run on Fresh Server
```powershell
Set-ExecutionPolicy RemoteSigned -Force
```

```powershell
.\install-adds.ps1
```
  🔔 NOTE: If the system reboots after renaming, just re-run the same script again.It will automatically skip the rename step and proceed with AD DS installation.


### 2. After Domain Promotion
```powershell
Set-ExecutionPolicy RemoteSigned -Force
```

```powershell
.\Configure-AD-ACLs.ps1
```
---

## 🛠️ Requirements

- 🪟 Windows Server 2016  
- 💻 PowerShell (Run as Administrator)  
- 📦 ActiveDirectory module (auto-installed with AD DS role)  

---

## 📎 Notes

- ⚠️ Ensure `Password@123` meets your domain's password policy  
- ✅ Idempotent: Safe to re-run without creating duplicate users  
- 🔒 Uses `System.DirectoryServices` for ACL operations  

---

## 📷 Preview

Permissions like `GenericWrite`, `AddSelf`, and `AllExtendedRights` are especially useful for:

- 🔬 Active Directory Labs  
- 🧪 Post-exploitation scenarios  
- 🔐 Red Team / Blue Team training  

---

## 👨‍💻 Author

Made with 💻 and 🧠 by **[Shubham](https://github.com/Shubhamvarmaa)**  
Feel free to ⭐ the repo or open an issue if you find this useful!

