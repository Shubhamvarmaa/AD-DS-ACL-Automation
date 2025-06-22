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
  - `WriteOwner` ➡️ rahul on Domain Admins
  - `GenericWrite` ➡️ aakash on Domain Admins
  - `AddSelf` ➡️ aakash and himanshu
  - `GenericAll` ➡️ ram on the domain root
  - `ForceChangePassword` ➡️ Nobita and raj on Shizuka
  - `GenericWrite` ➡️ kisan on sonu
  - `WriteDacl` ➡️ jainam on sandeep

---

## 🚀 Usage Instructions

### 1. Run on Fresh Server
```powershell
Set-ExecutionPolicy RemoteSigned -Force
```

```powershell
.\install-adds.ps1
```

### 2. After Domain Promotion
```powershell
Set-ExecutionPolicy RemoteSigned -Force
```

```powershell
.\Configure-AD-ACLs.ps1
```
---
