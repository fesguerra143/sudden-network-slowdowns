

# Scanning for Vulnerabilities Project 

This project is about Scanning a Windows VM: Authenticated vs. Unauthenticated

![Scanning Windows Authenticated vs Unauthenticated](https://github.com/user-attachments/assets/0475b1a7-3e0e-40a8-9341-08d97ee65d6e)

---
# Tools & Technology:
- Tenable (enterprise vulnerability management platform)
- Azure Virtual Machine
- PowerShell 

---
# Table of contents

- [Step 1) Create a Windows virtual machine in the Azure portal](#step-1-create-a-windows-virtual-machine-in-the-azure-portal)
- [Step 2) Log into the VM and disable the Windows Firewall](#step-2-log-into-the-vm-and-disable-the-windows-firewall)
- [Step 3) Run a PowerShell command:](#step-3-run-a-powershell-command)
- [Step 4) Create a Network Security Group](#step-4-create-a-network-security-group)
- [Step 5) Login to tenable](#step-5-login-to-tenable)
- [Step 6) Run a Basic Scan: Unauthenticated](#step-6-run-a-basic-scan-unauthenticated)
- [Step 7) Run a Basic Scan: Authenticated](#step-7-run-a-basic-scan-authenticated)
- [Difference in Scan Duration](#difference-in-scan-duration)

---


### Step 1) Create a Windows virtual machine in the Azure portal

#### Configure the Basics Tab: 

<img width="600" alt="vm1" src="https://github.com/user-attachments/assets/936b6db1-bfab-48c4-b9d8-c3cda0b55815" />

#### Configure the Disks Tab:

<img width="600" alt="vm2" src="https://github.com/user-attachments/assets/2c5feeaf-246e-4ded-b660-081dad228f4e" />

#### Configure the Setup Networking:

<img width="600" alt="vm3" src="https://github.com/user-attachments/assets/ac22751a-8567-4e49-991e-c049b7f63996" />

#### Review + Create:
<img width="600" alt="vm5" src="https://github.com/user-attachments/assets/5ade34fe-02e3-4369-a58f-dffd0e69384c" />

#### Deployment:
<img width="600" alt="vm7" src="https://github.com/user-attachments/assets/ffc85fea-5059-468c-a595-f3cd138adb94" />

---
### Step 2) Log into the VM and disable the Windows Firewall 

#### Remote Desktop Connection:

<img width="600" alt="rdp" src="https://github.com/user-attachments/assets/8dd4702d-8112-40f6-94ac-8d98e7b506d9" />

#### Disable Windows Firewall 

<img width="600" alt="wf" src="https://github.com/user-attachments/assets/b2cc7376-5bc6-4cf1-82ad-e549a2c393ee" />

---

### Step 3) Run a PowerShell command: 
This command sets a registry key that allows local accounts to connect remotely with full administrative privileges without requiring elevation. 

<img width="600" alt="powershell" src="https://github.com/user-attachments/assets/7dad2e05-ecd1-4632-8203-72e80b47ea58" />

---

### Step 4) Create a Network Security Group
#### Inbound Security Rule to allow all traffic

<img width="600" alt="powershell" src="https://github.com/user-attachments/assets/cf486cee-1961-4e11-97e0-0a66e71a7028" />

#### Test the NSG using Ping Command: 

<img width="600" alt="ping command" src="https://github.com/user-attachments/assets/ee909eb2-e99b-48c9-abc9-823685faf7fa" />

---

### Step 5) Login to tenable

<img width="600" alt="tenablelogin" src="https://github.com/user-attachments/assets/65aa3c73-113b-4b85-8b79-de3a142d4e4b" />

---
### Step 6) Run a Basic Scan: Unauthenticated
#### Configure Scan basic settings

<img width="600" alt="scan" src="https://github.com/user-attachments/assets/3acb6537-65cf-4df7-8bdc-8ebb6543ceea" />

#### Scan Results
<img width="600" alt="scan results" src="https://github.com/user-attachments/assets/fa337ccc-ab06-4b78-880e-982fa3ddeab1" />

#### Tenable Vulnerability Management Report
[Tenable Vulnerability Management Report - UnAuthenticated](https://drive.google.com/file/d/11Gtks85b8GboGLymJlLQIehsnZ-NUOhL/view?usp=sharing)


---

### Step 7) Run a Basic Scan: Authenticated
#### Configure Credentials

<img width="600" alt="credentials" src="https://github.com/user-attachments/assets/d91cbe35-6577-434a-99b7-23db1c4b0ac6" />

#### Scan Results
<img width="600" alt="scan results" src="https://github.com/user-attachments/assets/9b1c8f8e-0ff2-45d8-80a6-c801e99d5fe8" />

#### Tenable Vulnerability Management Report
[Tenable Vulnerability Management Report - Authenticated](https://drive.google.com/file/d/1crKF3tikhzv756wu7t05l9pV3MXs9rhR/view?usp=sharing)


---
### Difference in Scan Duration

![scantime](https://github.com/user-attachments/assets/c2f715f4-fbdb-429e-9fd5-d9aa93477e94)
