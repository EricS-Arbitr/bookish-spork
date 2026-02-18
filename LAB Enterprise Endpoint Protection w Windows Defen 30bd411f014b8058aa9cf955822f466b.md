# LAB: Enterprise Endpoint Protection w/ Windows Defender

Owner: Eric Starace
Last edited by: Eric Starace

# Lab: Enterprise Endpoint Protection with Windows Defender

## Cyber Defense Infrastructure Support Specialist Course

| **Estimated Completion Time** | 3–4 hours |
| --- | --- |
| **Prerequisites** | Lesson 8 Sections 8.1 and 8.3; Lab 6A (Implementing Access Controls); Lab 7A (Sysmon) recommended; Basic PowerShell and Group Policy familiarity |
| **Lab Type** | Hands-on technical deployment and configuration |
| **Classification** | UNCLASSIFIED // FOR TRAINING USE ONLY |

---

## Terminal Learning Objective

Configure and validate Windows Defender as an enterprise endpoint protection platform with centralized Group Policy management, advanced protection features, log collection to Elasticsearch, and operational monitoring dashboards.

## Enabling Learning Objectives

| ELO | Objective |
| --- | --- |
| 8A.1 | Assess the baseline Windows Defender configuration on a domain-joined endpoint using PowerShell |
| 8A.2 | Create and link an enterprise Group Policy Object for centralized Windows Defender management |
| 8A.3 | Configure advanced protection features including Attack Surface Reduction rules, Network Protection, and Cloud-Delivered Protection |
| 8A.4 | Establish a log pipeline using Winlogbeat to forward Windows Defender events to Elasticsearch |
| 8A.5 | Verify detection capability using the EICAR test file and validate alert ingestion in Kibana |
| 8A.6 | Create Kibana visualizations and a monitoring dashboard for endpoint protection events |

## Tools Implemented / Required

| Tool | Purpose | Type |
| --- | --- | --- |
| Windows Defender | Endpoint anti-malware protection | Endpoint Protection Platform |
| Group Policy Management Console | Centralized policy deployment | Policy Management |
| PowerShell | Configuration and verification | Administration Tool |
| Winlogbeat | Windows event log shipping | Log Shipper |
| Elasticsearch | Log storage and indexing | Data Repository |
| Kibana | Visualization and analysis | Dashboard |

## KSAT Alignment

| KSAT ID | Type | Description |
| --- | --- | --- |
| K0059A | Knowledge (Core) | Knowledge of IDS/IPS tools and applications |
| S0896 | Skill (Additional) | Skill in protecting a network against malware |
| T0471 | Task (Additional) | Coordinate with Cyber Defense Analysts to manage and administer the updating of rules and signatures for specialized cyber defense applications |
| T0769 | Task (Additional) | Perform system administration on specialized cyber defense applications and systems |
| T2772 | Task (Core) | Build, install, configure, and test dedicated cyber defense hardware |

---

## Lab Environment

### Required Systems

| System | Role | IP Address |
| --- | --- | --- |
| Windows Server 2019/2022 | Domain Controller (DC01) | 192.168.10.5 |
| Windows 10/11 Workstation | Domain-joined endpoint (WS01) | 192.168.10.50 |
| Ubuntu Server 22.04 LTS | Elastic Stack (YOURSERVER) | 192.168.10.100 |

### Assumptions

- Active Directory Domain Services are configured and operational on DC01.
- WS01 is joined to the domain.
- Elasticsearch and Kibana are installed and running on the Ubuntu server (192.168.10.100). If you completed Lab 7A or 7B, this infrastructure is already in place.
- All systems can communicate on the 192.168.10.0/24 network.
- You have domain administrator credentials.

---

## Part 1: Assessing Baseline Windows Defender Configuration

**Estimated Time:** 30 minutes

**ELO Mapping:** 8A.1

### Background

Before modifying any endpoint protection configuration, a Cyber Defense Infrastructure Support Specialist must first assess the current state. This provides a baseline for comparison after changes and helps identify any existing misconfigurations.

### Step 1.1: Check Defender Service Status

On WS01, open an elevated PowerShell session and verify that Windows Defender is operational:

```powershell
# Check Defender overall status
Get-MpComputerStatus | Select-Object AMRunningMode, AMServiceEnabled,
    AntispywareEnabled, AntivirusEnabled, BehaviorMonitorEnabled,
    IoavProtectionEnabled, NISEnabled, RealTimeProtectionEnabled
```

Record the output in the table below:

| Setting | Value |
| --- | --- |
| AMRunningMode |  |
| AMServiceEnabled |  |
| AntispywareEnabled |  |
| AntivirusEnabled |  |
| BehaviorMonitorEnabled |  |
| IoavProtectionEnabled |  |
| NISEnabled |  |
| RealTimeProtectionEnabled |  |

### Step 1.2: Review Current Preferences

Examine the current Defender preference settings:

```powershell
# View all current preferences
Get-MpPreference | Select-Object DisableRealtimeMonitoring,
    DisableBehaviorMonitoring, DisableIOAVProtection,
    MAPSReporting, SubmitSamplesConsent,
    EnableNetworkProtection, CloudBlockLevel,
    ScanScheduleDay, ScanScheduleTime
```

Record the current preferences:

| Preference | Current Value |
| --- | --- |
| DisableRealtimeMonitoring |  |
| DisableBehaviorMonitoring |  |
| MAPSReporting |  |
| SubmitSamplesConsent |  |
| EnableNetworkProtection |  |
| CloudBlockLevel |  |
| ScanScheduleDay |  |
| ScanScheduleTime |  |

### Step 1.3: Check Signature Status

Verify the current signature (definition) versions and age:

```powershell
# Check signature versions and dates
Get-MpComputerStatus | Select-Object AntivirusSignatureVersion,
    AntivirusSignatureLastUpdated, AntispywareSignatureVersion,
    AntispywareSignatureLastUpdated, NISSignatureVersion,
    NISSignatureLastUpdated
```

If signatures are more than 24 hours old, update them:

```powershell
Update-MpSignature
```

**Capture a screenshot of the baseline status and signature information.**

### Knowledge Check: Baseline Assessment

1. During your baseline assessment, you discover that `MAPSReporting` is set to `0` (Disabled). What does this mean for the endpoint’s protection capability?
    1. The endpoint cannot perform local scans
    2. Real-time protection is disabled
    3. **The endpoint is not sending telemetry to Microsoft’s cloud protection service, reducing its ability to detect zero-day and emerging threats**
    4. Signature updates are blocked
    
    💡
    Microsoft Active Protection Service (MAPS) is the cloud-based protection component of Windows Defender. When disabled, the endpoint relies entirely on local signature definitions and heuristics for detection. Enabling MAPS provides access to cloud-based machine learning models and rapid response definitions that can detect emerging threats before traditional signatures are released.
    

---

## Part 2: Creating Enterprise GPO for Centralized Management

**Estimated Time:** 45 minutes

**ELO Mapping:** 8A.2

### Background

In enterprise environments, Windows Defender settings are managed centrally through Group Policy rather than configured individually on each endpoint. This ensures consistent protection baselines across all workstations and prevents users from weakening security settings.

### Step 2.1: Create the GPO

On DC01, open the Group Policy Management Console:

```powershell
gpmc.msc
```

1. Expand your domain in the left pane.
2. Right-click the OU containing your workstations and select **Create a GPO in this domain, and Link it here…**
3. Name the GPO: **Endpoint Protection – Windows Defender**
4. Click **OK**.
5. Right-click the new GPO and select **Edit**.

### Step 2.2: Configure Real-Time Protection

Navigate to: **Computer Configuration > Policies > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Real-time Protection**

Configure the following settings:

| Setting | Value |
| --- | --- |
| Turn on behavior monitoring | Enabled |
| Scan all downloaded files and attachments | Enabled |
| Monitor file and program activity on your computer | Enabled |
| Turn on process scanning whenever real-time protection is enabled | Enabled |

For each setting, double-click it, select **Enabled**, and click **OK**.

### Step 2.3: Configure MAPS (Cloud Protection)

Navigate to: **Computer Configuration > Policies > Administrative Templates > Windows Components > Microsoft Defender Antivirus > MAPS**

| Setting | Value |
| --- | --- |
| Join Microsoft MAPS | Enabled → Advanced MAPS |
| Configure the ‘Block at First Sight’ feature | Enabled |
| Send file samples when further analysis is required | Enabled → Send safe samples |

### Step 2.4: Configure Scan Settings

Navigate to: **Computer Configuration > Policies > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Scan**

| Setting | Value |
| --- | --- |
| Scan archive files | Enabled |
| Scan removable drives | Enabled |
| Turn on e-mail scanning | Enabled |
| Specify the scan type to use for a scheduled scan | Enabled → Quick scan |
| Specify the day of the week to run a scheduled scan | Enabled → 0 (Every day) |
| Specify the time of day to run a scheduled scan | Enabled → 0200 (2:00 AM) |

### Step 2.5: Configure Signature Updates

Navigate to: **Computer Configuration > Policies > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Security Intelligence Updates**

| Setting | Value |
| --- | --- |
| Specify the interval to check for security intelligence updates | Enabled → 4 (hours) |
| Define the number of days before security intelligence is considered out of date | Enabled → 2 |
| Initiate security intelligence update on startup | Enabled |

### Step 2.6: Apply and Verify

On WS01, force a Group Policy update:

```powershell
gpupdate /force
```

Verify the GPO is applied:

```powershell
gpresult /r | Select-String "Endpoint Protection"
```

Confirm the settings took effect:

```powershell
Get-MpPreference | Select-Object DisableRealtimeMonitoring,
    DisableBehaviorMonitoring, MAPSReporting,
    SubmitSamplesConsent, ScanScheduleDay, ScanScheduleTime,
    SignatureUpdateInterval
```

Compare the values to your baseline from Part 1. The settings should now reflect the GPO configuration.

**Capture a screenshot of the updated preferences showing GPO-applied values.**

### Knowledge Check: Centralized Management

1. An administrator configures Windows Defender locally on a workstation, but a GPO also defines Defender settings. Which configuration takes precedence?
    1. The local configuration always wins
    2. Whichever was configured most recently
    3. **The Group Policy settings override local configuration**
    4. They merge together, with the most restrictive setting winning
    
    💡
    Group Policy settings override local configuration for the same settings. This is by design — GPOs enforce enterprise-wide baselines that individual users or local administrators cannot weaken. If a GPO defines a setting, the local preference for that same setting is ignored.
    

---

## Part 3: Configuring Advanced Protection Features

**Estimated Time:** 30 minutes

**ELO Mapping:** 8A.3

### Background

Windows Defender provides advanced protection features beyond traditional antivirus scanning. Attack Surface Reduction (ASR) rules block specific behaviors commonly used by malware, Network Protection blocks connections to known malicious domains, and Cloud-Delivered Protection leverages cloud analysis for faster threat identification.

### Step 3.1: Enable Attack Surface Reduction (ASR) Rules

ASR rules are configured via PowerShell or GPO. On WS01 (or through the GPO), enable the following commonly-recommended ASR rules:

```powershell
# Block executable content from email client and webmail
Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 `
    -AttackSurfaceReductionRules_Actions Enabled

# Block all Office applications from creating child processes
Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A `
    -AttackSurfaceReductionRules_Actions Enabled

# Block JavaScript or VBScript from launching downloaded executable content
Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D `
    -AttackSurfaceReductionRules_Actions Enabled

# Block execution of potentially obfuscated scripts
Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC `
    -AttackSurfaceReductionRules_Actions Enabled

# Block credential stealing from Windows LSASS
Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 `
    -AttackSurfaceReductionRules_Actions Enabled
```

Verify ASR rules are enabled:

```powershell
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions
```

> **Note:** An action value of `1` means Enabled (Block), `0` means Disabled, and `2` means Audit. In a production environment, start with Audit mode (2) to identify potential impacts before switching to Block mode (1).
> 

### Step 3.2: Enable Network Protection

Network Protection blocks outbound connections to known malicious IP addresses and domains:

```powershell
# Enable Network Protection
Set-MpPreference -EnableNetworkProtection Enabled

# Verify
Get-MpPreference | Select-Object EnableNetworkProtection
```

### Step 3.3: Configure Cloud-Delivered Protection Level

Set the cloud protection level and timeout:

```powershell
# Set cloud block level to High
Set-MpPreference -CloudBlockLevel High

# Set cloud check timeout to 50 seconds (allows more thorough cloud analysis)
Set-MpPreference -CloudExtendedTimeout 50

# Verify
Get-MpPreference | Select-Object CloudBlockLevel, CloudExtendedTimeout
```

### Step 3.4: Configure Controlled Folder Access (Optional)

Controlled Folder Access protects documents and files from ransomware:

```powershell
# Enable Controlled Folder Access in Audit mode first
Set-MpPreference -EnableControlledFolderAccess AuditMode

# Verify
Get-MpPreference | Select-Object EnableControlledFolderAccess
```

> **Important:** Controlled Folder Access can block legitimate applications from writing to protected folders (Documents, Desktop, Pictures, etc.). Always start with AuditMode and review the audit logs before switching to Enabled.
> 

**Capture a screenshot showing the ASR rules, Network Protection, and Cloud Block Level settings.**

### Knowledge Check: Advanced Features

1. You enable an Attack Surface Reduction rule in Block mode and discover that a legitimate business application is now being blocked. What is the recommended approach?
    1. Disable the ASR rule permanently
    2. Uninstall Windows Defender
    3. **Switch the rule to Audit mode, add an exclusion for the specific application, then re-enable Block mode**
    4. Configure Windows Firewall to bypass ASR
    
    💡
    ASR rules should first be deployed in Audit mode to identify legitimate applications that may be affected. When a legitimate application is blocked, create a targeted exclusion for that specific application rather than disabling the entire rule. This maintains protection while allowing necessary business operations.
    

---

## Part 4: Establishing the Log Pipeline

**Estimated Time:** 45 minutes

**ELO Mapping:** 8A.4

### Background

Forwarding Windows Defender events to a centralized log repository enables security analysts to correlate endpoint protection events across all workstations, detect patterns that individual endpoints cannot see, and maintain historical records for investigation. This exercise configures Winlogbeat to collect Defender-specific event logs and ship them to Elasticsearch.

### Step 4.1: Identify Relevant Event Logs

Windows Defender generates events in several log channels. The most important for security monitoring are:

| Log Channel | Purpose |
| --- | --- |
| Microsoft-Windows-Windows Defender/Operational | Detection events, scan results, configuration changes |
| Microsoft-Windows-Windows Defender/WHC | Windows Defender health and connectivity |

Key Event IDs to monitor:

| Event ID | Description |
| --- | --- |
| 1006 | Malware detection (action pending) |
| 1007 | Action taken on malware |
| 1008 | Action on malware failed |
| 1009 | Item restored from quarantine |
| 1013 | Malware history deleted |
| 1116 | Threat detected |
| 1117 | Action taken to protect system |
| 2001 | Signature update succeeded |
| 2003 | Signature update failed |
| 5001 | Real-time protection disabled |
| 5010 | Scanning for malware disabled |
| 5012 | Scanning for viruses disabled |

### Step 4.2: Install Winlogbeat (If Not Already Installed)

If you completed Lab 7A (Sysmon), Winlogbeat may already be installed. If not, download and install it on WS01.

Open an elevated PowerShell session:

```powershell
# Navigate to your install location
cd C:\Program Files\Winlogbeat

# If Winlogbeat is not installed, download and extract it
# (adjust version as appropriate)
# Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.x.x-windows-x86_64.zip" -OutFile winlogbeat.zip
# Expand-Archive winlogbeat.zip -DestinationPath "C:\Program Files\"
```

### Step 4.3: Configure Winlogbeat for Defender Events

Edit (or create) the Winlogbeat configuration file. If Winlogbeat is already configured for Sysmon (Lab 7A), add the Defender event log to the existing configuration rather than replacing it.

```powershell
notepad "C:\Program Files\Winlogbeat\winlogbeat.yml"
```

Add or modify the `winlogbeat.event_logs` section to include Defender events:

```yaml
winlogbeat.event_logs:
-name: Microsoft-Windows-Windows Defender/Operational
event_id: 1006, 1007, 1008, 1009, 1013, 1116, 1117, 2001, 2003, 5001, 5010, 5012
-name: Microsoft-Windows-Sysmon/Operational  # Keep if already configured from Lab 7A

output.elasticsearch:
hosts:["192.168.10.100:9200"]
username:"elastic"
password:"your_password"
index:"winlogbeat-defender-%{+yyyy.MM.dd}"

setup.template.name:"winlogbeat-defender"
setup.template.pattern:"winlogbeat-defender-*"
setup.ilm.enabled:false
```

> **Note:** If you already have a Winlogbeat configuration from Lab 7A, you can either add the Defender event log channel to the existing configuration (using one index for all Windows events) or create a separate index as shown above. Using a separate index makes it easier to build Defender-specific dashboards.
> 

### Step 4.4: Restart Winlogbeat

```powershell
# Restart the service to apply the new configuration
Restart-Service winlogbeat

# Verify the service is running
Get-Service winlogbeat | Select-Object Name, Status, StartType
```

### Step 4.5: Verify Index in Elasticsearch

On the Ubuntu server (or from any system with access to Kibana), verify that the new index is being created. Open Kibana (http://192.168.10.100:5601) and navigate to:

**Stack Management > Index Management**

Look for an index matching `winlogbeat-defender-*`. If no events have occurred yet, the index may not appear until the first event is generated (which you will do in Part 5).

Alternatively, verify from the command line on the Elastic server:

```bash
curl -u elastic:your_password "localhost:9200/_cat/indices?v" | grep defender
```

### Step 4.6: Create Data View in Kibana

1. Navigate to **Stack Management > Data Views** (or **Index Patterns** in older Kibana versions).
2. Click **Create data view**.
3. Enter the index pattern: `winlogbeat-defender-*`
4. Select the timestamp field: `@timestamp`
5. Click **Create data view**.

---

## Part 5: Verifying Detection with EICAR Test

**Estimated Time:** 20 minutes

**ELO Mapping:** 8A.5

### Background

The EICAR test file is a standardized test string recognized by all antivirus products as a test threat. It is not malicious but triggers a detection event, allowing you to verify that the endpoint protection and log pipeline are functioning correctly without introducing actual malware into the environment.

### Step 5.1: Generate a Test Detection

On WS01, open an elevated PowerShell session and attempt to download the EICAR test file:

```powershell
# Create a temp directory
New-Item -Path "C:\Temp" -ItemType Directory -Force

# Attempt to download the EICAR test file
# Windows Defender should immediately detect and quarantine this
try {
    Invoke-WebRequest -Uri "https://www.eicar.org/download/eicar.com.txt" `
        -OutFile "C:\Temp\eicar.txt"
} catch {
    Write-Host "Download blocked or file quarantined (expected behavior)" -ForegroundColor Yellow
}
```

> **Note:** If the download is blocked by Network Protection before it reaches the file system, create the EICAR test string manually:
> 

```powershell
# Create EICAR test string directly (this is the standard EICAR test string)
$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
Set-Content -Path "C:\Temp\eicar_test.txt" -Value $eicar
```

### Step 5.2: Verify Local Detection

Check that Windows Defender detected the test file:

```powershell
# Check recent threat detections
Get-MpThreatDetection | Select-Object ThreatID, DetectionSourceTypeID,
    ProcessName, InitialDetectionTime, ActionSuccess

# Check threat details
Get-MpThreat | Select-Object ThreatName, IsActive, SeverityID, StatusID
```

Record your detection results:

| Field | Value |
| --- | --- |
| ThreatName |  |
| DetectionTime |  |
| ActionTaken |  |
| ActionSuccess |  |

### Step 5.3: Verify Event in Event Viewer

Open Event Viewer and navigate to:

**Applications and Services Logs > Microsoft > Windows > Windows Defender > Operational**

Look for Event ID 1116 (Threat Detected) and Event ID 1117 (Action Taken). Note the timestamp and details.

### Step 5.4: Verify Event in Kibana

Open Kibana and navigate to **Discover**. Select the `winlogbeat-defender-*` data view.

1. Set the time range to the last 15 minutes.
2. Search for the EICAR detection event. Try filtering on:
    - `event_id: 1116` or `event_id: 1117`
    - Or search for `EICAR` in the search bar
3. Expand the event and examine the fields.

**Capture a screenshot showing the EICAR detection event in Kibana.**

> **Troubleshooting:** If you do not see events in Kibana:
- Verify Winlogbeat is running: `Get-Service winlogbeat`
- Check Winlogbeat logs: `Get-Content "C:\Program Files\Winlogbeat\logs\winlogbeat" -Tail 20`
- Verify the Elasticsearch index exists: `curl -u elastic:password "localhost:9200/_cat/indices?v" | grep defender`
- Ensure the Kibana data view matches the index pattern
> 

### Knowledge Check: Detection Verification

1. You run the EICAR test and Windows Defender detects it, but no event appears in Kibana. Which of the following is the most likely cause?
    1. EICAR test files do not generate log events
    2. Kibana does not support Windows Defender logs
    3. **Winlogbeat is not configured to collect the Windows Defender Operational log channel, or the event ID filter is excluding the detection events**
    4. Elasticsearch cannot index antivirus alerts
    
    💡
    Windows Defender generates events in the Microsoft-Windows-Windows Defender/Operational log channel. If Winlogbeat is not configured to monitor this specific channel, or if the event_id filter does not include the relevant detection events (1116, 1117), the events remain in the local Event Viewer but are never forwarded to Elasticsearch.
    

---

## Part 6: Creating Visualizations and Monitoring Dashboard

**Estimated Time:** 30 minutes

**ELO Mapping:** 8A.6

### Background

A monitoring dashboard provides security analysts with at-a-glance visibility into endpoint protection status across the enterprise. Effective dashboards display threat detection trends, signature update compliance, and protection status changes.

### Step 6.1: Create a Threat Detection Count Visualization

In Kibana, navigate to **Visualize Library > Create visualization**.

1. Select **Lens** as the visualization type.
2. Set the data view to `winlogbeat-defender-*`.
3. Configure:
    - **Visualization type:** Bar vertical
    - **Horizontal axis:** `@timestamp` (Date histogram, interval: Day)
    - **Vertical axis:** Count of records
    - **Filter:** `event_id: 1116 OR event_id: 1117`
4. Title: **Defender Threat Detections Over Time**
5. Save the visualization.

### Step 6.2: Create a Threat Name Breakdown

1. Create a new Lens visualization.
2. Configure:
    - **Visualization type:** Pie chart or Donut
    - **Slice by:** A keyword field containing the threat name (field name varies by Winlogbeat version; look for fields containing “EICAR” or “Threat” in Discover)
    - **Size:** Count of records
3. Title: **Threat Detections by Name**
4. Save the visualization.

### Step 6.3: Create a Protection Status Events Table

1. Create a new Lens visualization.
2. Configure:
    - **Visualization type:** Table
    - **Rows:** `event_id` (Top values)
    - **Metric:** Count of records
    - **Filter:** `event_id: 5001 OR event_id: 5010 OR event_id: 5012 OR event_id: 2001 OR event_id: 2003`
3. Title: **Protection Status Events**
4. Save the visualization.

This table shows events where protection was disabled or signatures were updated/failed, which are critical indicators of endpoint health.

### Step 6.4: Build the Dashboard

1. Navigate to **Dashboard > Create dashboard**.
2. Click **Add from library** and add all three visualizations.
3. Arrange the panels:
    - Threat Detections Over Time (top, full width)
    - Threat Detections by Name (bottom left)
    - Protection Status Events (bottom right)
4. Title the dashboard: **Windows Defender Endpoint Protection**
5. Save the dashboard.

**Capture a screenshot of the completed dashboard.**

---

## Lab Completion Checklist

Before submitting this lab, verify:

- [ ]  Baseline Windows Defender status documented (Part 1)
- [ ]  Signature versions checked and updated if needed
- [ ]  GPO created and linked with Real-Time Protection settings
- [ ]  GPO configured with MAPS/Cloud Protection settings
- [ ]  GPO configured with Scan and Signature Update schedules
- [ ]  GPO applied and verified on WS01 with gpresult
- [ ]  ASR rules enabled and verified
- [ ]  Network Protection enabled
- [ ]  Cloud Block Level set to High
- [ ]  Winlogbeat configured for Windows Defender event log channel
- [ ]  Winlogbeat service running and forwarding events
- [ ]  Data view created in Kibana for Defender index
- [ ]  EICAR test file generated and detection confirmed locally
- [ ]  EICAR detection event visible in Kibana Discover
- [ ]  Three visualizations created
- [ ]  Monitoring dashboard assembled and saved
- [ ]  All knowledge check questions answered
- [ ]  All required screenshots captured

### Screenshots Required

1. Baseline Defender status and signature information (Part 1)
2. GPO-applied preference values (Part 2, Step 2.6)
3. ASR, Network Protection, and Cloud Block Level settings (Part 3)
4. EICAR detection event in Kibana (Part 5, Step 5.4)
5. Completed Windows Defender dashboard (Part 6, Step 6.4)

---

## Troubleshooting Guide

| Symptom | Possible Cause | Resolution |
| --- | --- | --- |
| EICAR test not detected | Real-time protection disabled | Verify: `Get-MpPreference \| Select DisableRealtimeMonitoring` |
| GPO settings not applying | WS01 not in correct OU | Check: `gpresult /r` for applied GPOs |
| ASR rule blocks legitimate app | Rule too broad for environment | Switch to Audit mode (2), add exclusion, re-enable |
| No index in Elasticsearch | Winlogbeat config error | Check Winlogbeat logs for connection/config errors |
| Events in Event Viewer but not Kibana | Event ID filter too restrictive | Broaden the event_id list in winlogbeat.yml |
| Signature update fails | No internet or proxy required | Check network connectivity and proxy settings |

---

## Extension Challenges (Optional)

### Challenge 1: Exclusion Documentation

Create a formal exclusion request document that includes the application name, file path, justification, risk acceptance, and approver. This mirrors real-world change management for AV exclusions.

### Challenge 2: ASR Audit Analysis

Set all ASR rules to Audit mode for 30 minutes while performing normal workstation activities. Analyze the audit events in Event Viewer to determine which rules would block legitimate activity and which are safe to enable in Block mode.

### Challenge 3: Multi-Endpoint Comparison

If multiple workstations are available, compare Defender status across endpoints using PowerShell remoting:

```powershell
Invoke-Command -ComputerName WS01, WS02 -ScriptBlock {
    Get-MpComputerStatus | Select-Object PSComputerName, RealTimeProtectionEnabled,
        AntivirusSignatureLastUpdated
}
```

---

## Summary

In this lab, you configured an enterprise endpoint protection deployment by:

1. **Assessing the baseline** Windows Defender configuration to establish a reference point before changes
2. **Creating a centralized GPO** that enforces consistent Defender settings including real-time protection, cloud protection, scheduled scans, and automatic signature updates
3. **Enabling advanced features** including Attack Surface Reduction rules, Network Protection, and elevated Cloud-Delivered Protection to extend protection beyond traditional signature-based detection
4. **Establishing a log pipeline** using Winlogbeat to forward Defender events to Elasticsearch for centralized analysis
5. **Validating the detection chain** end-to-end using the EICAR test file, confirming that a detection on the endpoint flows through to the SIEM
6. **Building monitoring visualizations** that provide operational awareness of endpoint protection across the enterprise

This configuration aligns with CWP 3-2.1 Endpoint Awareness sensing capability by providing centralized visibility into endpoint protection events and ensuring consistent anti-malware coverage across all domain-joined workstations.

---

*Document Version: 1.0*

*Classification: UNCLASSIFIED // FOR TRAINING USE ONLY*