# LAB: Endpoint Sensing with Sysmon

Owner: Eric Starace
Last edited by: Eric Starace

# Lab: Endpoint Sensing with Sysmon

## Cyber Defense Infrastructure Support Specialist Course

**Estimated Completion Time:** 2-3 hours

**Prerequisites:** Module 7 Sections 7.1-7.2 (Sensing Capabilities), Basic Windows administration

**Lab Type:** Hands-on technical deployment and configuration

---

## Lab Overview

This lab focuses on deploying and configuring Sysmon (System Monitor) as an endpoint sensing capability. Sysmon provides detailed information about process creations, network connections, and changes to file creation time—critical data for detecting adversary activity on Windows endpoints. You will deploy Sysmon, configure it with a detection-focused configuration, pipeline the logs to an Elastic Stack instance, and verify successful log collection.

### Sensing Capability Alignment

This lab implements the **Endpoint Awareness** sensing capability per CWP 3-2.1:

> “Endpoint Awareness sensing capabilities should provide data in-band on endpoint behavior and support both signature and heuristic-based determination of required reporting.”
> 

Sysmon provides visibility into:
- Process creation and command-line arguments
- Network connections initiated by processes
- File creation time changes (timestomping detection)
- Driver and DLL loading
- Registry modifications
- Named pipe creation and connection
- WMI activity

### Lab Objectives

Upon completion of this lab, you will be able to:

1. Install and configure Sysmon on Windows endpoints
2. Apply a security-focused Sysmon configuration
3. Configure Winlogbeat to forward Sysmon logs to Elasticsearch
4. Verify log ingestion in Kibana
5. Create basic visualizations for Sysmon data
6. Generate test events and confirm detection

### KSAT Alignment

| KSAT ID | Description | Lab Section |
| --- | --- | --- |
| T2772 | Build, install, configure, and test dedicated cyber defense hardware | Parts 1-3 |
| K0059A | Knowledge of IDS/IPS tools and applications | Part 1 |
| S0227 | Skill in tuning sensors | Part 2 |
| T0471 | Coordinate with Cyber Defense Analysts to manage and administer updating of rules and signatures | Part 2 |

### Doctrinal Context

Per CWP 3-2.1, Endpoint Awareness data “should be provided in-band, via roll-up reporting, to an enterprise endpoint data repository that supports real-time situational awareness processing and visualization.”

This lab implements that requirement by:
- Deploying Sysmon as the endpoint sensor
- Using Winlogbeat for roll-up reporting
- Forwarding to Elasticsearch as the data repository
- Using Kibana for visualization

---

## Lab Environment

### Required Systems

| System | Role | IP Address | OS |
| --- | --- | --- | --- |
| **YOURSERVER-ELASTIC** | Elasticsearch/Kibana Server | 192.168.10.100 | Ubuntu Server 22.04 LTS |
| **YOURSERVER-DC01** | Domain Controller (optional) | 192.168.10.10 | Windows Server 2019/2022 |
| **YOURWORKSTATION** | Windows Endpoint (primary target) | 192.168.10.50 | Windows 10/11 |

### Network Requirements

- All systems on same network segment (192.168.10.0/24)
- Windows endpoint can reach Elastic server on port 9200
- Kibana accessible on port 5601
- Internet access for downloading packages (or local repository)

### Software Requirements

| Software | Version | Purpose |
| --- | --- | --- |
| **Sysmon** | Latest (v15+) | Windows system monitoring |
| **Sysmon Configuration** | SwiftOnSecurity or Olaf Hartong | Detection-focused ruleset |
| **Winlogbeat** | 8.x | Log shipping to Elasticsearch |
| **Elasticsearch** | 8.x | Log storage and indexing |
| **Kibana** | 8.x | Visualization and analysis |

### Pre-Lab Checklist

Before starting, verify:

- [ ]  Elastic Stack is installed and running on the Ubuntu server
- [ ]  Kibana is accessible at http://192.168.10.100:5601
- [ ]  Windows endpoint has administrative access
- [ ]  Network connectivity between all systems
- [ ]  You have documented the Elastic Stack credentials

---

## Part 1: Elastic Stack Verification

**Estimated Time:** 20 minutes

Before deploying Sysmon, verify your Elastic Stack is operational and ready to receive logs.

### Task 1.1: Verify Elasticsearch Status

On the Ubuntu Elastic server, verify Elasticsearch is running:

```bash
# Check Elasticsearch service status
sudo systemctl status elasticsearch

# Verify Elasticsearch is responding
curl -X GET "localhost:9200" -u elastic:YOUR_PASSWORD

# Expected output includes cluster name and version
```

**Expected Output:**

```json
{
  "name" : "elastic-server",
  "cluster_name" : "elasticsearch",
  "cluster_uuid" : "...",
  "version" : {
    "number" : "8.x.x",
    ...
  },
  "tagline" : "You Know, for Search"
}
```

### Task 1.2: Verify Kibana Status

```bash
# Check Kibana service status
sudo systemctl status kibana

# Access Kibana in browser
# Navigate to: http://192.168.10.100:5601
```

Log in to Kibana and verify the home page loads successfully.

### Task 1.3: Document Elastic Configuration

Record the following for use in later tasks:

| Configuration Item | Value |
| --- | --- |
| Elasticsearch URL |  |
| Elasticsearch Port |  |
| Kibana URL |  |
| Elastic Username |  |
| Elastic Password |  |
| SSL/TLS Enabled? |  |

### ✅ Checkpoint 1

Before proceeding, verify:
- [ ] Elasticsearch responds to API requests
- [ ] Kibana web interface is accessible
- [ ] You have documented all connection details

---

## Part 2: Sysmon Deployment and Configuration

**Estimated Time:** 45 minutes

### Task 2.1: Download Sysmon

On the Windows endpoint (YOURWORKSTATION), open PowerShell as Administrator:

```powershell
# Create tools directory
New-Item -ItemType Directory -Path "C:\Tools\Sysmon" -Force

# Download Sysmon from Sysinternals
$SysmonURL = "https://download.sysinternals.com/files/Sysmon.zip"
Invoke-WebRequest -Uri $SysmonURL -OutFile "C:\Tools\Sysmon\Sysmon.zip"

# Extract Sysmon
Expand-Archive -Path "C:\Tools\Sysmon\Sysmon.zip" -DestinationPath "C:\Tools\Sysmon" -Force

# Verify files
Get-ChildItem "C:\Tools\Sysmon"
```

**Expected Files:**
- Sysmon.exe (32-bit)
- Sysmon64.exe (64-bit)
- Sysmon64a.exe (ARM64)
- Eula.txt

### Task 2.2: Download Sysmon Configuration

Download a security-focused Sysmon configuration. This lab uses the SwiftOnSecurity configuration as a baseline:

```powershell
# Download SwiftOnSecurity Sysmon config
$ConfigURL = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
Invoke-WebRequest -Uri $ConfigURL -OutFile "C:\Tools\Sysmon\sysmonconfig.xml"

# Verify download
Get-Content "C:\Tools\Sysmon\sysmonconfig.xml" | Select-Object -First 20
```

### Task 2.3: Review Sysmon Configuration

Before installing, review key configuration elements:

```powershell
# Open configuration for review
notepad "C:\Tools\Sysmon\sysmonconfig.xml"
```

**Key Configuration Sections to Understand:**

| Event ID | Event Type | Description |
| --- | --- | --- |
| 1 | Process Creation | New process with full command line |
| 3 | Network Connection | TCP/UDP connections with process info |
| 7 | Image Loaded | DLL loading (can be verbose) |
| 8 | CreateRemoteThread | Thread injection detection |
| 10 | ProcessAccess | Process memory access (LSASS monitoring) |
| 11 | FileCreate | File creation events |
| 12-14 | Registry Events | Registry modifications |
| 15 | FileCreateStreamHash | Alternate data streams |
| 17-18 | Pipe Events | Named pipe activity |
| 22 | DNS Query | DNS resolution logging |

**Configuration Analysis Questions:**

1. Which Event IDs are enabled in the configuration?
    
    ```
    Your answer:
    ```
    
2. What filtering is applied to Process Creation (Event ID 1)?
    
    ```
    Your answer:
    ```
    
3. Why might some events be excluded by default?
    
    ```
    Your answer:
    ```
    

### Task 2.4: Install Sysmon

Install Sysmon with the downloaded configuration:

```powershell
# Navigate to Sysmon directory
Set-Location "C:\Tools\Sysmon"

# Install Sysmon with configuration (use 64-bit version for modern systems)
.\Sysmon64.exe -accepteula -i sysmonconfig.xml

# Verify installation
Get-Service Sysmon64
```

**Expected Output:**

```
Status   Name               DisplayName
------   ----               -----------
Running  Sysmon64           Sysmon64
```

### Task 2.5: Verify Sysmon Operation

Verify Sysmon is generating events:

```powershell
# Check Sysmon driver is loaded
fltMC.exe

# View recent Sysmon events
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 |
    Format-Table TimeCreated, Id, Message -Wrap

# Count events by type
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1000 |
    Group-Object Id |
    Sort-Object Count -Descending |
    Format-Table Name, Count
```

### Task 2.6: Generate Test Events

Generate specific events to verify Sysmon detection:

```powershell
# Event ID 1 - Process Creation
# Simply running commands creates process events
whoami
ipconfig /all
net user

# Event ID 3 - Network Connection
# Make an outbound connection
Test-NetConnection -ComputerName 8.8.8.8 -Port 443

# Event ID 11 - File Creation
# Create a test file
New-Item -Path "C:\Temp\sysmon-test.txt" -ItemType File -Value "Test file for Sysmon" -Force

# Event ID 22 - DNS Query (if enabled)
Resolve-DnsName google.com
```

### Task 2.7: Verify Test Events in Event Viewer

Open Event Viewer and navigate to:
**Applications and Services Logs > Microsoft > Windows > Sysmon > Operational**

Verify you can see:
- Process Creation events (ID 1) for commands you ran
- Network Connection events (ID 3) for the Test-NetConnection
- File Create events (ID 11) for the test file

**Screenshot Checkpoint:** Capture a screenshot showing Sysmon events in Event Viewer.

### ✅ Checkpoint 2

Before proceeding, verify:
- [ ] Sysmon service is running
- [ ] Sysmon driver is loaded (visible in fltMC output)
- [ ] Events are appearing in the Sysmon Operational log
- [ ] You can identify Process Creation, Network, and File events
- [ ] Screenshot captured

---

## Part 3: Configure Log Pipeline to Elastic

**Estimated Time:** 45 minutes

### Task 3.1: Download and Install Winlogbeat

Winlogbeat is the Elastic Beat for shipping Windows Event Logs to Elasticsearch.

```powershell
# Create directory for Winlogbeat
New-Item -ItemType Directory -Path "C:\Program Files\Winlogbeat" -Force

# Download Winlogbeat (adjust version as needed)
$WinlogbeatVersion = "8.11.0"
$WinlogbeatURL = "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-$WinlogbeatVersion-windows-x86_64.zip"
Invoke-WebRequest -Uri $WinlogbeatURL -OutFile "C:\Temp\winlogbeat.zip"

# Extract
Expand-Archive -Path "C:\Temp\winlogbeat.zip" -DestinationPath "C:\Temp" -Force

# Move to Program Files
Move-Item -Path "C:\Temp\winlogbeat-$WinlogbeatVersion-windows-x86_64\*" -Destination "C:\Program Files\Winlogbeat" -Force

# Verify installation
Get-ChildItem "C:\Program Files\Winlogbeat"
```

### Task 3.2: Configure Winlogbeat

Edit the Winlogbeat configuration to collect Sysmon logs and send to Elasticsearch:

```powershell
# Open configuration file
notepad "C:\Program Files\Winlogbeat\winlogbeat.yml"
```

Replace the contents with the following configuration (adjust IP addresses and credentials):

```yaml
###################### Winlogbeat Configuration #######################

#======================== Winlogbeat Inputs ===========================
winlogbeat.event_logs:
  # Sysmon Operational Log - PRIMARY FOCUS
-name: Microsoft-Windows-Sysmon/Operational
processors:
-add_tags:
tags:[sysmon, endpoint]

  # Windows Security Log (authentication events)
-name: Security
event_id: 4624, 4625, 4634, 4648, 4672, 4688, 4697, 4698, 4699, 4700, 4701, 4702, 4768, 4769, 4770, 4771, 4776
processors:
-add_tags:
tags:[windows-security, authentication]

  # PowerShell Operational Log
-name: Microsoft-Windows-PowerShell/Operational
event_id: 4103, 4104
processors:
-add_tags:
tags:[powershell, scripting]

  # Windows System Log (service events)
-name: System
event_id: 7034, 7035, 7036, 7040, 7045
processors:
-add_tags:
tags:[windows-system, services]

#======================== Processors ==================================
processors:
-add_host_metadata:
when.not.contains.tags: forwarded
-add_cloud_metadata:~

#======================== Outputs =====================================

#-------------------------- Elasticsearch Output -----------------------
output.elasticsearch:
hosts:["192.168.10.100:9200"]
username:"elastic"
password:"YOUR_ELASTIC_PASSWORD"

  # If using SSL/TLS (recommended for production)
  # ssl.enabled: true
  # ssl.certificate_authorities: ["/path/to/ca.crt"]
  # ssl.verification_mode: full

  # Index naming
index:"winlogbeat-%{+yyyy.MM.dd}"

#======================== Kibana ======================================
setup.kibana:
host:"192.168.10.100:5601"
username:"elastic"
password:"YOUR_ELASTIC_PASSWORD"

#======================== Dashboards ==================================
setup.dashboards.enabled:true

#======================== Index Lifecycle Management ==================
setup.ilm.enabled: auto
setup.ilm.rollover_alias:"winlogbeat"
setup.ilm.pattern:"{now/d}-000001"

#======================== Logging =====================================
logging.level: info
logging.to_files:true
logging.files:
path: C:\ProgramData\Winlogbeat\Logs
name: winlogbeat
keepfiles:7
permissions:0640
```

**⚠️ Important:** Replace the following values with your actual configuration:
- `192.168.10.100` - Your Elasticsearch server IP
- `YOUR_ELASTIC_PASSWORD` - Your Elastic user password

### Task 3.3: Test Winlogbeat Configuration

Before installing as a service, test the configuration:

```powershell
# Navigate to Winlogbeat directory
Set-Location "C:\Program Files\Winlogbeat"

# Test configuration
.\winlogbeat.exe test config -c winlogbeat.yml

# Test Elasticsearch connectivity
.\winlogbeat.exe test output -c winlogbeat.yml
```

**Expected Output (Configuration):**

```
Config OK
```

**Expected Output (Connection):**

```
elasticsearch: 192.168.10.100:9200...
  parse url... OK
  connection...
    parse host... OK
    dns lookup... OK
    addresses: 192.168.10.100
    dial up... OK
  TLS... WARN secure connection disabled
  talk to server... OK
  version: 8.x.x
```

### Task 3.4: Setup Kibana Dashboards

Load the built-in Winlogbeat dashboards:

```powershell
# Setup dashboards (this may take a few minutes)
.\winlogbeat.exe setup --dashboards -c winlogbeat.yml

# Setup index template
.\winlogbeat.exe setup --index-management -c winlogbeat.yml
```

### Task 3.5: Install Winlogbeat as a Service

```powershell
# Install as Windows service
PowerShell.exe -ExecutionPolicy UnRestricted -File .\install-service-winlogbeat.ps1

# Start the service
Start-Service winlogbeat

# Verify service status
Get-Service winlogbeat
```

**Expected Output:**

```
Status   Name               DisplayName
------   ----               -----------
Running  winlogbeat         winlogbeat
```

### Task 3.6: Verify Winlogbeat Logs

Check Winlogbeat is running without errors:

```powershell
# Check Windows Event Log for Winlogbeat
Get-WinEvent -ProviderName "winlogbeat" -MaxEvents 10 -ErrorAction SilentlyContinue

# Check Winlogbeat log file
Get-Content "C:\ProgramData\Winlogbeat\Logs\winlogbeat" -Tail 20
```

Look for messages indicating successful connection to Elasticsearch and events being published.

### ✅ Checkpoint 3

Before proceeding, verify:
- [ ] Winlogbeat configuration test passes
- [ ] Elasticsearch connectivity test succeeds
- [ ] Winlogbeat service is running
- [ ] No errors in Winlogbeat logs

---

## Part 4: Verify Log Collection in Elastic

**Estimated Time:** 30 minutes

### Task 4.1: Verify Index Creation in Kibana

1. Open Kibana in your browser: `http://192.168.10.100:5601`
2. Navigate to **Management > Stack Management > Index Management**
3. Look for indices starting with `winlogbeat-`

**Expected:** You should see indices like `winlogbeat-2024.01.15` (with current date)

### Task 4.2: Create Data View

1. Navigate to **Management > Stack Management > Data Views**
2. Click **Create data view**
3. Configure:
    - Name: `Sysmon Logs`
    - Index pattern: `winlogbeat-*`
    - Timestamp field: `@timestamp`
4. Click **Save data view to Kibana**

### Task 4.3: Explore Sysmon Data in Discover

1. Navigate to **Analytics > Discover**
2. Select the `Sysmon Logs` data view
3. Set time range to **Last 15 minutes**
4. You should see events appearing

**Filter for Sysmon Events Only:**

Add a filter:
- Field: `winlog.channel`
- Operator: `is`
- Value: `Microsoft-Windows-Sysmon/Operational`

### Task 4.4: Examine Sysmon Event Structure

Click on a Sysmon Event ID 1 (Process Creation) and examine the fields:

| Field | Description | Example Value |
| --- | --- | --- |
| `winlog.event_id` | Sysmon event type | 1 |
| `winlog.event_data.Image` | Process executable path | C:.exe |
| `winlog.event_data.CommandLine` | Full command line | cmd.exe /c whoami |
| `winlog.event_data.User` | User context | DOMAIN |
| `winlog.event_data.ParentImage` | Parent process | C:.exe |
| `winlog.event_data.ParentCommandLine` | Parent command line | explorer.exe |
| `winlog.event_data.ProcessId` | Process ID | 1234 |
| `winlog.event_data.Hashes` | File hashes | SHA256=ABC123… |

**Document three interesting Sysmon events you find:**

| Event ID | Image/Process | Interesting Observation |
| --- | --- | --- |
|  |  |  |
|  |  |  |
|  |  |  |

### Task 4.5: Generate and Verify Detection Events

On the Windows endpoint, generate suspicious-looking activity:

```powershell
# Simulate reconnaissance commands (Event ID 1)
whoami /all
net user
net localgroup administrators
systeminfo
ipconfig /all
arp -a
netstat -ano
tasklist /v

# Simulate suspicious PowerShell (Event ID 1 + PowerShell logs)
powershell -encodedcommand dwBoAG8AYQBtAGkA

# Simulate network connection to external IP (Event ID 3)
Test-NetConnection -ComputerName 1.1.1.1 -Port 443

# Create file in suspicious location (Event ID 11)
New-Item -Path "C:\Windows\Temp\suspicious-file.txt" -ItemType File -Value "test" -Force
```

### Task 4.6: Query for Suspicious Events in Kibana

In Discover, use the following KQL (Kibana Query Language) queries:

**Find reconnaissance commands:**

```
winlog.event_id: 1 AND (winlog.event_data.CommandLine: *whoami* OR winlog.event_data.CommandLine: *net user* OR winlog.event_data.CommandLine: *systeminfo*)
```

**Find encoded PowerShell:**

```
winlog.event_id: 1 AND winlog.event_data.CommandLine: *encodedcommand*
```

**Find network connections:**

```
winlog.event_id: 3 AND winlog.event_data.DestinationPort: 443
```

**Screenshot Checkpoint:** Capture screenshots showing:
1. Events appearing in Kibana Discover
2. A filtered view showing only Sysmon events
3. The detail view of a Process Creation event

### ✅ Checkpoint 4

Before proceeding, verify:
- [ ] Winlogbeat index exists in Kibana
- [ ] Data view created successfully
- [ ] Sysmon events visible in Discover
- [ ] Can filter and query for specific event types
- [ ] Generated test events are visible in Kibana
- [ ] Screenshots captured

---

## Part 5: Create Sysmon Visualization Dashboard

**Estimated Time:** 30 minutes

### Task 5.1: Create Event Type Distribution Visualization

1. Navigate to **Analytics > Visualize Library**
2. Click **Create visualization**
3. Select **Lens**
4. Configure:
    - Index pattern: `winlogbeat-*`
    - Visualization type: **Pie chart**
    - Slice by: `winlog.event_id` (Top 10)
    - Add filter: `winlog.channel: Microsoft-Windows-Sysmon/Operational`
5. Save as: `Sysmon - Event Type Distribution`

### Task 5.2: Create Process Creation Timeline

1. Create new visualization (Lens)
2. Configure:
    - Visualization type: **Bar vertical stacked**
    - Horizontal axis: `@timestamp` (Date histogram)
    - Vertical axis: Count
    - Break down by: `winlog.event_data.Image` (Top 10)
    - Add filter: `winlog.event_id: 1`
3. Save as: `Sysmon - Process Creation Timeline`

### Task 5.3: Create Network Connections Table

1. Create new visualization (Lens)
2. Configure:
    - Visualization type: **Table**
    - Rows:
        - `winlog.event_data.Image`
        - `winlog.event_data.DestinationIp`
        - `winlog.event_data.DestinationPort`
    - Metrics: Count
    - Add filter: `winlog.event_id: 3`
3. Save as: `Sysmon - Network Connections`

### Task 5.4: Create Sysmon Dashboard

1. Navigate to **Analytics > Dashboard**
2. Click **Create dashboard**
3. Add the three visualizations you created
4. Add additional panels:
    - **Saved Search:** Recent Sysmon Events (from Discover)
    - **Metric:** Total Event Count
5. Arrange panels logically
6. Save as: `Sysmon Endpoint Monitoring`

### Task 5.5: Test Dashboard with New Activity

Generate activity on the Windows endpoint and refresh the dashboard:

```powershell
# Generate varied activity
Start-Process notepad
Start-Process calc
ping 8.8.8.8
nslookup google.com
```

Verify the dashboard updates with new events.

**Screenshot Checkpoint:** Capture a screenshot of your completed Sysmon dashboard.

---

## Lab Assessment

### Knowledge Check Questions

Answer the following questions based on your lab experience:

1. What Windows Event Log channel does Sysmon write to?
    
    **A.** Security
    
    **B.** System
    
    **C.** Microsoft-Windows-Sysmon/Operational
    
    **D.** Application
    
2. Which Sysmon Event ID captures process creation with command-line arguments?
    
    **A.** Event ID 3
    
    **B.** Event ID 1
    
    **C.** Event ID 11
    
    **D.** Event ID 22
    
3. What is the purpose of using a Sysmon configuration file like SwiftOnSecurity’s?
    
    **A.** To disable Sysmon logging
    
    **B.** To filter events and reduce noise while capturing security-relevant data
    
    **C.** To encrypt Sysmon logs
    
    **D.** To send logs directly to Elasticsearch
    
4. In the Elastic Stack, which component is responsible for shipping Windows logs to Elasticsearch?
    
    **A.** Kibana
    
    **B.** Logstash
    
    **C.** Winlogbeat
    
    **D.** Filebeat
    
5. Per CWP 3-2.1, Endpoint Awareness data should be provided how?
    
    **A.** Out-of-band only
    
    **B.** In-band via roll-up reporting
    
    **C.** Through manual collection
    
    **D.** Via email alerts only
    
- **Click to reveal Answer Key**
    1. **C** - Microsoft-Windows-Sysmon/Operational
    2. **B** - Event ID 1 (Process Creation)
    3. **B** - To filter events and reduce noise while capturing security-relevant data
    4. **C** - Winlogbeat
    5. **B** - In-band via roll-up reporting

### Practical Validation

Complete the following validation tasks and document your results:

| Validation Task | Status | Evidence/Notes |
| --- | --- | --- |
| Sysmon service running | ☐ Pass ☐ Fail |  |
| Sysmon events in Event Viewer | ☐ Pass ☐ Fail |  |
| Winlogbeat service running | ☐ Pass ☐ Fail |  |
| Events visible in Kibana | ☐ Pass ☐ Fail |  |
| Can filter by Event ID | ☐ Pass ☐ Fail |  |
| Dashboard displays data | ☐ Pass ☐ Fail |  |
| Generated events detected | ☐ Pass ☐ Fail |  |

---

## Troubleshooting Guide

### Sysmon Issues

**Problem:** Sysmon service not starting

```powershell
# Check service status
Get-Service Sysmon64

# Check for errors in System event log
Get-WinEvent -LogName System -MaxEvents 50 | Where-Object {$_.ProviderName -like "*Sysmon*"}

# Try reinstalling
.\Sysmon64.exe -u force
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

**Problem:** No events in Sysmon log

```powershell
# Verify Sysmon driver loaded
fltMC.exe | Select-String "SysmonDrv"

# Check configuration is loaded
.\Sysmon64.exe -c

# Generate guaranteed event
cmd.exe /c echo test
```

### Winlogbeat Issues

**Problem:** Configuration test fails

```powershell
# Validate YAML syntax (common issue: tabs vs spaces)
.\winlogbeat.exe test config -c winlogbeat.yml -e

# Check for permission issues
icacls "C:\Program Files\Winlogbeat\winlogbeat.yml"
```

**Problem:** Cannot connect to Elasticsearch

```powershell
# Test network connectivity
Test-NetConnection -ComputerName 192.168.10.100 -Port 9200

# Test with curl (if available)
curl -u elastic:password http://192.168.10.100:9200

# Check firewall
Get-NetFirewallRule | Where-Object {$_.Direction -eq "Outbound" -and $_.Action -eq "Block"}
```

**Problem:** Events not appearing in Kibana

```powershell
# Check Winlogbeat logs
Get-Content "C:\ProgramData\Winlogbeat\Logs\winlogbeat" -Tail 50

# Look for specific errors
Select-String -Path "C:\ProgramData\Winlogbeat\Logs\winlogbeat" -Pattern "error|failed"

# Restart service
Restart-Service winlogbeat
```

### Kibana Issues

**Problem:** Index not appearing

1. Check Index Management for index health
2. Verify index pattern matches actual index name
3. Check time range in Discover (events may be outside selected range)
4. Verify Elasticsearch received data:

```bash
# On Elastic server
curl -u elastic:password "localhost:9200/_cat/indices?v" | grep winlogbeat
```

---

## Lab Completion Checklist

Before submitting this lab, verify:

- [ ]  Sysmon installed and running on Windows endpoint
- [ ]  Sysmon generating events visible in Event Viewer
- [ ]  Winlogbeat configured and running as service
- [ ]  Logs flowing to Elasticsearch (index exists)
- [ ]  Data view created in Kibana
- [ ]  Can query and filter Sysmon events in Discover
- [ ]  Created at least one visualization
- [ ]  Created Sysmon monitoring dashboard
- [ ]  Completed all knowledge check questions
- [ ]  Documented validation task results
- [ ]  Captured all required screenshots

### Screenshots Required

1. Sysmon events in Windows Event Viewer
2. Winlogbeat service running
3. Sysmon events in Kibana Discover
4. Process Creation event detail view
5. Completed Sysmon dashboard

---

## Extension Challenges (Optional)

If you complete the lab early, attempt these advanced tasks:

### Challenge 1: Custom Sysmon Rule

Add a custom rule to your Sysmon configuration to detect:
- Processes launched from the Downloads folder
- Document your rule and test it

### Challenge 2: Detection Alert

Create a Kibana alert that triggers when:
- More than 5 failed login attempts occur in 5 minutes
- Encoded PowerShell commands are detected

### Challenge 3: Sysmon Configuration Comparison

Download and compare multiple Sysmon configurations:
- SwiftOnSecurity
- Olaf Hartong (sysmon-modular)
- Document the differences in coverage

---

## Summary

In this lab, you implemented an endpoint sensing capability by:

1. **Deploying Sysmon** as the primary endpoint sensor for process, network, and file activity
2. **Configuring a security-focused ruleset** that balances visibility with noise reduction
3. **Establishing a log pipeline** using Winlogbeat to forward events to Elasticsearch
4. **Verifying log collection** in Kibana with filtering and querying
5. **Creating visualizations** to support real-time situational awareness

This implementation aligns with CWP 3-2.1 requirements for Endpoint Awareness, providing:
- In-band data collection on endpoint behavior
- Roll-up reporting to a central data repository
- Real-time visualization and analysis capability

**Proceed to Lab 7B: Host-Based Detection with Wazuh**

---

*Document Version: 1.0*

*Last Updated: December 2024*

*Classification: UNCLASSIFIED // FOR TRAINING USE ONLY*