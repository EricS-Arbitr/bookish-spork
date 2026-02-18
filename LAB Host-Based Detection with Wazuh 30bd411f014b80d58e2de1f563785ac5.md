# LAB: Host-Based Detection with Wazuh

Owner: Eric Starace
Last edited by: Eric Starace

# LAB: Host-Based Detection with Wazuh

## Cyber Defense Infrastructure Support Specialist Course

**Estimated Completion Time:** 3-4 hours

**Prerequisites:** Module 7 Sections 7.1-7.4, Lab 7A (Sysmon) recommended

**Lab Type:** Hands-on technical deployment and configuration

---

## Lab Overview

This lab focuses on deploying Wazuh as a comprehensive host-based intrusion detection system (HIDS) and security information and event management (SIEM) solution. Wazuh provides file integrity monitoring, rootkit detection, log analysis, and active response capabilities. You will deploy the Wazuh server, configure agents on endpoints, establish a log pipeline to Elasticsearch, and verify successful detection and alerting.

### Sensing Capability Alignment

This lab implements multiple sensing capabilities per CWP 3-2.1:

| Capability | Wazuh Function |
| --- | --- |
| **Endpoint Awareness** | Agent-based monitoring, process/file/user activity |
| **Security Alerting** | HIDS alerts, correlation rules, active response |
| **Application Logging** | Log collection and analysis from multiple sources |
| **Asset & Config Management** | System inventory, vulnerability detection, compliance checking |

Per CWP 3-2.1, Security Alerting should “provide data out-of-band on network security alerts” and “provide data to both operators for situational awareness and automated countermeasure platforms to enable response.”

### Lab Objectives

Upon completion of this lab, you will be able to:

1. Deploy Wazuh Manager on a Linux server
2. Install and configure Wazuh Agents on Windows and Linux endpoints
3. Configure Wazuh to integrate with Elasticsearch
4. Create custom detection rules for specific threat indicators
5. Verify alert generation and log ingestion in Kibana
6. Implement active response for automated threat mitigation

### KSAT Alignment

| KSAT ID | Description | Lab Section |
| --- | --- | --- |
| T2772 | Build, install, configure, and test dedicated cyber defense hardware | Parts 1-3 |
| K0059A | Knowledge of IDS/IPS tools and applications | Parts 1-2 |
| S0227 | Skill in tuning sensors | Part 4 |
| T0471 | Coordinate with Cyber Defense Analysts to manage and administer updating of rules and signatures | Part 4 |
| T0393B | Coordinate with system administrators to create cyber defense tools, test bed(s), and evaluate applications | All Parts |

### Doctrinal Context

Per CWP 3-2.1, Security Alerting technologies include:
- NIPS (Network Intrusion Prevention System)
- HIPS/Host Firewall
- Firewall
- Embedded OS Host Agents
- Proxy
- Web Application Firewall

Wazuh serves as the “Embedded OS Host Agent” and provides HIDS functionality, delivering alerts to the centralized data repository for analysis and automated response.

---

## Lab Environment

### Required Systems

| System | Role | IP Address | OS |
| --- | --- | --- | --- |
| **YOURSERVER-WAZUH** | Wazuh Manager + Elastic | 192.168.10.100 | Ubuntu Server 22.04 LTS |
| **YOURSERVER-DC01** | Windows Endpoint (Agent) | 192.168.10.10 | Windows Server 2019/2022 |
| **YOURWORKSTATION** | Windows Endpoint (Agent) | 192.168.10.50 | Windows 10/11 |
| **YOURSERVER-LINUX** | Linux Endpoint (Agent) | 192.168.10.60 | Ubuntu 22.04 LTS |

### Network Requirements

- All systems on same network segment (192.168.10.0/24)
- Wazuh Manager accessible on ports: 1514 (agent), 1515 (registration), 55000 (API)
- Elasticsearch accessible on port 9200
- Kibana accessible on port 5601
- Internet access for downloading packages (or local repository)

### Resource Requirements

| Component | Minimum RAM | Recommended RAM | Disk Space |
| --- | --- | --- | --- |
| Wazuh Manager + Elastic | 8 GB | 16 GB | 50 GB |
| Windows Agent | 512 MB | 1 GB | 500 MB |
| Linux Agent | 256 MB | 512 MB | 200 MB |

### Pre-Lab Checklist

Before starting, verify:

- [ ]  Ubuntu server meets minimum requirements
- [ ]  All endpoints can reach the Wazuh server
- [ ]  Administrative access on all systems
- [ ]  Firewall rules allow required ports
- [ ]  DNS resolution working between systems

---

## Part 1: Wazuh Manager Deployment

**Estimated Time:** 45 minutes

### Task 1.1: System Preparation

On the Ubuntu server (YOURSERVER-WAZUH), prepare the system:

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install prerequisites
sudo apt install curl apt-transport-https unzip wget -y

# Set hostname (optional but recommended)
sudo hostnamectl set-hostname wazuh-server

# Verify system resources
free -h
df -h
```

**Minimum Requirements Check:**
- RAM: At least 8 GB available
- Disk: At least 50 GB free on /
- CPU: 2+ cores recommended

### Task 1.2: Install Wazuh Indexer (Elasticsearch-based)

Wazuh 4.x uses the Wazuh Indexer (OpenSearch-based) or can integrate with Elasticsearch. For this lab, we’ll use the Wazuh all-in-one installation which includes the indexer:

```bash
# Download Wazuh installation assistant
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh

# Make executable
chmod +x wazuh-install.sh

# Run all-in-one installation
sudo ./wazuh-install.sh -a

# Installation will take 10-15 minutes
```

**⚠️ Important:** Save the generated passwords displayed at the end of installation!

```bash
# The installer will display credentials like:
# INFO: --- Summary ---
# INFO: You can access the web interface https://<wazuh-dashboard-ip>
# INFO: User: admin
# INFO: Password: <generated-password>
```

**Document your credentials:**

| Component | Username | Password |
| --- | --- | --- |
| Wazuh Dashboard | admin |  |
| Wazuh API | wazuh |  |
| Wazuh Indexer | admin |  |

### Task 1.3: Verify Wazuh Manager Installation

```bash
# Check Wazuh Manager service
sudo systemctl status wazuh-manager

# Check Wazuh Indexer service
sudo systemctl status wazuh-indexer

# Check Wazuh Dashboard service
sudo systemctl status wazuh-dashboard

# Verify all services are active
sudo systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard
```

**Expected Output:**

```
active
active
active
```

### Task 1.4: Access Wazuh Dashboard

1. Open a browser and navigate to: `https://192.168.10.100`
2. Accept the self-signed certificate warning
3. Log in with the admin credentials from installation
4. Verify the dashboard loads successfully

**Initial Dashboard View:**
- No agents connected yet (expected)
- Wazuh Manager version displayed
- No alerts initially

**Screenshot Checkpoint:** Capture a screenshot of the Wazuh Dashboard home page.

### Task 1.5: Configure Wazuh Manager for Agent Registration

Edit the Wazuh Manager configuration to enable agent registration:

```bash
# Edit ossec.conf
sudo nano /var/ossec/etc/ossec.conf
```

Verify the following section exists (should be present by default):

```xml
<ossec_config>
  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>no</use_source_ip>
    <purge>yes</purge>
    <use_password>no</use_password>
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <ssl_agent_ca></ssl_agent_ca>
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>/var/ossec/etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>/var/ossec/etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>
</ossec_config>
```

Restart the manager if changes were made:

```bash
sudo systemctl restart wazuh-manager
```

### ✅ Checkpoint 1

Before proceeding, verify:
- [ ] Wazuh Manager service is running
- [ ] Wazuh Indexer service is running
- [ ] Wazuh Dashboard is accessible via browser
- [ ] You have documented all credentials
- [ ] Screenshot captured

---

## Part 2: Wazuh Agent Deployment

**Estimated Time:** 45 minutes

### Task 2.1: Deploy Windows Agent (YOURWORKSTATION)

On the Windows endpoint, open PowerShell as Administrator:

```powershell
# Set Wazuh Manager IP
$WazuhManager = "192.168.10.100"

# Download Wazuh Agent installer
$WazuhAgentURL = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi"
Invoke-WebRequest -Uri $WazuhAgentURL -OutFile "$env:TEMP\wazuh-agent.msi"

# Install with manager configuration
msiexec.exe /i "$env:TEMP\wazuh-agent.msi" /q WAZUH_MANAGER=$WazuhManager WAZUH_REGISTRATION_SERVER=$WazuhManager

# Wait for installation
Start-Sleep -Seconds 30

# Start the Wazuh service
NET START WazuhSvc

# Verify service status
Get-Service WazuhSvc
```

**Expected Output:**

```
Status   Name               DisplayName
------   ----               -----------
Running  WazuhSvc           Wazuh
```

### Task 2.2: Verify Windows Agent Registration

Check agent registration on the manager:

```bash
# On Wazuh Manager
sudo /var/ossec/bin/agent_control -l
```

**Expected Output:**

```
Wazuh agent_control. List of available agents:
   ID: 000, Name: wazuh-server (server), IP: 127.0.0.1, Active/Local
   ID: 001, Name: YOURWORKSTATION, IP: any, Active
```

Also verify in the Wazuh Dashboard:
1. Navigate to **Agents**
2. You should see the Windows endpoint listed as “Active”

### Task 2.3: Deploy Windows Server Agent (YOURSERVER-DC01)

Repeat the agent installation on the Windows Server:

```powershell
# Set Wazuh Manager IP
$WazuhManager = "192.168.10.100"

# Download and install
$WazuhAgentURL = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi"
Invoke-WebRequest -Uri $WazuhAgentURL -OutFile "$env:TEMP\wazuh-agent.msi"
msiexec.exe /i "$env:TEMP\wazuh-agent.msi" /q WAZUH_MANAGER=$WazuhManager WAZUH_REGISTRATION_SERVER=$WazuhManager

Start-Sleep -Seconds 30
NET START WazuhSvc
Get-Service WazuhSvc
```

### Task 2.4: Deploy Linux Agent (YOURSERVER-LINUX)

On the Ubuntu endpoint:

```bash
# Add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee -a /etc/apt/sources.list.d/wazuh.list

# Update and install
sudo apt update
sudo apt install wazuh-agent -y

# Configure manager address
sudo sed -i 's/MANAGER_IP/192.168.10.100/' /var/ossec/etc/ossec.conf

# Enable and start agent
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

# Verify status
sudo systemctl status wazuh-agent
```

### Task 2.5: Configure Sysmon Integration (Windows Agents)

If you completed Lab 7A, Wazuh can collect Sysmon logs. Configure the Windows agents:

On each Windows endpoint, edit the Wazuh agent configuration:

```powershell
# Open agent configuration
notepad "C:\Program Files (x86)\ossec-agent\ossec.conf"
```

Add the following within the `<ossec_config>` section:

```xml
<!-- Sysmon Log Collection -->
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

<!-- PowerShell Operational Log -->
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

<!-- Windows Security Log (if not already present) -->
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Restart the Wazuh agent:

```powershell
NET STOP WazuhSvc
NET START WazuhSvc
```

### Task 2.6: Verify All Agents

In the Wazuh Dashboard:
1. Navigate to **Agents**
2. Verify all three agents are listed and Active

| Agent ID | Name | OS | Status |
| --- | --- | --- | --- |
| 001 | YOURWORKSTATION | Windows 10/11 | ☐ Active |
| 002 | YOURSERVER-DC01 | Windows Server | ☐ Active |
| 003 | YOURSERVER-LINUX | Ubuntu | ☐ Active |

**Screenshot Checkpoint:** Capture a screenshot showing all agents in the Wazuh Dashboard.

### ✅ Checkpoint 2

Before proceeding, verify:
- [ ] Windows workstation agent active
- [ ] Windows server agent active
- [ ] Linux agent active
- [ ] All agents visible in Wazuh Dashboard
- [ ] Screenshot captured

---

## Part 3: Configure Elastic Integration

**Estimated Time:** 30 minutes

The Wazuh all-in-one installation includes the Wazuh Indexer (based on OpenSearch), which provides Elasticsearch-compatible functionality. For environments requiring true Elasticsearch integration, follow this section.

### Option A: Using Wazuh Indexer (Default Installation)

If you used the all-in-one installation, you already have the Wazuh Indexer working with the Dashboard. Verify data is flowing:

```bash
# Check indices
curl -k -u admin:YOUR_PASSWORD "https://localhost:9200/_cat/indices?v" | grep wazuh

# Expected output shows indices like:
# wazuh-alerts-4.x-2024.01.15
# wazuh-archives-4.x-2024.01.15
```

### Option B: External Elasticsearch Integration

If you have a separate Elasticsearch cluster, configure Wazuh to forward alerts:

**Step 1: Configure Filebeat on Wazuh Manager**

```bash
# Install Filebeat
curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update && sudo apt install filebeat -y

# Download Wazuh Filebeat module
curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.7/extensions/elasticsearch/7.x/wazuh-template.json

# Configure Filebeat
sudo nano /etc/filebeat/filebeat.yml
```

Configure Filebeat to read Wazuh alerts and send to Elasticsearch:

```yaml
filebeat.modules:
-module: wazuh
alerts:
enabled:true

output.elasticsearch:
hosts:["YOUR_ELASTICSEARCH_IP:9200"]
username:"elastic"
password:"YOUR_PASSWORD"

setup.template.name:"wazuh"
setup.template.pattern:"wazuh-*"
setup.template.json.enabled:true
setup.template.json.path:"/etc/filebeat/wazuh-template.json"
setup.template.json.name:"wazuh"
setup.template.overwrite:true
```

```bash
# Start Filebeat
sudo systemctl enable filebeat
sudo systemctl start filebeat

# Verify Filebeat is running
sudo systemctl status filebeat
```

### Task 3.1: Verify Data in Dashboard

Navigate to the Wazuh Dashboard and verify alerts are appearing:

1. Go to **Security Events**
2. Set time range to **Last 24 hours**
3. You should see authentication events, file integrity events, etc.

### Task 3.2: Explore Wazuh Indices

In the Wazuh Dashboard (or Kibana if using external Elasticsearch):

1. Navigate to **Stack Management > Index Management** (or **Indexer Management** in Wazuh Dashboard)
2. Look for indices:
    - `wazuh-alerts-*` - Security alerts
    - `wazuh-archives-*` - All events (if archiving enabled)
    - `wazuh-monitoring-*` - Agent status
    - `wazuh-statistics-*` - Performance metrics

### Task 3.3: Create Wazuh Data Views (If Using External Kibana)

If forwarding to external Elasticsearch/Kibana:

1. Navigate to **Stack Management > Data Views**
2. Create data view:
    - Name: `Wazuh Alerts`
    - Index pattern: `wazuh-alerts-*`
    - Timestamp field: `timestamp`
3. Save the data view

### ✅ Checkpoint 3

Before proceeding, verify:
- [ ] Wazuh indices exist with data
- [ ] Alerts visible in Security Events
- [ ] Can filter by agent, rule level, etc.
- [ ] Data views created (if using external Elastic)

---

## Part 4: Generate and Detect Security Events

**Estimated Time:** 45 minutes

### Task 4.1: Trigger File Integrity Monitoring Alerts

Wazuh includes File Integrity Monitoring (FIM) that detects changes to critical files.

**On Windows Workstation:**

```powershell
# Modify a monitored file (hosts file is monitored by default)
Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "# Test entry for FIM"

# Create file in monitored directory
New-Item -Path "C:\Windows\Temp\fim-test.exe" -ItemType File -Value "test" -Force
```

**On Linux Agent:**

```bash
# Modify /etc/passwd (will trigger alert)
sudo cp /etc/passwd /etc/passwd.bak
echo "# FIM test comment" | sudo tee -a /etc/passwd
sudo mv /etc/passwd.bak /etc/passwd

# Create file in /etc
sudo touch /etc/fim-test-file
sudo rm /etc/fim-test-file
```

### Task 4.2: Trigger Authentication Alerts

Generate failed authentication attempts:

**On Windows:**

```powershell
# Failed login attempts
for ($i = 1; $i -le 5; $i++) {
    net use \\localhost\c$ /user:fakeuser wrongpassword 2>$null
}

# Or using runas
for ($i = 1; $i -le 5; $i++) {
    echo "wrongpassword" | runas /user:nonexistent cmd 2>$null
}
```

**On Linux:**

```bash
# Generate failed SSH logins (from another system or locally)
for i in {1..5}; do
    sshpass -p 'wrongpassword' ssh -o StrictHostKeyChecking=no fakeuser@localhost 2>/dev/null
done

# Or using su
for i in {1..5}; do
    echo "wrongpassword" | su - nonexistentuser 2>/dev/null
done
```

### Task 4.3: Trigger Reconnaissance Detection

Wazuh can detect common reconnaissance commands:

**On Windows:**

```powershell
# These commands will generate Sysmon events that Wazuh analyzes
whoami /all
net user
net localgroup administrators
systeminfo
ipconfig /all
netstat -ano
tasklist
quser
net share
```

**On Linux:**

```bash
# Common enumeration commands
whoami
id
cat /etc/passwd
cat /etc/shadow 2>/dev/null
netstat -tulpn
ps aux
ls -la /root 2>/dev/null
```

### Task 4.4: Verify Alerts in Wazuh Dashboard

Navigate to the Wazuh Dashboard and explore the generated alerts:

1. Go to **Security Events** or **Threat Hunting > Events**
2. Set time range to **Last 15 minutes**
3. Look for alerts with different rule levels:

| Rule Level | Severity | Example Alerts |
| --- | --- | --- |
| 0-4 | Low | System events, informational |
| 5-7 | Medium | Policy violations, suspicious activity |
| 8-11 | High | Attack attempts, privilege escalation |
| 12-15 | Critical | Successful attacks, malware detected |

**Filter for specific alert types:**

| Alert Type | Filter |
| --- | --- |
| File Integrity | `rule.groups: syscheck` |
| Authentication | `rule.groups: authentication` |
| Windows Security | `agent.os.platform: windows` |
| Linux Security | `agent.os.platform: linux` |

### Task 4.5: Document Detected Alerts

Record alerts generated from your test activities:

| Alert ID | Rule ID | Description | Agent | Level |
| --- | --- | --- | --- | --- |
|  |  |  |  |  |
|  |  |  |  |  |
|  |  |  |  |  |
|  |  |  |  |  |
|  |  |  |  |  |

**Screenshot Checkpoint:** Capture screenshots showing:
1. File Integrity alerts
2. Authentication failure alerts
3. A high-severity alert detail view

### ✅ Checkpoint 4

Before proceeding, verify:
- [ ] FIM alerts generated for file changes
- [ ] Authentication alerts generated
- [ ] Can filter and search alerts effectively
- [ ] Alerts documented
- [ ] Screenshots captured

---

## Part 5: Custom Detection Rules

**Estimated Time:** 30 minutes

### Task 5.1: Understand Wazuh Rule Structure

Wazuh rules are XML-based and follow a hierarchical structure:

```xml
<rule id="100001" level="10">
  <if_sid>5710</if_sid>
  <match>Failed password</match>
  <description>SSH brute force attempt</description>
  <group>authentication_failures,</group>
</rule>
```

**Rule Components:**

| Element | Description |
| --- | --- |
| `id` | Unique rule identifier (custom rules: 100000+) |
| `level` | Severity level (0-15) |
| `if_sid` | Parent rule to match first |
| `match` | String to match in log |
| `regex` | Regular expression match |
| `description` | Human-readable description |
| `group` | Categories for filtering |

### Task 5.2: Create Custom Detection Rule

Create a custom rule to detect PowerShell encoded commands:

On the Wazuh Manager:

```bash
# Create custom rules file
sudo nano /var/ossec/etc/rules/local_rules.xml
```

Add the following rules:

```xml
<group name="local,sysmon,powershell,">

  <!-- Detect encoded PowerShell commands -->
  <rule id="100100" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)-encodedcommand|-enc\s|-e\s</field>
    <description>PowerShell executed with encoded command - possible obfuscation</description>
    <mitre>
      <id>T1059.001</id>
      <id>T1027</id>
    </mitre>
    <group>attack,powershell,execution,</group>
  </rule>

  <!-- Detect suspicious process from Downloads folder -->
  <rule id="100101" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)\\Downloads\\.*\.exe</field>
    <description>Process execution from Downloads folder - possible malware</description>
    <mitre>
      <id>T1204.002</id>
    </mitre>
    <group>attack,execution,</group>
  </rule>

  <!-- Detect credential dumping tools -->
  <rule id="100102" level="14">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz|procdump|lazagne|secretsdump</field>
    <description>Known credential dumping tool detected</description>
    <mitre>
      <id>T1003</id>
    </mitre>
    <group>attack,credential_access,</group>
  </rule>

  <!-- Detect reconnaissance commands -->
  <rule id="100103" level="8">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(whoami\s*/all|net\s+user|net\s+localgroup|systeminfo|ipconfig\s*/all)</field>
    <description>System reconnaissance command detected</description>
    <mitre>
      <id>T1087</id>
      <id>T1082</id>
    </mitre>
    <group>attack,discovery,</group>
  </rule>

  <!-- Multiple failed logins from same source -->
  <rule id="100110" level="10" frequency="5" timeframe="120">
    <if_matched_sid>5710</if_matched_sid>
    <same_source_ip />
    <description>Brute force attack - multiple failed logins from same source</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failures,attack,</group>
  </rule>

</group>
```

### Task 5.3: Apply Custom Rules

```bash
# Test the configuration
sudo /var/ossec/bin/wazuh-logtest

# Restart Wazuh Manager to apply rules
sudo systemctl restart wazuh-manager

# Verify rules loaded
sudo /var/ossec/bin/wazuh-logtest << EOF
Oct 20 10:00:00 WinEvtLog: Microsoft-Windows-Sysmon/Operational: INFORMATION(1): Sysmon: User: SYSTEM: CommandLine: powershell.exe -encodedcommand ZQBjAGgAbwAgAHQAZQBzAHQA
EOF
```

### Task 5.4: Test Custom Rules

On the Windows endpoint, trigger the custom rules:

```powershell
# Test encoded PowerShell rule (100100)
powershell -encodedcommand ZQBjAGgAbwAgAHQAZQBzAHQA

# Test reconnaissance rule (100103)
whoami /all
net user
systeminfo
ipconfig /all
```

### Task 5.5: Verify Custom Rule Detection

In the Wazuh Dashboard:

1. Navigate to **Security Events**
2. Filter by rule ID: `rule.id: 100100 OR rule.id: 100103`
3. Verify your custom rules triggered

**Document custom rule triggers:**

| Rule ID | Rule Description | Triggered? | Notes |
| --- | --- | --- | --- |
| 100100 | Encoded PowerShell | ☐ Yes ☐ No |  |
| 100101 | Downloads Execution | ☐ Yes ☐ No |  |
| 100102 | Credential Tool | ☐ Yes ☐ No |  |
| 100103 | Reconnaissance | ☐ Yes ☐ No |  |

### ✅ Checkpoint 5

Before proceeding, verify:
- [ ] Custom rules file created
- [ ] Wazuh Manager restarted without errors
- [ ] Custom rules triggering on test events
- [ ] Alerts visible in Dashboard with custom rule IDs

---

## Part 6: Active Response Configuration

**Estimated Time:** 20 minutes

### Task 6.1: Understand Active Response

Wazuh Active Response allows automated actions when specific alerts trigger:

| Response Type | Description | Example Use |
| --- | --- | --- |
| **firewall-drop** | Block IP at firewall | Block attacking IPs |
| **host-deny** | Add to hosts.deny | Block SSH attackers |
| **disable-account** | Disable user account | Response to compromise |
| **restart-service** | Restart a service | Recovery action |
| **custom** | Run custom script | Any automated action |

### Task 6.2: Configure Brute Force Response

On the Wazuh Manager, edit the configuration:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add active response configuration:

```xml
<ossec_config>
  <!-- Active Response Configuration -->
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>100110</rules_id>
    <timeout>300</timeout>
  </active-response>

  <!-- Custom Active Response Commands -->
  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>
</ossec_config>
```

⚠️ **Warning:** In production, carefully test active responses. Misconfiguration can block legitimate users.

### Task 6.3: Test Active Response (Optional - Lab Environment Only)

```bash
# View active response logs
sudo tail -f /var/ossec/logs/active-responses.log

# Generate brute force attack to trigger response
# (Do this from a test system that can be blocked)
```

### Task 6.4: Monitor Active Response

Check active response actions:

```bash
# View recent active responses
sudo cat /var/ossec/logs/active-responses.log | tail -20

# Check current blocked IPs (Linux)
sudo iptables -L -n | grep DROP
```

---

## Part 7: Dashboard and Visualization

**Estimated Time:** 20 minutes

### Task 7.1: Explore Wazuh Dashboard Modules

Navigate through the Wazuh Dashboard and explore:

| Module | Purpose | Key Information |
| --- | --- | --- |
| **Security Events** | All security alerts | Alert timeline, severity distribution |
| **Integrity Monitoring** | File changes | Modified/added/deleted files |
| **Vulnerabilities** | System vulnerabilities | CVE information, affected packages |
| **MITRE ATT&CK** | Threat mapping | Techniques detected, coverage |
| **Compliance** | Regulatory compliance | PCI DSS, HIPAA, GDPR checks |

### Task 7.2: Create Custom Dashboard

1. Navigate to **Dashboards > Create Dashboard**
2. Add the following visualizations:
    - Alert count by agent (pie chart)
    - Alert timeline (line chart)
    - Top triggered rules (table)
    - Alert severity distribution (gauge)
3. Save as: `Lab Environment Monitoring`

### Task 7.3: Configure Alert Notifications (Optional)

For production environments, configure email notifications:

```bash
# Edit ossec.conf
sudo nano /var/ossec/etc/ossec.conf
```

Add email configuration:

```xml
<ossec_config>
  <global>
    <email_notification>yes</email_notification>
    <email_to>security-team@yourdomain.com</email_to>
    <smtp_server>smtp.yourdomain.com</smtp_server>
    <email_from>wazuh@yourdomain.com</email_from>
    <email_maxperhour>12</email_maxperhour>
  </global>
</ossec_config>
```

---

## Lab Assessment

### Knowledge Check Questions

Answer the following questions based on your lab experience:

1. What port does the Wazuh Agent use to communicate with the Manager?
    
    **A.** 443
    
    **B.** 1514
    
    **C.** 9200
    
    **D.** 5601
    
2. Which Wazuh component is responsible for collecting and analyzing logs from agents?
    
    **A.** Wazuh Indexer
    
    **B.** Wazuh Dashboard
    
    **C.** Wazuh Manager
    
    **D.** Filebeat
    
3. What is the purpose of File Integrity Monitoring (FIM) in Wazuh?
    
    **A.** To encrypt files on endpoints
    
    **B.** To detect unauthorized changes to files
    
    **C.** To backup important files
    
    **D.** To compress log files
    
4. Custom Wazuh rules should use rule IDs starting at:
    
    **A.** 1
    
    **B.** 1000
    
    **C.** 100000
    
    **D.** 500
    
5. Per CWP 3-2.1, Security Alerting should provide data to support which two purposes?
    
    **A.** Billing and compliance only
    
    **B.** Operator situational awareness and automated countermeasure platforms
    
    **C.** User training and documentation
    
    **D.** System backup and recovery
    
- **Click to reveal Answer Key**
    1. **B** - Port 1514 (agent communication)
    2. **C** - Wazuh Manager
    3. **B** - To detect unauthorized changes to files
    4. **C** - 100000 (custom rules start at 100000)
    5. **B** - Operator situational awareness and automated countermeasure platforms

### Practical Validation

| Validation Task | Status | Evidence/Notes |
| --- | --- | --- |
| Wazuh Manager running | ☐ Pass ☐ Fail |  |
| All agents connected and active | ☐ Pass ☐ Fail |  |
| FIM alerts generated | ☐ Pass ☐ Fail |  |
| Authentication alerts generated | ☐ Pass ☐ Fail |  |
| Custom rules triggering | ☐ Pass ☐ Fail |  |
| Data visible in Dashboard | ☐ Pass ☐ Fail |  |
| Can filter and search alerts | ☐ Pass ☐ Fail |  |

---

## Troubleshooting Guide

### Agent Connection Issues

**Problem:** Agent not connecting to Manager

```bash
# On Agent - Check connectivity
ping 192.168.10.100
telnet 192.168.10.100 1514

# Check agent logs
# Windows
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 50

# Linux
sudo tail -50 /var/ossec/logs/ossec.log

# Re-register agent if needed
# Linux
sudo /var/ossec/bin/agent-auth -m 192.168.10.100
```

**Problem:** Agent shows disconnected in Dashboard

```bash
# On Manager - Check agent status
sudo /var/ossec/bin/agent_control -l

# Restart manager
sudo systemctl restart wazuh-manager

# Check manager logs
sudo tail -100 /var/ossec/logs/ossec.log | grep -i error
```

### Alert Issues

**Problem:** No alerts appearing

```bash
# Check if events are being received
sudo tail -f /var/ossec/logs/alerts/alerts.json

# Test rule matching
sudo /var/ossec/bin/wazuh-logtest

# Check rule syntax
sudo /var/ossec/bin/wazuh-analysisd -t
```

**Problem:** Custom rules not triggering

```bash
# Verify rule syntax
sudo /var/ossec/bin/wazuh-analysisd -t

# Test specific log against rules
sudo /var/ossec/bin/wazuh-logtest

# Check if parent rule (if_sid) is matching first
```

### Dashboard Issues

**Problem:** Dashboard not loading data

```bash
# Check indexer status
sudo systemctl status wazuh-indexer

# Check indices
curl -k -u admin:PASSWORD "https://localhost:9200/_cat/indices?v"

# Restart services
sudo systemctl restart wazuh-manager wazuh-indexer wazuh-dashboard
```

---

## Lab Completion Checklist

Before submitting this lab, verify:

- [ ]  Wazuh Manager installed and running
- [ ]  Wazuh Dashboard accessible
- [ ]  Windows workstation agent deployed and active
- [ ]  Windows server agent deployed and active
- [ ]  Linux agent deployed and active
- [ ]  Sysmon integration configured (if Lab 7A completed)
- [ ]  File Integrity alerts generated
- [ ]  Authentication failure alerts generated
- [ ]  Custom detection rules created
- [ ]  Custom rules triggering correctly
- [ ]  Dashboard shows all agents and alerts
- [ ]  Completed all knowledge check questions
- [ ]  Documented validation task results
- [ ]  Captured all required screenshots

### Screenshots Required

1. Wazuh Dashboard home page with agents
2. Agents list showing all active agents
3. File Integrity Monitoring alerts
4. Authentication failure alerts
5. Custom rule alert (rule ID 100100 or 100103)
6. Alert detail view with MITRE mapping

---

## Extension Challenges (Optional)

### Challenge 1: Vulnerability Assessment

Enable vulnerability detection on agents and assess system vulnerabilities:

1. Enable vulnerability-detector in ossec.conf
2. Run vulnerability scan on agents
3. Document critical vulnerabilities found

### Challenge 2: Compliance Monitoring

Configure and run compliance checks:

1. Enable PCI DSS compliance checking
2. Run compliance scan on Windows agent
3. Document compliance failures and remediation steps

### Challenge 3: Integration with MISP

Integrate Wazuh with MISP (Malware Information Sharing Platform):

1. Configure MISP integration
2. Create rules that match against threat intelligence
3. Test with known malicious indicators

---

## Summary

In this lab, you implemented a comprehensive host-based detection capability by:

1. **Deploying Wazuh Manager** as the central security monitoring platform
2. **Installing Agents** on Windows and Linux endpoints for distributed sensing
3. **Integrating with Elastic** for scalable log storage and visualization
4. **Creating Custom Rules** for organization-specific threat detection
5. **Configuring Active Response** for automated threat mitigation
6. **Building Dashboards** for security operations visibility

This implementation aligns with CWP 3-2.1 requirements for:
- **Security Alerting** - Generating alerts for security events
- **Endpoint Awareness** - Agent-based endpoint monitoring
- **Application Logging** - Centralized log collection and analysis

The combination of Lab 7A (Sysmon) and Lab 7B (Wazuh) provides a comprehensive endpoint sensing solution that feeds data to a centralized Elastic Stack for analysis and visualization.

---

**Module 7 Labs Complete**

You have now completed both sensing capability labs:
- ✅ Lab 7A: Sysmon Endpoint Sensing
- ✅ Lab 7B: Wazuh Host-Based Detection

**Proceed to Module 8: Cyber Defense Tools and Technologies**

---

*Document Version: 1.0*

*Last Updated: December 2024*

*Classification: UNCLASSIFIED // FOR TRAINING USE ONLY*