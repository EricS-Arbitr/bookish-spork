# LAB: Arkime Full Packet Capture

Owner: Eric Starace
Last edited by: Eric Starace

# Lab: Full Packet Capture with Arkime

## Cyber Defense Infrastructure Support Specialist Course

| **Estimated Completion Time** | 3–4 hours |
| --- | --- |
| **Prerequisites** | Lesson 7 Sections 7.1–7.4; Lab 7C (Sysmon) and Lab 7D (Wazuh) completed; Basic Linux administration |
| **Lab Type** | Hands-on technical deployment and configuration |
| **Classification** | UNCLASSIFIED // FOR TRAINING USE ONLY |

---

## Terminal Learning Objective

Deploy and configure Arkime as a full packet capture and indexed session analysis platform with centralized log collection to support forensic investigation and incident response.

### Enabling Learning Objectives

| ELO | Objective |
| --- | --- |
| 7E.1 | Install and configure Arkime capture and viewer components on a Linux sensor |
| 7E.2 | Configure network interfaces for full packet capture with appropriate storage and retention |
| 7E.3 | Navigate the Arkime viewer interface to search, inspect, and export captured session data |
| 7E.4 | Retrieve and export PCAP data for detailed forensic analysis with external tools |
| 7E.5 | Create visualizations and dashboards in Kibana using Arkime session metadata stored in Elasticsearch |

### KSAT Alignment

| KSAT ID | Type | Description | Lab Section |
| --- | --- | --- | --- |
| K0087A | Knowledge (C) | Knowledge of network traffic analysis (tools, methodologies, processes) | All Parts |
| K0093 | Knowledge (A) | Knowledge of packet-level analysis | Parts 3–4 |
| T2772 | Task (C) | Build, install, configure, and test dedicated cyber defense hardware | Parts 1–2 |
| S0227 | Skill (A) | Skill in tuning sensors | Parts 2–3 |
| T0393B | Task (C) | Coordinate with system admins to create cyber defense tools, test beds, and evaluate applications | Parts 1–5 |

---

## Lab Overview

This lab focuses on deploying Arkime (formerly Moloch) as a full packet capture and indexed session analysis platform. Arkime captures, indexes, and stores complete network traffic, enabling security analysts to search, retrieve, and analyze full packet data for forensic investigation and incident response. Deploy Arkime on a Linux sensor, configure packet capture and retention policies, explore the session analysis interface, and integrate with the existing Elastic Stack for unified visibility.

### Sensing Capability Alignment

This lab implements the **Full Packet Capture** sensing capability per CWP 3-2.1.

Per CWP 3-2.1, Full Packet Capture capabilities provide bi-directional network traffic data to security alerting platforms supporting signature and heuristic-based analysis and post-incident analysis. Data is provided out-of-band and stored in a network data repository.

Full Packet Capture differs from other network sensing capabilities:

| Sensing Capability | Function | Tool (This Course) |
| --- | --- | --- |
| **Passive Sensing** | Captures metadata and flow records | Zeek |
| **Security Alerting** | Generates alerts from signatures and heuristics | Suricata |
| **Full Packet Capture** | Stores complete packet payloads for deep inspection and forensics | **Arkime** |

Per CWP 3-2.1, Full Packet Capture is required at the following boundaries:

| Boundary | Requirement |
| --- | --- |
| Enterprise Boundary (EB) | Full Packet Capture provides data on selected traffic content informing EB security platform functions |
| Regional Boundary (RB) | Full Packet Capture provides bi-directional network traffic data to RB security platforms |
| Local Boundary (LB) | On order, Full Packet Capture enables collection of full payload content for all bi-directional traffic |

### Doctrinal Context

CWP 3-2.1 establishes three sensing goals. Full Packet Capture contributes to all three:

1. **Goal 1 — Enhance protection of DOD cyberspace terrain:** Full Packet Capture provides data to signature and heuristic-based security platforms supporting automated countermeasures at boundaries.
2. **Goal 2 — Enhance real-time situational awareness:** Captured packet data supports analysis of aggregated sensing data and agile maneuver in cyberspace.
3. **Goal 3 — Enhance threat-specific defensive operations:** Full Packet Capture enables advanced forensic analysis and activation of additional sensing capabilities.

CWP 3-2.1 specifies that Full Packet Capture data need only provide data on selected traffic content identified as informing situational awareness, and that this data only requires short-duration retention to enable immediate inspection. Arkime addresses both requirements through its configurable capture filters and retention policies.

---

## Lab Environment

### Required Systems

| System | Role | IP Address | OS |
| --- | --- | --- | --- |
| **YOURSERVER-ELASTIC** | Elasticsearch + Kibana | 192.168.10.100 | Ubuntu Server 22.04 LTS |
| **YOURSERVER-SENSOR** | Arkime Capture + Viewer | 192.168.10.110 | Ubuntu Server 22.04 LTS |
| **YOURSERVER-DC01** | Windows Domain Controller (traffic source) | 192.168.10.10 | Windows Server 2019/2022 |
| **YOURWORKSTATION** | Windows Workstation (traffic source) | 192.168.10.50 | Windows 10/11 |

> **💡 Note:** If the lab environment has limited systems, Arkime can be installed on the same server as Elasticsearch. Adjust IP addresses accordingly. The Arkime sensor requires a network interface that can see the traffic to be captured — in a virtual environment this typically means a promiscuous-mode adapter or mirrored port.
> 

### Network Requirements

- All systems on same network segment (192.168.10.0/24)
- Arkime sensor interface configured for promiscuous mode or connected to a SPAN/mirror port
- Elasticsearch accessible on port 9200
- Kibana accessible on port 5601
- Arkime viewer accessible on port 8005
- Internet access for downloading packages (or local repository)

### Resource Requirements

| Component | Minimum RAM | Recommended RAM | Minimum Disk Space |
| --- | --- | --- | --- |
| Arkime Sensor (Capture + Viewer) | 4 GB | 8 GB | 50 GB (PCAP storage) |
| Elasticsearch + Kibana | 8 GB | 16 GB | 50 GB |

> **⚠️ Important:** Full packet capture generates significant disk usage. In a production environment, storage requirements are driven by link speed and retention duration. For this lab, 50 GB of PCAP storage space is sufficient for the training exercises.
> 

### Pre-Lab Checklist

Before starting, verify:

- [ ]  Ubuntu sensor system meets minimum resource requirements
- [ ]  Elasticsearch and Kibana are operational (from previous labs)
- [ ]  Sensor system can reach the Elasticsearch server on port 9200
- [ ]  Administrative (sudo) access on the sensor system
- [ ]  Network interface available for packet capture
- [ ]  DNS resolution working between systems

---

## Part 1: Install Arkime

**Estimated Time:** 30 minutes

### Background

Arkime consists of three primary components:

1. **Capture (arkime-capture):** Monitors network interfaces, captures packets, parses protocols, and stores both the raw PCAP data and indexed session metadata.
2. **Viewer (arkime-viewer):** Provides a web-based interface for searching sessions, viewing session details, and exporting PCAP data.
3. **Elasticsearch Integration:** Arkime stores session metadata (SPI data — Session Profile Information) in Elasticsearch indices, enabling fast searching across millions of sessions.

### Task 1.1: Verify Elasticsearch Connectivity

Before installing Arkime, confirm the sensor can reach the Elasticsearch instance.

On the **Arkime sensor** (YOURSERVER-SENSOR):

```bash
# Test Elasticsearch connectivity
curl -u elastic:YOUR_ELASTIC_PASSWORD "http://192.168.10.100:9200"
```

**Expected Output:**

```json
{
  "name" : "elastic-node",
  "cluster_name" : "elasticsearch",
  "cluster_uuid" : "...",
  "version" : {
    "number" : "8.x.x",
    ...
  },
  "tagline" : "You Know, for Search"
}
```

> **⚠️ Important:** If this command fails, troubleshoot network connectivity before proceeding. Arkime requires a working Elasticsearch connection.
> 

### Task 1.2: Download and Install Arkime

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install prerequisites
sudo apt install wget curl libpcap-dev libyaml-dev -y

# Download the latest Arkime release for Ubuntu 22.04
# Check https://arkime.com/downloads for the current version
wget https://s3.amazonaws.com/files.molo.ch/builds/ubuntu-22.04/arkime_5.4.0-1_amd64.deb

# Install the package
sudo dpkg -i arkime_5.4.0-1_amd64.deb
```

> **💡 Note:** The version number in the download URL may differ. Visit https://arkime.com/downloads and select the appropriate package for Ubuntu 22.04. Adjust the filename in the `dpkg` command to match the version downloaded.
> 

**Expected Output:**

```
Selecting previously unselected package arkime.
(Reading database ... done)
Preparing to unpack arkime_5.4.0-1_amd64.deb ...
Unpacking arkime (5.4.0-1) ...
Setting up arkime (5.4.0-1) ...
```

### Task 1.3: Identify the Capture Interface

Determine which network interface Arkime will use for packet capture:

```bash
# List available network interfaces
ip addr show
```

Identify the interface connected to the monitored network segment. Common interface names include `ens33`, `ens160`, `eth0`, or `ens192`. Record the interface name:

**Capture Interface:** ____________________

> **💡 Note:** In a virtual environment, this is typically the interface on the 192.168.10.0/24 network. If using a dedicated capture interface (e.g., connected to a SPAN port), use that interface name instead.
> 

### Task 1.4: Run the Arkime Configuration Script

Arkime includes a configuration script that performs initial setup:

```bash
sudo /opt/arkime/bin/Configure
```

The script prompts for the following information. Enter the values shown:

| Prompt | Value to Enter |
| --- | --- |
| Interface to monitor | The interface name from Task 1.3 (e.g., `ens33`) |
| Elasticsearch server URL | `http://192.168.10.100:9200` |
| Password for encrypting S2S and Arkime viewer passwords | Choose a password and **record it** |

**Expected Output:**

```
Arkime - Creating configuration file /opt/arkime/etc/config.ini
```

### Task 1.5: Verify Installation

Confirm the Arkime installation directory structure:

```bash
# View Arkime directory structure
ls -la /opt/arkime/

# Verify the configuration file exists
cat /opt/arkime/etc/config.ini | head -30
```

Expected directories include: `bin/`, `db/`, `etc/`, `logs/`, `raw/`, `viewer/`.

### ✅ Checkpoint 1

Before proceeding, verify:

- [ ]  Elasticsearch connectivity confirmed
- [ ]  Arkime package installed successfully
- [ ]  Configuration script completed without errors
- [ ]  `config.ini` file exists at `/opt/arkime/etc/config.ini`

---

## Part 2: Configure Arkime

**Estimated Time:** 45 minutes

### Task 2.1: Configure PCAP Storage

Arkime stores raw PCAP files on disk. Configure the storage location and retention policy:

```bash
# Create a dedicated PCAP storage directory
sudo mkdir -p /opt/arkime/raw

# Verify available disk space
df -h /opt/arkime/raw
```

Edit the Arkime configuration file to set storage parameters:

```bash
sudo nano /opt/arkime/etc/config.ini
```

Locate and modify (or verify) the following settings in the `[default]` section:

```
# ---- PCAP Storage ----
# Directory for storing PCAP files
pcapDir= /opt/arkime/raw

# Maximum percentage of disk space Arkime will use before deleting old PCAPs
freeSpaceG= 5%

# Maximum PCAP file size in megabytes (files rotate at this size)
maxFileSizeG=2

# ---- Elasticsearch ----
elasticsearch= http://192.168.10.100:9200

# ---- Interface ----
interface= ens33

# ---- Security ----
# Password secret (set during Configure script)
passwordSecret= YOUR_PASSWORD_SECRET
```

> **💡 Note:** The `freeSpaceG` parameter controls automatic PCAP rotation. When free disk space drops below this threshold, Arkime automatically deletes the oldest PCAP files. This implements the CWP 3-2.1 requirement that Full Packet Capture data only requires short-duration retention.
> 

### Task 2.2: Configure Elasticsearch Authentication

If Elasticsearch requires authentication (standard in Elastic 8.x), add credentials to the configuration:

```bash
sudo nano /opt/arkime/etc/config.ini
```

Modify the Elasticsearch URL to include credentials:

```
elasticsearch= http://elastic:YOUR_ELASTIC_PASSWORD@192.168.10.100:9200
```

Alternatively, use the separate authentication fields if available in the Arkime version:

```
elasticsearch= http://192.168.10.100:9200
elasticsearchBasicAuth= elastic:YOUR_ELASTIC_PASSWORD
```

### Task 2.3: Configure the Capture Interface for Promiscuous Mode

For Arkime to capture all traffic on the network segment (not just traffic addressed to the sensor), the capture interface must operate in promiscuous mode:

```bash
# Enable promiscuous mode on the capture interface
sudo ip link set ens33 promisc on

# Verify promiscuous mode is enabled
ip addr show ens33 | grep -i promisc
```

**Expected Output (look for PROMISC flag):**

```
3: ens33: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> mtu 1500 ...
```

To make promiscuous mode persist across reboots, create a systemd service:

```bash
sudo nano /etc/systemd/system/promisc-mode.service
```

Add the following content:

```
[Unit]
Description=Enable promiscuous mode on capture interface
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ip link set ens33 promisc on
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

Enable the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable promisc-mode.service
```

> **💡 Note:** Replace `ens33` with the actual capture interface name identified in Task 1.3 throughout this task.
> 

### Task 2.4: Initialize the Elasticsearch Database

Arkime requires its own index templates and database schema in Elasticsearch. Initialize these using the included database script:

```bash
# Initialize the Arkime database in Elasticsearch
sudo /opt/arkime/db/db.pl --esurl http://elastic:YOUR_ELASTIC_PASSWORD@192.168.10.100:9200 init
```

When prompted, type `INIT` to confirm:

```
Do you want to init Arkime database? Type INIT to confirm:
```

**Expected Output:**

```
Creating template arkime_sessions3_template
Creating template arkime_history_v1_template
Creating arkime_sequence_v3 index
Creating arkime_files_v30 index
Creating arkime_users_v30 index
Creating arkime_dstats_v4 index
...
Finished
```

> **⚠️ Important:** The `init` command creates the necessary Elasticsearch indices and templates. Only run this once per Elasticsearch cluster. Running it again deletes all existing Arkime data.
> 

### Task 2.5: Create an Arkime Admin User

Create a user account for accessing the Arkime viewer web interface:

```bash
# Create an admin user
sudo /opt/arkime/bin/arkime_add_user.sh admin "Admin User" YOUR_VIEWER_PASSWORD --admin
```

**Expected Output:**

```
Added
```

> **💡 Note:** Choose a strong password for the viewer interface. This is separate from the Elasticsearch password.
> 

### Task 2.6: Review the Complete Configuration

Display the final configuration for review:

```bash
sudo cat /opt/arkime/etc/config.ini
```

Record the key configuration values:

| Setting | Value |
| --- | --- |
| Capture Interface |  |
| Elasticsearch URL |  |
| PCAP Storage Directory |  |
| Free Space Threshold |  |
| Max File Size |  |
| Viewer Port |  |

### ✅ Checkpoint 2

Before proceeding, verify:

- [ ]  PCAP storage directory created with adequate disk space
- [ ]  Elasticsearch authentication configured
- [ ]  Capture interface set to promiscuous mode
- [ ]  Elasticsearch database initialized successfully
- [ ]  Admin user created for viewer access

---

## Part 3: Start Arkime Services and Verify Capture

**Estimated Time:** 30 minutes

### Task 3.1: Create Systemd Service for Arkime Capture

Create a systemd service file to manage the Arkime capture process:

```bash
sudo nano /etc/systemd/system/arkimecapture.service
```

Add the following content:

```
[Unit]
Description=Arkime Capture
After=network-online.target elasticsearch.service
Wants=network-online.target

[Service]
Type=simple
Restart=on-failure
RestartSec=10
ExecStart=/opt/arkime/bin/capture -c /opt/arkime/etc/config.ini
WorkingDirectory=/opt/arkime
LimitCORE=infinity
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
```

### Task 3.2: Create Systemd Service for Arkime Viewer

```bash
sudo nano /etc/systemd/system/arkimeviewer.service
```

Add the following content:

```
[Unit]
Description=Arkime Viewer
After=network-online.target elasticsearch.service arkimecapture.service
Wants=network-online.target

[Service]
Type=simple
Restart=on-failure
RestartSec=10
ExecStart=/opt/arkime/bin/viewer -c /opt/arkime/etc/config.ini
WorkingDirectory=/opt/arkime/viewer

[Install]
WantedBy=multi-user.target
```

### Task 3.3: Start Services

```bash
# Reload systemd to recognize new service files
sudo systemctl daemon-reload

# Enable services to start on boot
sudo systemctl enable arkimecapture.service
sudo systemctl enable arkimeviewer.service

# Start the capture service
sudo systemctl start arkimecapture.service

# Wait 5 seconds for capture to initialize, then start viewer
sleep 5
sudo systemctl start arkimeviewer.service
```

### Task 3.4: Verify Service Status

```bash
# Check capture service status
sudo systemctl status arkimecapture.service

# Check viewer service status
sudo systemctl status arkimeviewer.service
```

**Expected Output (for each service):**

```
● arkimecapture.service - Arkime Capture
     Loaded: loaded (/etc/systemd/system/arkimecapture.service; enabled; ...)
     Active: active (running) since ...
```

If either service fails to start, check the logs:

```bash
# View capture logs
sudo journalctl -u arkimecapture.service --no-pager -n 50

# View viewer logs
sudo journalctl -u arkimeviewer.service --no-pager -n 50

# Also check Arkime's own log files
sudo tail -50 /opt/arkime/logs/capture.log
sudo tail -50 /opt/arkime/logs/viewer.log
```

### Task 3.5: Verify PCAP Files Are Being Created

```bash
# Check PCAP storage directory
ls -la /opt/arkime/raw/

# Watch for new PCAP files being created
watch -n 5 'ls -lh /opt/arkime/raw/ | tail -5'
```

PCAP files appear with names following the pattern: `HOSTNAME-YYMMDD-HHMMSS.pcap`. If no files appear after 30 seconds, generate some network traffic (see Task 3.6).

### Task 3.6: Generate Network Traffic

From the **Windows Workstation** or the **Arkime sensor itself**, generate traffic for Arkime to capture:

**From the Arkime sensor:**

```bash
# Generate HTTP traffic
curl -s http://example.com > /dev/null
curl -s http://httpbin.org/get > /dev/null

# Generate DNS queries
nslookup google.com
nslookup microsoft.com

# Ping other systems on the network
ping -c 5 192.168.10.10
ping -c 5 192.168.10.50
```

**From the Windows Workstation** (PowerShell):

```powershell
# Browse to websites
Invoke-WebRequest -Uri "http://example.com" -UseBasicParsing | Out-Null

# Perform DNS lookups
Resolve-DnsName google.com
Resolve-DnsName microsoft.com

# Ping the sensor
Test-Connection -ComputerName 192.168.10.110 -Count 5
```

### Task 3.7: Verify Sessions in Elasticsearch

Confirm that Arkime is indexing session metadata into Elasticsearch:

```bash
# Check for Arkime indices in Elasticsearch
curl -u elastic:YOUR_ELASTIC_PASSWORD "http://192.168.10.100:9200/_cat/indices?v" | grep arkime
```

**Expected Output:**

```
green  open  arkime_sessions3-YYMMDD    ...  ...  ...  ...
green  open  arkime_files_v30           ...  ...  ...  ...
green  open  arkime_users_v30           ...  ...  ...  ...
green  open  arkime_sequence_v3         ...  ...  ...  ...
green  open  arkime_dstats_v4           ...  ...  ...  ...
```

The `arkime_sessions3-YYMMDD` index contains the session metadata. The number of documents should increase as traffic is captured.

### ✅ Checkpoint 3

Before proceeding, verify:

- [ ]  Arkime capture service running (`active (running)`)
- [ ]  Arkime viewer service running (`active (running)`)
- [ ]  PCAP files appearing in `/opt/arkime/raw/`
- [ ]  Arkime session indices present in Elasticsearch
- [ ]  Session document count is increasing

---

## Part 4: Explore the Arkime Viewer Interface

**Estimated Time:** 45 minutes

### Task 4.1: Access the Arkime Viewer

Open a web browser and navigate to:

```
http://192.168.10.110:8005
```

Log in with the admin credentials created in Task 2.5.

> **💡 Note:** If the viewer is running on the same host as Elasticsearch, adjust the IP address accordingly. The default Arkime viewer port is 8005.
> 

### Task 4.2: Navigate the Sessions Page

The **Sessions** page is the primary interface for analyzing captured traffic. Familiarize yourself with the following elements:

| Interface Element | Purpose |
| --- | --- |
| **Search Bar** | Enter Arkime query expressions to filter sessions |
| **Time Range Selector** | Set the time window for displayed sessions |
| **Session List** | Displays matching sessions with summary information |
| **Session Detail** | Expand any session to view full details |
| **Column Headers** | Click to sort by Start Time, Source IP, Destination IP, Bytes, etc. |

### Task 4.3: Practice Arkime Query Syntax

Arkime uses its own query language (sometimes called Arkime Expression Syntax) for searching sessions. Practice the following queries in the search bar:

**Query 1: Find all HTTP sessions**

```
protocols == http
```

**Query 2: Find sessions from a specific source IP**

```
ip.src == 192.168.10.50
```

**Query 3: Find sessions to a specific destination IP**

```
ip.dst == 192.168.10.10
```

**Query 4: Find DNS sessions**

```
protocols == dns
```

**Query 5: Find sessions with more than 1000 bytes transferred**

```
bytes > 1000
```

**Query 6: Combine conditions — HTTP traffic from a specific host**

```
protocols == http && ip.src == 192.168.10.50
```

**Query 7: Find sessions involving a specific port**

```
port == 443
```

**Query 8: Search session content for a domain name**

```
host.http == example.com
```

> **💡 Note:** Arkime’s query syntax differs from KQL (used in Kibana). The full query syntax reference is available at https://arkime.com/sessions#expressions.
> 

Record the results of each query:

| Query | Number of Sessions Found |
| --- | --- |
| `protocols == http` |  |
| `ip.src == 192.168.10.50` |  |
| `ip.dst == 192.168.10.10` |  |
| `protocols == dns` |  |
| `bytes > 1000` |  |
| `protocols == http && ip.src == 192.168.10.50` |  |
| `port == 443` |  |
| `host.http == example.com` |  |

### Task 4.4: Inspect Session Details

1. Click on any session in the session list to expand its details.
2. Review the following sections in the session detail view:

| Section | Information Provided |
| --- | --- |
| **General** | Start/stop time, duration, source/destination IP and port, bytes transferred |
| **IP** | Geographic information, ASN data (if configured) |
| **HTTP** (if applicable) | Method, URI, host, user-agent, status code, content-type |
| **DNS** (if applicable) | Query name, query type, response |
| **TLS** (if applicable) | JA3/JA4 fingerprint, cipher suite, certificate information |
1. Explore the **Session Data** tab to view the raw payload content (packet bytes).

### Task 4.5: Export PCAP Data

Arkime’s forensic value comes from the ability to export raw PCAP data for any session or group of sessions.

**Export a single session:**

1. Click on a session to expand it.
2. Click the **download PCAP** icon (downward arrow) in the session detail header.
3. Save the file.

**Export multiple sessions:**

1. Enter a search query to filter the sessions of interest (e.g., `protocols == http && ip.src == 192.168.10.50`).
2. Click the **Actions** dropdown in the session list header.
3. Select **Export PCAP**.
4. Choose whether to export all matching sessions or only selected sessions.
5. Save the exported PCAP file.

### Task 4.6: Analyze Exported PCAP (Optional — If Wireshark Is Available)

If Wireshark is installed on the workstation:

1. Transfer the exported PCAP file to the Windows workstation.
2. Open the file in Wireshark.
3. Apply display filters to examine specific traffic.
4. Compare the Arkime session view with the Wireshark packet view.

This demonstrates the forensic workflow: use Arkime for rapid searching and session identification, then export to Wireshark for deep packet-level analysis.

### Task 4.7: Explore the SPI View

Arkime provides Session Profile Information (SPI) views that aggregate session metadata:

1. Navigate to the **SPIView** page from the top navigation menu.
2. Observe the field categories and their value distributions.
3. Click on individual field values to add them as search filters.

The SPIView page provides a high-level overview of captured traffic, useful for identifying trends and anomalies.

### ✅ Checkpoint 4

Before proceeding, verify:

- [ ]  Arkime viewer accessible via web browser
- [ ]  Can search sessions using Arkime query syntax
- [ ]  Can view session details (general, protocol-specific sections)
- [ ]  Can export PCAP data from the viewer
- [ ]  Explored the SPIView page

---

## Part 5: Create Kibana Visualizations from Arkime Data

**Estimated Time:** 30 minutes

### Background

Arkime stores session metadata in Elasticsearch indices (`arkime_sessions3-*`). This data is also accessible from Kibana, enabling integration of Arkime session data into the same dashboards used for Sysmon, Wazuh, Zeek, and Suricata data.

### Task 5.1: Create a Kibana Data View for Arkime

1. Open Kibana at `http://192.168.10.100:5601`.
2. Navigate to **Management > Stack Management > Data Views**.
3. Click **Create data view**.
4. Enter the following:

| Field | Value |
| --- | --- |
| **Name** | `Arkime Sessions` |
| **Index pattern** | `arkime_sessions3-*` |
| **Timestamp field** | `firstPacket` |
1. Click **Save data view to Kibana**.

### Task 5.2: Explore Arkime Data in Discover

1. Navigate to **Discover** in Kibana.
2. Select the **Arkime Sessions** data view.
3. Set the time range to cover the period when traffic was generated.
4. Explore the available fields. Key fields include:

| Field | Description |
| --- | --- |
| `firstPacket` | Session start time |
| `lastPacket` | Session end time |
| `source.ip` | Source IP address |
| `destination.ip` | Destination IP address |
| `source.port` | Source port |
| `destination.port` | Destination port |
| `network.bytes` | Total bytes transferred |
| `network.packets` | Total packets |
| `protocol` | Protocol list |
| `node` | Capture node name |

> **💡 Note:** Arkime field names in Elasticsearch may vary based on the Arkime version. Use the Discover interface to browse available fields if the names above do not match exactly.
> 
1. Apply filters to find specific traffic types:
    - Filter: `destination.port : 80` (HTTP traffic)
    - Filter: `destination.port : 53` (DNS traffic)
    - Filter: `source.ip : 192.168.10.50` (traffic from workstation)

### Task 5.3: Create Visualization — Top Talkers by Bytes

1. Navigate to **Visualize Library** > **Create visualization**.
2. Select **Lens**.
3. Configure:
    - **Data view:** Arkime Sessions
    - **Visualization type:** Bar (horizontal)
    - **X-axis:** `source.ip` (Top 10 values)
    - **Y-axis:** Sum of `network.bytes`
4. Title: **“Arkime — Top Source IPs by Bytes Transferred”**
5. Click **Save and return**.

### Task 5.4: Create Visualization — Protocol Distribution

1. Create a new **Lens** visualization.
2. Configure:
    - **Data view:** Arkime Sessions
    - **Visualization type:** Donut
    - **Slice by:** `protocol` (Top 10 values)
    - **Size by:** Count
3. Title: **“Arkime — Protocol Distribution”**
4. Click **Save and return**.

### Task 5.5: Create Visualization — Sessions Over Time

1. Create a new **Lens** visualization.
2. Configure:
    - **Data view:** Arkime Sessions
    - **Visualization type:** Line
    - **X-axis:** `firstPacket` (Date histogram, auto interval)
    - **Y-axis:** Count
3. Title: **“Arkime — Sessions Over Time”**
4. Click **Save and return**.

### Task 5.6: Create Visualization — Top Destination Ports

1. Create a new **Lens** visualization.
2. Configure:
    - **Data view:** Arkime Sessions
    - **Visualization type:** Bar (horizontal)
    - **X-axis:** `destination.port` (Top 15 values)
    - **Y-axis:** Count
3. Title: **“Arkime — Top Destination Ports”**
4. Click **Save and return**.

### Task 5.7: Assemble an Arkime Dashboard

1. Navigate to **Dashboard** > **Create dashboard**.
2. Add all four Arkime visualizations created above.
3. Arrange them in a logical layout:

```
┌──────────────────────────────────────────────────────┐
│              Sessions Over Time (full width)          │
├───────────────────────────┬──────────────────────────┤
│  Top Source IPs by Bytes  │  Protocol Distribution   │
├───────────────────────────┴──────────────────────────┤
│            Top Destination Ports (full width)         │
└──────────────────────────────────────────────────────┘
```

1. Title the dashboard: **“Arkime — Full Packet Capture Overview”**
2. Click **Save**.

### ✅ Checkpoint 5

Before proceeding, verify:

- [ ]  Data view created for `arkime_sessions3-*`
- [ ]  Arkime session data visible in Kibana Discover
- [ ]  Created Top Talkers, Protocol Distribution, Sessions Over Time, and Top Destination Ports visualizations
- [ ]  Dashboard assembled and saved

---

## Part 6: Correlating Arkime with Other Sensing Tools

**Estimated Time:** 15 minutes

### Background

The combination of Arkime with Zeek and Suricata creates a comprehensive network sensing architecture. This part demonstrates the operational workflow for using all three tools together during an investigation.

### Task 6.1: Understand the Network Sensing Triad

Review the following investigation workflow:

```
┌────────────────────────────────────────────────────────────┐
│                  INVESTIGATION WORKFLOW                      │
├────────────────────────────────────────────────────────────┤
│                                                             │
│  Step 1: DETECT — An alert fires                            │
│  ┌──────────────────────────────────────────────┐          │
│  │  Suricata generates an IDS alert for a        │          │
│  │  suspicious outbound connection               │          │
│  └──────────────────┬───────────────────────────┘          │
│                     │                                       │
│  Step 2: CONTEXTUALIZE — Enrich with metadata               │
│  ┌──────────────────▼───────────────────────────┐          │
│  │  Zeek logs reveal the connection used HTTP,   │          │
│  │  the URI was /update.php, the user-agent is   │          │
│  │  unusual, and 500KB was transferred out        │          │
│  └──────────────────┬───────────────────────────┘          │
│                     │                                       │
│  Step 3: INVESTIGATE — Retrieve full packets                │
│  ┌──────────────────▼───────────────────────────┐          │
│  │  Arkime retrieves the complete PCAP for this  │          │
│  │  session, revealing the actual payload         │          │
│  │  content and confirming data exfiltration      │          │
│  └──────────────────────────────────────────────┘          │
│                                                             │
└────────────────────────────────────────────────────────────┘
```

Each tool answers different questions:

| Question | Tool | Data Type |
| --- | --- | --- |
| Was the traffic malicious? | Suricata | Signature-based alerts |
| Who talked to whom, using what protocol? | Zeek | Connection metadata, protocol logs |
| What exactly was in the packets? | Arkime | Full packet payloads |

### Task 6.2: Practice the Correlation Workflow

Using data already captured in the lab environment, practice the following:

1. **In Kibana**, identify an interesting session from the Arkime dashboard (e.g., a session with a large byte count or an unusual destination port).
2. Record the session’s timestamp, source IP, destination IP, and destination port.
3. **In Arkime Viewer**, search for the same session using Arkime query syntax:

```
ip.src == [SOURCE_IP] && ip.dst == [DEST_IP] && port == [DEST_PORT]
```

1. Expand the session and review the full details.
2. Export the PCAP if further analysis is needed.

> **💡 Note:** In a production environment with Zeek and Suricata also deployed (Labs 7C and 7D), this workflow would include querying Zeek conn logs and Suricata alerts for the same time window and IP addresses.
> 

### Task 6.3: Document the Correlation Workflow

Complete the following table for one session you investigated:

| Investigation Step | Tool Used | Finding |
| --- | --- | --- |
| Initial detection or observation |  |  |
| Session metadata review |  |  |
| Full packet retrieval |  |  |
| Analyst conclusion |  |  |

---

## Knowledge Check Questions

Answer the following questions based on this lab.

---

**Question 1:** What CWP 3-2.1 sensing capability does Arkime implement?

1. Passive Sensing
2. Security Alerting
3. **Full Packet Capture**
4. Endpoint Awareness

> **💡 Explanation:** Arkime implements the Full Packet Capture capability per CWP 3-2.1. Full Packet Capture stores complete packet payloads, unlike Passive Sensing (metadata only) or Security Alerting (signature-based alerts). Endpoint Awareness applies to host-based tools such as Sysmon.
> 

---

**Question 2:** According to CWP 3-2.1, Full Packet Capture data requires what type of retention?

1. Permanent retention for all captured data
2. **Short-duration retention to enable immediate inspection**
3. 90-day retention per federal records requirements
4. Retention only until the next system reboot

> **💡 Explanation:** CWP 3-2.1 specifies that Full Packet Capture data “only requires short duration retention to enable immediate inspection.” This is because full packet data consumes significant storage and the primary use case is near-real-time forensic analysis rather than long-term archival.
> 

---

**Question 3:** What Arkime component is responsible for monitoring network interfaces and writing PCAP files?

1. Arkime Viewer
2. Arkime Parliament
3. Elasticsearch
4. **Arkime Capture**

> **💡 Explanation:** Arkime Capture (arkime-capture) is the component that monitors network interfaces, captures packets, parses protocols, and stores both raw PCAP files and indexed session metadata. The Viewer provides the web interface for searching and analyzing captured data.
> 

---

**Question 4:** Which Elasticsearch index pattern contains Arkime session metadata?

1. `filebeat-*`
2. `winlogbeat-*`
3. **`arkime_sessions3-*`**
4. `wazuh-alerts-*`

> **💡 Explanation:** Arkime stores session metadata in indices following the `arkime_sessions3-YYMMDD` pattern. Each day’s sessions are stored in a separate date-stamped index. This is distinct from other tool indices such as filebeat (Zeek/Suricata) or winlogbeat (Sysmon).
> 

---

**Question 5:** In the network sensing triad used in this course, which question does Arkime primarily answer?

1. Was the traffic malicious?
2. Who talked to whom, using what protocol?
3. Which endpoint process initiated the connection?
4. **What exactly was in the packets?**

> **💡 Explanation:** Arkime’s primary value is providing complete packet payloads for forensic analysis — answering “what exactly was in the packets?” Suricata answers whether traffic was malicious (signature-based alerting). Zeek answers who talked to whom and with what protocol (connection metadata). Sysmon answers which endpoint process initiated the connection (endpoint awareness).
> 

---

**Question 6:** What must the capture interface support in order for Arkime to see all traffic on the network segment?

1. IPv6 addressing
2. Jumbo frames
3. **Promiscuous mode**
4. VLAN tagging

> **💡 Explanation:** Promiscuous mode allows the network interface to capture all traffic on the network segment, not just traffic addressed to the sensor itself. Without promiscuous mode, Arkime would only capture traffic destined to or originating from its own IP address. In production environments, Arkime sensors are typically connected to SPAN or mirror ports.
> 

---

**Question 7:** Which Arkime parameter controls automatic deletion of old PCAP files when disk space runs low?

1. `maxFileSizeG`
2. `pcapDir`
3. **`freeSpaceG`**
4. `rotateIndex`

> **💡 Explanation:** The `freeSpaceG` parameter defines the minimum free disk space threshold. When free space drops below this value, Arkime automatically deletes the oldest PCAP files to maintain available storage. The `maxFileSizeG` parameter controls individual file rotation size, not deletion.
> 

---

**Question 8:** According to CWP 3-2.1, at which DoD boundaries is Full Packet Capture required or available on order? (Select all that apply.)

1. **Enterprise Boundary**
2. **Regional Boundary**
3. **Local Boundary**
4. PIT/ICS/SCADA Boundary

> **💡 Explanation:** CWP 3-2.1 specifies Full Packet Capture requirements at the Enterprise Boundary (provides data on selected traffic content), Regional Boundary (provides bi-directional traffic data), and Local Boundary (on order, enables collection of full payload content). PIT/ICS/SCADA boundaries require Passive Sensing and Security Alerting but not Full Packet Capture.
> 

---

## Troubleshooting Guide

### Arkime Capture Service Fails to Start

**Problem:** `arkimecapture.service` reports failed status.

```bash
# Check service logs
sudo journalctl -u arkimecapture.service --no-pager -n 50

# Check Arkime capture log
sudo tail -50 /opt/arkime/logs/capture.log
```

**Common Causes and Solutions:**

| Cause | Solution |
| --- | --- |
| Elasticsearch unreachable | Verify Elasticsearch is running and the URL in `config.ini` is correct |
| Invalid interface name | Verify the interface name in `config.ini` matches an existing interface (`ip addr show`) |
| Permission denied on PCAP directory | Run `sudo chown -R nobody:daemon /opt/arkime/raw` or check the user Arkime runs as |
| Port already in use | Check if another process is using the viewer port: `sudo lsof -i :8005` |

### Arkime Viewer Not Accessible

**Problem:** Cannot reach `http://SENSOR_IP:8005` in the browser.

```bash
# Verify viewer is listening
sudo ss -tlnp | grep 8005

# Check firewall rules
sudo ufw status
sudo ufw allow 8005/tcp

# Verify viewer service is running
sudo systemctl status arkimeviewer.service
```

### No Sessions Appearing in Viewer

**Problem:** Viewer is accessible but shows no sessions.

```bash
# Verify capture is running and processing packets
sudo systemctl status arkimecapture.service

# Check if PCAP files are being created
ls -la /opt/arkime/raw/

# Check capture log for errors
sudo tail -20 /opt/arkime/logs/capture.log

# Verify Elasticsearch has session data
curl -u elastic:YOUR_ELASTIC_PASSWORD "http://192.168.10.100:9200/arkime_sessions3-*/_count"
```

If the count is 0, verify the capture interface is correct and receiving traffic:

```bash
# Test packet capture on the interface
sudo tcpdump -i ens33 -c 10
```

### Elasticsearch Database Initialization Errors

**Problem:** `db.pl init` fails.

```bash
# Verify Elasticsearch is running
curl -u elastic:YOUR_ELASTIC_PASSWORD "http://192.168.10.100:9200/_cluster/health?pretty"

# Check Perl dependencies (required by db.pl)
perl -e 'use LWP::UserAgent; print "OK\n"'

# If Perl modules are missing
sudo apt install libwww-perl libjson-perl -y
```

### Kibana Data View Shows No Data

**Problem:** Arkime data view created but no documents visible.

```bash
# Verify Arkime indices exist and have documents
curl -u elastic:YOUR_ELASTIC_PASSWORD "http://192.168.10.100:9200/_cat/indices?v" | grep arkime

# Verify the index pattern matches
curl -u elastic:YOUR_ELASTIC_PASSWORD "http://192.168.10.100:9200/arkime_sessions3-*/_count"
```

In Kibana:
1. Verify the time range in Discover covers the capture period.
2. Check that the timestamp field is set to `firstPacket`.
3. Verify the index pattern matches the actual index names.

---

## Lab Completion Checklist

Before submitting this lab, verify:

- [ ]  Arkime Capture installed and configured on Linux sensor
- [ ]  Arkime Viewer installed and accessible via web browser
- [ ]  Systemd services created, enabled, and running for both Capture and Viewer
- [ ]  PCAP files being stored in the configured directory
- [ ]  Sessions appearing in Arkime Viewer
- [ ]  Can search sessions using Arkime query syntax
- [ ]  Can view expanded session details (General, HTTP, DNS, TLS, etc.)
- [ ]  Can export PCAP data for forensic analysis
- [ ]  Kibana data view created for `arkime_sessions3-*`
- [ ]  Four visualizations created in Kibana
- [ ]  Dashboard assembled and saved
- [ ]  Completed all knowledge check questions
- [ ]  Documented correlation workflow results
- [ ]  Captured all required screenshots

### Screenshots Required

1. Arkime Viewer sessions page showing captured traffic
2. Expanded session detail view showing protocol information
3. Arkime query search results (any query from Task 4.3)
4. PCAP export dialog or downloaded file
5. Completed Arkime Kibana dashboard

---

## Extension Challenges (Optional)

If you complete the lab early, attempt these advanced tasks.

### Challenge 1: Arkime Hunt

Arkime includes a **Hunt** feature that performs full-text searches across raw PCAP content:

1. Navigate to the **Hunt** page in Arkime Viewer.
2. Create a hunt for a specific string (e.g., a domain name or user-agent string).
3. Review the matching sessions.
4. Document the hunt query and results.

### Challenge 2: Custom Arkime View

Create a custom view in Arkime that displays only sessions matching specific criteria:

1. Build a complex query combining multiple fields.
2. Save it as a named view for reuse.
3. Document the query and its purpose.

### Challenge 3: Automated PCAP Retention Script

Write a bash script that monitors PCAP storage usage and sends an alert when disk usage exceeds 80%:

```bash
#!/bin/bash
PCAP_DIR="/opt/arkime/raw"
THRESHOLD=80
USAGE=$(df "$PCAP_DIR" | tail -1 | awk '{print $5}' | sed 's/%//')
if [ "$USAGE" -gt "$THRESHOLD" ]; then
    echo "WARNING: PCAP storage at${USAGE}% — threshold is${THRESHOLD}%"
    # Add alerting logic here
fi
```

---

## Summary

In this lab, you implemented a full packet capture capability by:

1. **Deploying Arkime Capture and Viewer** on a Linux sensor for network traffic capture and indexed session analysis.
2. **Configuring packet capture** with appropriate storage and retention settings aligned with CWP 3-2.1’s short-duration retention requirement.
3. **Creating systemd services** for reliable, persistent operation of both Capture and Viewer components.
4. **Navigating the Arkime Viewer** to search, inspect, and export captured session data using Arkime query syntax.
5. **Integrating with Kibana** by creating data views, visualizations, and a dashboard for unified visibility alongside data from other sensing tools.
6. **Understanding the correlation workflow** for investigating incidents using the network sensing triad (Suricata for alerting, Zeek for metadata, Arkime for full packets).

This implementation aligns with CWP 3-2.1 requirements for Full Packet Capture:

- Bi-directional traffic capture at network boundaries
- Out-of-band storage in a network data repository
- Support for both real-time analysis and post-incident forensics
- Configurable retention based on operational requirements
- Integration with other sensing capabilities for comprehensive situational awareness

### Complete Network Sensing Stack

With this lab complete alongside Labs 7C (Zeek) and 7D (Suricata), you now have a comprehensive network sensing architecture:

| Tool | CWP 3-2.1 Capability | Function |
| --- | --- | --- |
| **Zeek** | Passive Sensing | Network metadata and protocol analysis |
| **Suricata** | Security Alerting | Signature-based threat detection |
| **Arkime** | Full Packet Capture | Complete packet storage and forensic retrieval |

Together with the endpoint sensing capabilities from Labs 7A (Sysmon) and 7B (Wazuh), this architecture implements four of the eight core sensing capabilities defined in CWP 3-2.1.

---

*Document Version: 1.0Last Updated: February 2025Classification: UNCLASSIFIED // FOR TRAINING USE ONLY*