# LAB: Network Analysis with Zeek

Owner: Eric Starace
Last edited by: Eric Starace

# Lab: Network Analysis with Zeek

## Cyber Defense Infrastructure Support Specialist Course

| **Estimated Completion Time** | 3–4 hours |
| --- | --- |
| **Prerequisites** | Lesson 8 Sections 8.1, 8.2, and 8.6; Lab 7A or 7B (Elastic Stack operational); Basic Linux administration |
| **Lab Type** | Hands-on technical deployment and configuration |
| **Classification** | UNCLASSIFIED // FOR TRAINING USE ONLY |

---

## Terminal Learning Objective

Deploy and configure Zeek as a passive network security monitor with JSON logging, centralized log collection to Elasticsearch, and Kibana visualizations to support network traffic analysis and threat detection.

## Enabling Learning Objectives

| ELO | Objective |
| --- | --- |
| 8B.1 | Install and deploy Zeek on an Ubuntu server configured to monitor the LAN interface |
| 8B.2 | Configure Zeek for comprehensive protocol logging and JSON output format |
| 8B.3 | Establish a log pipeline using Filebeat to forward Zeek logs to Elasticsearch |
| 8B.4 | Verify log collection by generating network traffic and confirming ingestion in Kibana |
| 8B.5 | Create Kibana visualizations and a dashboard for network traffic monitoring |
| 8B.6 | (Optional) Write a custom Zeek detection script for a specific network behavior |

## Tools Implemented / Required

| Tool | Purpose | Type |
| --- | --- | --- |
| Zeek | Passive network traffic analysis and protocol logging | Network Sensor (NIDS) |
| Filebeat | Log shipping from Zeek to Elasticsearch | Log Shipper |
| Elasticsearch | Log storage and indexing | Data Repository |
| Kibana | Visualization and analysis | Dashboard |

## KSAT Alignment

| KSAT ID | Type | Description |
| --- | --- | --- |
| K0059A | Knowledge (Core) | Knowledge of IDS/IPS tools and applications |
| K0087A | Knowledge (Core) | Knowledge of network traffic analysis methods |
| K0093 | Knowledge (Additional) | Knowledge of packet-level analysis |
| S0227 | Skill (Additional) | Skill in tuning sensors |
| T2772 | Task (Core) | Build, install, configure, and test dedicated cyber defense hardware |

---

## Lab Environment

### Required Systems

| System | Role | IP Address |
| --- | --- | --- |
| Ubuntu Server 22.04 LTS | Zeek Sensor + Elastic Stack (YOURSERVER) | 192.168.10.100 |
| Windows Server 2019/2022 | Domain Controller (DC01) | 192.168.10.5 |
| Windows 10/11 Workstation | Traffic generator (WS01) | 192.168.10.50 |

### Assumptions

- Elasticsearch and Kibana are installed and running on the Ubuntu server (192.168.10.100).
- The Ubuntu server has a network interface capable of seeing LAN traffic. If using a virtual environment, ensure the interface is in promiscuous mode or connected to a mirrored/SPAN port.
- You have sudo access on the Ubuntu server.

> **Note on Promiscuous Mode:** Zeek must be able to capture traffic that is not specifically destined for its own IP address. In a virtual environment, enable promiscuous mode on the virtual NIC. In a physical environment, configure a SPAN port on the switch to mirror traffic to the Zeek sensor’s interface.
> 

---

## Part 1: Installing and Deploying Zeek

**Estimated Time:** 45 minutes

**ELO Mapping:** 8B.1

### Background

Zeek (formerly Bro) is a passive network security monitor that generates detailed logs of network activity. Unlike signature-based IDS tools, Zeek focuses on creating a comprehensive record of all connections, protocols, and transactions it observes. This makes it an invaluable tool for both real-time monitoring and forensic investigation.

Per CWP 3-2.1, Zeek supports the **Passive Sensing** capability by providing metadata collection and protocol analysis of observed network traffic.

### Step 1.1: Install Zeek

Add the Zeek repository and install:

```bash
# Add Zeek repository
sudo apt update
sudo apt install -y curl gnupg
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | \
    sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | \
    gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

sudo apt update
sudo apt install -y zeek
```

> **Note:** If the repository method does not work in your environment, you can install from source or use an alternative method. Consult the Zeek documentation at https://docs.zeek.org for current installation instructions.
> 

### Step 1.2: Verify Installation

```bash
# Check Zeek version
/opt/zeek/bin/zeek --version

# Add Zeek to PATH for convenience
echo 'export PATH=/opt/zeek/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
```

### Step 1.3: Identify the Capture Interface

Determine which network interface Zeek should monitor:

```bash
# List network interfaces
ip addr show

# Identify the interface on the 192.168.10.0/24 network
# This is typically eth0, ens33, or ens160 depending on your environment
```

Record your interface name: ______________

### Step 1.4: Configure the Node

Edit the Zeek node configuration to specify the capture interface:

```bash
sudo nano /opt/zeek/etc/node.cfg
```

Set the interface to your identified network interface:

```
[zeek]
type=standalone
host=localhost
interface=ens33   # Replace with your actual interface name
```

### Step 1.5: Configure the Network

Edit the Zeek networks configuration to define your monitored networks:

```bash
sudo nano /opt/zeek/etc/networks.cfg
```

Add your network:

```
192.168.10.0/24    Lab LAN
```

### Step 1.6: Deploy Zeek

Use the Zeek control tool to deploy:

```bash
# Deploy the configuration
sudo /opt/zeek/bin/zeekctl deploy

# Check status
sudo /opt/zeek/bin/zeekctl status
```

The output should show Zeek running. If it shows “crashed,” check the crash log:

```bash
cat /opt/zeek/logs/current/reporter.log
```

> **Troubleshooting:** Common deployment failures include an incorrect interface name in node.cfg, insufficient permissions (must run as root or with proper capabilities), or the interface not being in promiscuous mode.
> 

**Capture a screenshot of `zeekctl status` showing Zeek running.**

### Knowledge Check: Zeek Deployment

1. Zeek is classified as a passive network monitor rather than an intrusion prevention system. What is the operational implication of this distinction?
    1. Zeek cannot detect malicious traffic
    2. Zeek requires less processing power than an IPS
    3. **Zeek observes and logs traffic without modifying or blocking it, meaning it cannot prevent attacks in progress but provides detailed records for analysis and investigation**
    4. Zeek only works on wireless networks
    
    💡
    As a passive monitor, Zeek copies and analyzes traffic without sitting inline. It cannot drop or modify packets. This means Zeek excels at providing comprehensive network visibility and forensic data, but must be paired with inline tools (like Suricata in IPS mode or firewalls) if blocking capability is needed.
    

---

## Part 2: Configuring Comprehensive Logging and JSON Output

**Estimated Time:** 30 minutes

**ELO Mapping:** 8B.2

### Background

By default, Zeek generates logs in a tab-separated value (TSV) format. For integration with Elasticsearch and modern SIEM platforms, JSON format is preferred because it preserves field names, handles nested data naturally, and is directly parseable without custom ingestion pipelines.

### Step 2.1: Enable JSON Output

Edit the Zeek local configuration:

```bash
sudo nano /opt/zeek/share/zeek/site/local.zeek
```

Add the following lines at the end of the file to enable JSON output:

```
# Enable JSON logging for SIEM integration
@load policy/tuning/json-logs.zeek
```

### Step 2.2: Review Enabled Log Types

Zeek generates many log types by default. Review what is currently loaded by examining the local.zeek file. Key log types include:

| Log File | Content | Security Value |
| --- | --- | --- |
| conn.log | All connections (TCP, UDP, ICMP) | Connection metadata, duration, bytes |
| dns.log | DNS queries and responses | Domain lookups, potential C2, tunneling |
| http.log | HTTP transactions | Web activity, user agents, URIs |
| ssl.log | SSL/TLS handshake details | Certificate info, JA3 hashes |
| files.log | File transfers observed | File hashes, MIME types |
| notice.log | Zeek-generated notices/alerts | Anomalies, policy violations |
| weird.log | Unusual/malformed traffic | Protocol violations, evasion attempts |
| x509.log | Certificate details | Certificate validation, expiry |

### Step 2.3: Enable Additional Logging Policies

Add these recommended policies to local.zeek for enhanced security visibility:

```bash
sudo nano /opt/zeek/share/zeek/site/local.zeek
```

Ensure the following lines are present (some may already be uncommented):

```
# Load standard detection scripts
@load protocols/ftp/detect
@load protocols/http/detect-sqli
@load protocols/http/detect-MHR
@load protocols/ssl/validate-certs
@load protocols/dns/detect-external-names

# File analysis
@load frameworks/files/hash-all-files
@load frameworks/files/detect-MHR

# Notice policies
@load policy/misc/known-devices
@load policy/misc/scan
```

### Step 2.4: Redeploy Zeek

Apply the configuration changes:

```bash
sudo /opt/zeek/bin/zeekctl deploy

# Verify status
sudo /opt/zeek/bin/zeekctl status
```

### Step 2.5: Verify JSON Output

Wait approximately 30 seconds for some traffic to be logged, then check the log format:

```bash
# Check that logs are in JSON format
head -5 /opt/zeek/logs/current/conn.log
```

The output should be JSON objects (one per line), not tab-separated values. If you still see TSV format, verify the JSON policy line was added correctly and that Zeek was redeployed.

```bash
# View a formatted sample of the connection log
cat /opt/zeek/logs/current/conn.log | head -3 | python3 -m json.tool
```

**Capture a screenshot of the JSON-formatted log output.**

### Knowledge Check: Zeek Logging

1. Why is JSON output preferred over Zeek’s default tab-separated format when integrating with Elasticsearch?
    1. JSON files are smaller than TSV files
    2. Elasticsearch cannot read TSV format
    3. **JSON preserves field names within each record, enables automatic field mapping in Elasticsearch, and handles nested or variable-length data without custom parsing pipelines**
    4. TSV format is deprecated in current Zeek versions
    
    💡
    Tab-separated logs require an external field mapping (header line or external schema) to understand what each column represents. JSON embeds the field name with each value, which allows Elasticsearch to automatically detect and map fields. This reduces configuration effort and eliminates errors from column misalignment.
    

---

## Part 3: Establishing the Log Pipeline

**Estimated Time:** 45 minutes

**ELO Mapping:** 8B.3

### Background

Filebeat is the recommended log shipper for forwarding Zeek logs to Elasticsearch. Filebeat includes a dedicated Zeek module that understands Zeek’s log format and applies appropriate field mappings.

### Step 3.1: Install Filebeat

On the Ubuntu server (where Zeek is running):

```bash
# Install Filebeat (match your Elasticsearch version)
sudo apt install -y filebeat
```

> **Note:** Ensure the Filebeat version matches your Elasticsearch version. Mismatched versions can cause ingestion failures.
> 

### Step 3.2: Enable the Zeek Module

Filebeat includes a built-in Zeek module:

```bash
sudo filebeat modules enable zeek
```

### Step 3.3: Configure the Zeek Module

Edit the Zeek module configuration:

```bash
sudo nano /etc/filebeat/modules.d/zeek.yml
```

Enable the log types you want to collect. At minimum, enable these critical log types:

```yaml
-module: zeek
connection:
enabled:true
var.paths:["/opt/zeek/logs/current/conn.log"]
dns:
enabled:true
var.paths:["/opt/zeek/logs/current/dns.log"]
http:
enabled:true
var.paths:["/opt/zeek/logs/current/http.log"]
files:
enabled:true
var.paths:["/opt/zeek/logs/current/files.log"]
ssl:
enabled:true
var.paths:["/opt/zeek/logs/current/ssl.log"]
notice:
enabled:true
var.paths:["/opt/zeek/logs/current/notice.log"]
weird:
enabled:true
var.paths:["/opt/zeek/logs/current/weird.log"]
x509:
enabled:true
var.paths:["/opt/zeek/logs/current/x509.log"]
```

### Step 3.4: Configure Filebeat Output

Edit the main Filebeat configuration:

```bash
sudo nano /etc/filebeat/filebeat.yml
```

Configure the Elasticsearch output:

```yaml
output.elasticsearch:
hosts:["192.168.10.100:9200"]
username:"elastic"
password:"your_password"
```

Disable the default Logstash output if it is enabled:

```yaml
#output.logstash:
  #hosts: ["localhost:5044"]
```

### Step 3.5: Set Up Index Templates and Dashboards

Load the Filebeat index templates and Kibana dashboards:

```bash
sudo filebeat setup -e
```

> **Note:** This command may take a few minutes. It creates index templates, data views, and pre-built dashboards in Kibana. The `-e` flag outputs progress to the console.
> 

### Step 3.6: Start Filebeat

```bash
sudo systemctl start filebeat
sudo systemctl enable filebeat

# Verify status
sudo systemctl status filebeat
```

Check for errors in the Filebeat log:

```bash
sudo tail -20 /var/log/filebeat/filebeat
```

### Step 3.7: Verify Index Creation

In Kibana, navigate to **Stack Management > Index Management** and look for indices matching `filebeat-*`. You should see the Zeek data flowing into the filebeat index.

Alternatively:

```bash
curl -u elastic:your_password "localhost:9200/_cat/indices?v" | grep filebeat
```

**Capture a screenshot of the index appearing in Kibana Index Management.**

---

## Part 4: Verifying Log Collection

**Estimated Time:** 30 minutes

**ELO Mapping:** 8B.4

### Background

After establishing the log pipeline, generate known traffic patterns and verify that Zeek captures them and that the events appear in Kibana. This validates the entire chain from network capture to visualization.

### Step 4.1: Generate HTTP Traffic

From WS01, generate HTTP traffic to create entries in Zeek’s http.log:

```powershell
# Generate HTTP traffic (from WS01)
Invoke-WebRequest -Uri "http://192.168.10.5" -UseBasicParsing
Invoke-WebRequest -Uri "http://www.example.com" -UseBasicParsing
```

Or from the Ubuntu server itself:

```bash
curl http://www.example.com
curl http://192.168.10.5
```

### Step 4.2: Generate DNS Traffic

```bash
# Generate DNS queries
nslookup www.example.com
nslookup www.google.com
dig @192.168.10.5 example.com
```

### Step 4.3: Verify Local Zeek Logs

Before checking Kibana, verify that Zeek is logging the traffic locally:

```bash
# Check connection log
cat /opt/zeek/logs/current/conn.log | python3 -m json.tool | tail -30

# Check DNS log
cat /opt/zeek/logs/current/dns.log | python3 -m json.tool | tail -10

# Check HTTP log (if HTTP traffic was generated)
cat /opt/zeek/logs/current/http.log | python3 -m json.tool | tail -10
```

### Step 4.4: Verify in Kibana

Open Kibana and navigate to **Discover**. Select the `filebeat-*` data view (or the Zeek-specific data view if one was created during setup).

1. Set the time range to the last 15 minutes.
2. Filter for Zeek events: add a filter for `event.module: zeek`
3. Verify you can see:
    - Connection events (`event.dataset: zeek.connection`)
    - DNS events (`event.dataset: zeek.dns`)
    - HTTP events (`event.dataset: zeek.http`)
4. Expand an event and examine the parsed fields.

**Capture a screenshot of Zeek events visible in Kibana Discover.**

### Step 4.5: Explore Zeek Fields

In Discover, examine the fields available in a Zeek connection event. Key fields to note:

| Field | Description |
| --- | --- |
| source.ip | Source IP address |
| destination.ip | Destination IP address |
| destination.port | Destination port |
| network.transport | Protocol (tcp, udp, icmp) |
| network.bytes | Total bytes transferred |
| event.duration | Connection duration |
| zeek.connection.state | Connection state (S0, S1, SF, etc.) |

### Knowledge Check: Log Verification

1. You generate HTTP traffic from WS01, and you can see entries in Zeek’s local http.log on the sensor, but no HTTP events appear in Kibana. What should you check first?
    1. Reinstall Zeek with a different configuration
    2. **Verify that the http module is enabled in Filebeat’s zeek.yml and that the log path matches Zeek’s actual log location**
    3. Restart the Windows workstation
    4. Increase the Elasticsearch heap size
    
    💡
    If data appears in Zeek’s local logs but not in Kibana, the issue is in the log pipeline between Zeek and Elasticsearch. The most common cause is that the specific log type is not enabled in Filebeat’s Zeek module configuration, or the file path in the module configuration does not match where Zeek is actually writing logs.
    

---

## Part 5: Creating Visualizations and Dashboard

**Estimated Time:** 30 minutes

**ELO Mapping:** 8B.5

### Background

Zeek’s comprehensive logging lends itself to powerful visualizations that provide situational awareness about network activity. Effective dashboards show traffic volume trends, top talkers, protocol distribution, and anomalous activity.

> **Note:** Filebeat’s setup command (Part 3, Step 3.5) may have installed pre-built Zeek dashboards. Check **Dashboard** in Kibana and search for “Zeek” to see if any are available. If so, explore them first, then create additional custom visualizations below.
> 

### Step 5.1: Top DNS Queries Visualization

In Kibana, navigate to **Visualize Library > Create visualization**.

1. Select **Lens**.
2. Set the data view to `filebeat-*`.
3. Add a filter: `event.dataset: zeek.dns`
4. Configure:
    - **Visualization type:** Bar horizontal
    - **Vertical axis:** `dns.question.name` (Top 15 values)
    - **Horizontal axis:** Count of records
5. Title: **Top DNS Queries (Zeek)**
6. Save.

### Step 5.2: Network Connections by Protocol

1. Create a new Lens visualization.
2. Filter: `event.module: zeek` and `event.dataset: zeek.connection`
3. Configure:
    - **Visualization type:** Donut
    - **Slice by:** `network.transport` (Top values)
    - **Size:** Count of records
4. Title: **Connections by Protocol (Zeek)**
5. Save.

### Step 5.3: Top Source-Destination Pairs

1. Create a new Lens visualization.
2. Filter: `event.module: zeek` and `event.dataset: zeek.connection`
3. Configure:
    - **Visualization type:** Table
    - **Row 1:** `source.ip` (Top 10 values)
    - **Row 2:** `destination.ip` (Top 10 values)
    - **Row 3:** `destination.port` (Top 10 values)
    - **Metric:** Count of records
4. Title: **Top Conversations (Zeek)**
5. Save.

### Step 5.4: Connection Volume Over Time

1. Create a new Lens visualization.
2. Filter: `event.module: zeek`
3. Configure:
    - **Visualization type:** Area
    - **Horizontal axis:** `@timestamp` (Date histogram)
    - **Vertical axis:** Count of records
    - **Break down by:** `event.dataset` (Top values)
4. Title: **Zeek Events Over Time**
5. Save.

### Step 5.5: Build the Dashboard

1. Navigate to **Dashboard > Create dashboard**.
2. Add all four visualizations from the library.
3. Arrange:
    - Zeek Events Over Time (top, full width)
    - Top DNS Queries (middle left)
    - Connections by Protocol (middle right)
    - Top Conversations (bottom, full width)
4. Title: **Zeek Network Monitoring**
5. Save.

**Capture a screenshot of the completed dashboard.**

---

## Part 6: Custom Zeek Detection Script (Optional)

**Estimated Time:** 30 minutes

**ELO Mapping:** 8B.6

### Background

Zeek’s scripting language allows analysts to write custom detection logic. Unlike signature-based rules, Zeek scripts can analyze protocol state, track connections over time, and correlate multiple events.

### Step 6.1: Create a Script to Detect Large DNS Responses

Large DNS responses can indicate DNS tunneling (data exfiltration via DNS). Create a custom script:

```bash
sudo nano /opt/zeek/share/zeek/site/detect-large-dns.zeek
```

```
##! Detect unusually large DNS responses that may indicate DNS tunneling

module LargeDNS;

export {
    ## The threshold in bytes for a DNS response to be considered large
    const large_dns_threshold = 512 &redef;

    ## Create a new notice type
    redef enum Notice::Type += {
        Large_DNS_Response,
    };
}

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
    {
    if ( !is_orig && len > large_dns_threshold )
        {
        NOTICE([$note=Large_DNS_Response,
                $msg=fmt("Large DNS response: %d bytes from %s", len, c$id$resp_h),
                $conn=c,
                $identifier=cat(c$id$resp_h)]);
        }
    }
```

### Step 6.2: Load the Script

Add the script to local.zeek:

```bash
echo '@load ./detect-large-dns.zeek' | sudo tee -a /opt/zeek/share/zeek/site/local.zeek
```

### Step 6.3: Deploy and Test

```bash
# Redeploy Zeek
sudo /opt/zeek/bin/zeekctl deploy

# Generate a DNS query that produces a large response
dig @8.8.8.8 google.com ANY

# Check for notices
cat /opt/zeek/logs/current/notice.log | python3 -m json.tool
```

> **Note:** Not all DNS queries will trigger this notice. The threshold may need adjustment for your environment.
> 

---

## Lab Completion Checklist

Before submitting this lab, verify:

- [ ]  Zeek installed and running (`zeekctl status` shows “running”)
- [ ]  Capture interface correctly configured in node.cfg
- [ ]  Network defined in networks.cfg
- [ ]  JSON logging enabled via local.zeek
- [ ]  Additional logging policies loaded
- [ ]  Zeek generating JSON logs in /opt/zeek/logs/current/
- [ ]  Filebeat installed with Zeek module enabled
- [ ]  Zeek module configured with correct log paths
- [ ]  Filebeat running and forwarding to Elasticsearch
- [ ]  Index visible in Kibana Index Management
- [ ]  Generated test traffic (HTTP, DNS) visible in local Zeek logs
- [ ]  Zeek events visible in Kibana Discover
- [ ]  Four visualizations created
- [ ]  Network monitoring dashboard assembled and saved
- [ ]  All knowledge check questions answered
- [ ]  All required screenshots captured

### Screenshots Required

1. `zeekctl status` showing Zeek running (Part 1)
2. JSON-formatted log output (Part 2)
3. Filebeat index in Kibana Index Management (Part 3)
4. Zeek events in Kibana Discover (Part 4)
5. Completed Zeek network monitoring dashboard (Part 5)

---

## Troubleshooting Guide

| Symptom | Possible Cause | Resolution |
| --- | --- | --- |
| Zeek status: “crashed” | Wrong interface name or permissions | Check reporter.log; verify interface in node.cfg |
| Logs still in TSV format | JSON policy not loaded | Verify `@load policy/tuning/json-logs.zeek` in local.zeek |
| No conn.log entries | Interface not seeing traffic | Enable promiscuous mode; verify SPAN/mirror config |
| Filebeat errors in log | Version mismatch with Elasticsearch | Match Filebeat version to Elasticsearch version |
| No data in Kibana | Filebeat not reading log path | Verify paths in zeek.yml match actual log locations |
| Missing fields in events | Zeek module not parsing JSON correctly | Ensure JSON logging is enabled before Filebeat starts |

---

## Summary

In this lab, you deployed a comprehensive network monitoring capability by:

1. **Installing and deploying Zeek** as a passive network sensor on the LAN interface
2. **Configuring JSON output and comprehensive logging** to capture connections, DNS, HTTP, SSL, files, and anomaly data
3. **Establishing a log pipeline** using Filebeat’s Zeek module to forward parsed events to Elasticsearch
4. **Validating the entire chain** by generating known traffic and confirming visibility from sensor to dashboard
5. **Creating visualizations** that provide operational awareness of network activity, top talkers, protocol distribution, and DNS query patterns
6. **(Optional) Writing a custom detection script** demonstrating Zeek’s programmable analysis capability

This implementation aligns with CWP 3-2.1 Passive Sensing and Metadata Collection capabilities, providing detailed network traffic records that support situational awareness, threat detection, and forensic investigation.

---

*Document Version: 1.0*

*Classification: UNCLASSIFIED // FOR TRAINING USE ONLY*