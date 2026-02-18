# LAB: Intrusion Detection with Suricata

Owner: Eric Starace
Last edited by: Eric Starace

# Lab: Intrusion Detection with Suricata

## Cyber Defense Infrastructure Support Specialist Course

| **Estimated Completion Time** | 3–4 hours |
| --- | --- |
| **Prerequisites** | Lesson 8 Sections 8.1, 8.2, and 8.7; Lab 7A or 7B (Elastic Stack operational); Basic Linux administration |
| **Lab Type** | Hands-on technical deployment and configuration |
| **Classification** | UNCLASSIFIED // FOR TRAINING USE ONLY |

---

## Terminal Learning Objective

Deploy and configure Suricata as a network intrusion detection system with managed rulesets, custom detection rules, EVE JSON logging, centralized log collection to Elasticsearch, and sensor tuning to reduce false positives.

## Enabling Learning Objectives

| ELO | Objective |
| --- | --- |
| 8C.1 | Install and deploy Suricata on an Ubuntu server configured for network capture on the LAN interface |
| 8C.2 | Configure Suricata’s network variables, capture settings, and detection engine for the lab environment |
| 8C.3 | Manage detection rules including updating rulesets from community sources, enabling rule categories, and writing custom detection rules |
| 8C.4 | Enable and configure EVE JSON logging for SIEM integration |
| 8C.5 | Establish a log pipeline using Filebeat to forward Suricata alerts and events to Elasticsearch |
| 8C.6 | Verify alert ingestion by generating test traffic and confirming events appear in Kibana |
| 8C.7 | Create Kibana visualizations and a monitoring dashboard for intrusion detection events |
| 8C.8 | Apply sensor tuning techniques including thresholds and suppression rules to reduce false positives |

## Tools Implemented / Required

| Tool | Purpose | Type |
| --- | --- | --- |
| Suricata | Signature-based network intrusion detection | Network IDS (NIDS) |
| suricata-update | Rule management and updates | Rule Manager |
| Filebeat | Log shipping from Suricata to Elasticsearch | Log Shipper |
| Elasticsearch | Log storage and indexing | Data Repository |
| Kibana | Visualization and analysis | Dashboard |

## KSAT Alignment

| KSAT ID | Type | Description |
| --- | --- | --- |
| K0059A | Knowledge (Core) | Knowledge of IDS/IPS tools and applications |
| S0227 | Skill (Additional) | Skill in tuning sensors |
| T0471 | Task (Additional) | Coordinate with Cyber Defense Analysts to manage and administer the updating of rules and signatures for specialized cyber defense applications |
| T2772 | Task (Core) | Build, install, configure, and test dedicated cyber defense hardware |

---

## Lab Environment

### Required Systems

| System | Role | IP Address |
| --- | --- | --- |
| Ubuntu Server 22.04 LTS | Suricata Sensor + Elastic Stack (YOURSERVER) | 192.168.10.100 |
| Windows Server 2019/2022 | Domain Controller (DC01) | 192.168.10.5 |
| Windows 10/11 Workstation | Traffic generator (WS01) | 192.168.10.50 |

### Assumptions

- Elasticsearch and Kibana are installed and running on the Ubuntu server.
- The Ubuntu server’s network interface can see LAN traffic (promiscuous mode or SPAN port configured).
- You have sudo access on the Ubuntu server.
- If you completed Lab 8B (Zeek), Filebeat is already installed. You will add the Suricata module to the existing Filebeat installation.

---

## Part 1: Installing and Deploying Suricata

**Estimated Time:** 30 minutes

**ELO Mapping:** 8C.1

### Background

Suricata is a high-performance network IDS/IPS engine capable of real-time intrusion detection, inline intrusion prevention, network security monitoring, and offline pcap processing. It uses signature-based detection rules compatible with the Snort rule format and adds additional features like multi-threading and protocol-aware detection keywords.

Per CWP 3-2.1, Suricata supports the **Security Alerting** sensing capability by generating alerts based on signature matches and protocol anomalies.

### Step 1.1: Install Suricata

```bash
# Add Suricata PPA for latest stable version
sudo add-apt-repository -y ppa:oisf/suricata-stable
sudo apt update

# Install Suricata and rule management tool
sudo apt install -y suricata suricata-update jq
```

### Step 1.2: Verify Installation

```bash
# Check version
suricata --build-info | head -5

# Check default configuration file location
ls -la /etc/suricata/suricata.yaml
```

### Step 1.3: Identify the Capture Interface

```bash
# List network interfaces and identify the LAN interface
ip addr show | grep -E "^[0-9]|inet "
```

Record your capture interface name: ______________

### Step 1.4: Test Configuration

Run a configuration test before starting the service:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```

If the test reports errors, address them before proceeding.

**Capture a screenshot of the successful configuration test.**

---

## Part 2: Configuring Suricata

**Estimated Time:** 30 minutes

**ELO Mapping:** 8C.2, 8C.4

### Background

Suricata’s primary configuration file (`suricata.yaml`) controls network variables, capture settings, detection engine behavior, and logging output. Proper configuration is essential for accurate detection and manageable alert volumes.

### Step 2.1: Configure Network Variables

Edit the Suricata configuration:

```bash
sudo nano /etc/suricata/suricata.yaml
```

Locate the `vars` section near the top of the file and set your network variables:

```yaml
vars:
address-groups:
HOME_NET:"[192.168.10.0/24]"
EXTERNAL_NET:"!$HOME_NET"
HTTP_SERVERS:"$HOME_NET"
DNS_SERVERS:"[192.168.10.5]"
```

> **Important:** The `HOME_NET` variable defines your protected network. Suricata uses this to determine the directionality of rules. An incorrect HOME_NET setting will cause rules to fire in the wrong direction or not at all.
> 

### Step 2.2: Configure the Capture Interface

In the same file, locate the `af-packet` section and set the interface:

```yaml
af-packet:
-interface: ens33   # Replace with your actual interface
cluster-id:99
cluster-type: cluster_flow
defrag:yes
use-mmap:yes
tpacket-v3:yes
```

### Step 2.3: Configure EVE JSON Logging

Locate the `outputs` section and ensure EVE JSON logging is enabled:

```yaml
outputs:
-eve-log:
enabled:yes
filetype: regular
filename: eve.json
types:
-alert:
tagged-packets:yes
-http:
extended:yes
-dns:
query:yes
answer:yes
-tls:
extended:yes
-files:
force-magic:yes
force-hash:[md5, sha256]
-stats:
totals:yes
threads:no
deltas:yes
```

> **Note:** The `force-hash` option under files instructs Suricata to compute MD5 and SHA256 hashes for all observed files. This is valuable for threat intelligence lookups but adds processing overhead.
> 

### Step 2.4: Set the Default Rule Path

Verify the rule path is set correctly:

```yaml
default-rule-path: /var/lib/suricata/rules

rule-files:
- suricata.rules
```

### Step 2.5: Save and Validate

Save the file and test the configuration:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```

Address any errors before proceeding.

### Knowledge Check: Suricata Configuration

1. You configure HOME_NET as `[10.0.0.0/8]` but your network actually uses 192.168.10.0/24. A rule reads `alert tcp $EXTERNAL_NET any -> $HOME_NET 80`. What is the impact?
    1. The rule fires correctly because it covers all private ranges
    2. **The rule may miss attacks targeting 192.168.10.0/24 from other 10.x.x.x addresses, and generates false positives for traffic between 10.x.x.x hosts that are actually external**
    3. Suricata automatically adjusts HOME_NET based on observed traffic
    4. The rule syntax becomes invalid
    
    💡
    HOME_NET must accurately reflect your actual protected network. If set too broadly, external-to-internal traffic patterns are misidentified. Legitimate traffic within the overly broad range is treated as internal, and real attacks from addresses within that range but outside your actual network are classified as internal traffic rather than external threats.
    

---

## Part 3: Managing Detection Rules

**Estimated Time:** 45 minutes

**ELO Mapping:** 8C.3

### Background

Suricata uses signature-based rules to detect known threats. Rules are maintained by community and commercial rule providers. The `suricata-update` tool manages rule downloads, enables/disables rule categories, and merges custom rules with community rulesets.

### Step 3.1: Update Rules from Community Sources

```bash
# Update rules (downloads from Emerging Threats Open by default)
sudo suricata-update

# List available rule sources
sudo suricata-update list-sources
```

Review the update output. Note how many rules were loaded:

```bash
# Check how many rules are active
sudo suricata-update list-sources --enabled
```

### Step 3.2: Enable Additional Rule Sources (Optional)

```bash
# Enable a specific source (example: tgreen/hunting rules)
sudo suricata-update enable-source tgreen/hunting

# Re-run update to download new rules
sudo suricata-update
```

### Step 3.3: Review Rule Categories

Examine the categories of rules that were loaded:

```bash
# List rule categories and counts
grep -c "alert" /var/lib/suricata/rules/suricata.rules
grep -oP 'classtype:\K[^;]+' /var/lib/suricata/rules/suricata.rules | sort | uniq -c | sort -rn | head -20
```

### Step 3.4: Understand Rule Syntax

Before writing custom rules, review the structure of an existing rule:

```bash
# View a sample rule
grep "sid:2100498" /var/lib/suricata/rules/suricata.rules
```

A Suricata rule follows this structure:

```
action protocol source_ip source_port -> dest_ip dest_port (options;)
```

Key rule options:

| Option | Purpose | Example |
| --- | --- | --- |
| msg | Alert message text | `msg:"Malware detected";` |
| content | Pattern to match in packet | `content:"cmd.exe";` |
| flow | Connection direction/state | `flow:to_server,established;` |
| sid | Unique signature ID | `sid:1000001;` |
| rev | Rule revision number | `rev:1;` |
| classtype | Alert classification | `classtype:trojan-activity;` |
| threshold | Rate limiting | `threshold:type limit,track by_src,count 1,seconds 60;` |

### Step 3.5: Write Custom Detection Rules

Create a local rules file for your custom rules:

```bash
sudo nano /var/lib/suricata/rules/local.rules
```

Add the following custom rules:

```
# Rule 1: Detect ICMP ping to HOME_NET (useful for testing)
alert icmp any any -> $HOME_NET any (msg:"LOCAL - ICMP Ping Detected"; sid:9000001; rev:1; classtype:misc-activity;)

# Rule 2: Detect SSH connection attempts to HOME_NET
alert tcp any any -> $HOME_NET 22 (msg:"LOCAL - SSH Connection Attempt"; flow:to_server; sid:9000002; rev:1; classtype:misc-activity;)

# Rule 3: Detect potential web shell - cmd.exe in HTTP URI
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL - Possible Web Shell cmd.exe in URI"; content:"cmd.exe"; http_uri; nocase; classtype:web-application-attack; sid:9000003; rev:1;)

# Rule 4: Detect DNS query to .ru domain (policy-based)
alert dns $HOME_NET any -> any 53 (msg:"LOCAL - DNS Query to .ru Domain"; dns.query; content:".ru"; endswith; classtype:policy-violation; sid:9000004; rev:1;)

# Rule 5: Detect potential data exfiltration - large outbound transfer
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"LOCAL - Large Outbound Transfer >10MB"; flow:to_server,established; dsize:>10000000; classtype:policy-violation; sid:9000005; rev:1;)
```

> **Note:** Custom rules should use SIDs starting at 9000000 or higher to avoid conflicts with community rule SIDs. The `LOCAL -` prefix in the message helps quickly identify custom rules in alert logs.
> 

### Step 3.6: Include Local Rules

Edit the suricata-update configuration to include local rules:

```bash
# Tell suricata-update to include local rules
echo "/var/lib/suricata/rules/local.rules" | sudo tee -a /etc/suricata/suricata-update.yaml.bak

# Or add directly to suricata.yaml rule-files section:
sudo nano /etc/suricata/suricata.yaml
```

Under `rule-files:`, add:

```yaml
rule-files:
- suricata.rules
- /var/lib/suricata/rules/local.rules
```

### Step 3.7: Restart Suricata

```bash
sudo systemctl restart suricata
sudo systemctl enable suricata

# Verify service is running
sudo systemctl status suricata
```

Check for rule loading errors:

```bash
sudo tail -50 /var/log/suricata/suricata.log | grep -i "rule\|error\|warning"
```

**Capture a screenshot of Suricata running with rules loaded.**

### Knowledge Check: Rule Management

1. You write a custom rule with `sid:2100500` and after a `suricata-update` run, your rule stops working. What happened?
    1. suricata-update deletes all custom rules automatically
    2. **The SID conflicts with a community rule; suricata-update overwrote your custom rule with the community version**
    3. Custom rules cannot be loaded alongside community rules
    4. The rule revision number was too low
    
    💡
    Community rule providers (Emerging Threats, Snort) use specific SID ranges. If your custom rule uses a SID within those ranges, suricata-update may overwrite it during an update. Always use SIDs above 9000000 for custom rules to avoid conflicts.
    

---

## Part 4: Establishing the Log Pipeline

**Estimated Time:** 30 minutes

**ELO Mapping:** 8C.5

### Background

Suricata’s EVE JSON output must be forwarded to Elasticsearch for centralized analysis. Filebeat includes a dedicated Suricata module that parses EVE JSON and maps fields to the Elastic Common Schema (ECS).

### Step 4.1: Enable the Suricata Filebeat Module

If Filebeat is already installed (from Lab 8B or another lab), enable the Suricata module:

```bash
sudo filebeat modules enable suricata
```

### Step 4.2: Configure the Suricata Module

Edit the module configuration:

```bash
sudo nano /etc/filebeat/modules.d/suricata.yml
```

```yaml
-module: suricata
eve:
enabled:true
var.paths:["/var/log/suricata/eve.json"]
```

### Step 4.3: Restart Filebeat

```bash
# If index templates need to be updated for the new module
sudo filebeat setup --pipelines --modules suricata

sudo systemctl restart filebeat

# Verify
sudo systemctl status filebeat
```

### Step 4.4: Verify Index Creation

In Kibana, navigate to **Stack Management > Index Management** and confirm that Suricata data is being indexed. Suricata events will appear in the `filebeat-*` index alongside Zeek events (if Lab 8B was completed), differentiated by the `event.module: suricata` field.

```bash
curl -u elastic:your_password "localhost:9200/_cat/indices?v" | grep filebeat
```

---

## Part 5: Verifying Alert Ingestion

**Estimated Time:** 20 minutes

**ELO Mapping:** 8C.6

### Background

Generate traffic that triggers your custom rules and verify that alerts flow from Suricata through Filebeat to Kibana.

### Step 5.1: Generate Test Traffic

**Trigger Rule 1 (ICMP):**

```bash
# From any system, ping a host on the HOME_NET
ping -c 5 192.168.10.50
```

**Trigger Rule 2 (SSH):**

```bash
# Attempt SSH connection (even if it fails, the attempt triggers the rule)
ssh user@192.168.10.50
```

### Step 5.2: Verify Local Alerts

Check Suricata’s EVE log for alerts:

```bash
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert")' | tail -30
```

You should see alerts with your custom rule messages (e.g., “LOCAL - ICMP Ping Detected”).

Record the alerts observed:

| SID | Message | Source IP | Destination IP |
| --- | --- | --- | --- |
|  |  |  |  |
|  |  |  |  |

### Step 5.3: Verify in Kibana

Open Kibana and navigate to **Discover** with the `filebeat-*` data view.

1. Set the time range to the last 15 minutes.
2. Add a filter: `event.module: suricata`
3. Add another filter: `event.kind: alert`
4. Verify your custom rule alerts are visible.
5. Expand an alert and examine the fields, including:
    - `suricata.eve.alert.signature`
    - `suricata.eve.alert.signature_id`
    - `suricata.eve.alert.category`
    - `source.ip` and `destination.ip`

**Capture a screenshot of Suricata alerts visible in Kibana.**

---

## Part 6: Creating Visualizations and Dashboard

**Estimated Time:** 30 minutes

**ELO Mapping:** 8C.7

### Step 6.1: Alert Volume Over Time

In Kibana, create a Lens visualization:

1. Filter: `event.module: suricata` and `event.kind: alert`
2. Configure:
    - **Type:** Bar vertical (stacked)
    - **Horizontal axis:** `@timestamp` (Date histogram)
    - **Vertical axis:** Count of records
    - **Break down by:** `suricata.eve.alert.severity` (Top values)
3. Title: **Suricata Alert Volume Over Time**
4. Save.

### Step 6.2: Top Alert Signatures

1. Create a new Lens visualization.
2. Filter: `event.module: suricata` and `event.kind: alert`
3. Configure:
    - **Type:** Bar horizontal
    - **Vertical axis:** `suricata.eve.alert.signature` (Top 15 values)
    - **Horizontal axis:** Count of records
4. Title: **Top Suricata Alert Signatures**
5. Save.

### Step 6.3: Alert Sources Table

1. Create a new Lens visualization.
2. Filter: `event.module: suricata` and `event.kind: alert`
3. Configure:
    - **Type:** Table
    - **Row 1:** `source.ip` (Top 10)
    - **Row 2:** `suricata.eve.alert.signature` (Top 5)
    - **Metric:** Count
4. Title: **Alert Sources and Signatures**
5. Save.

### Step 6.4: Suricata Protocol Events

1. Create a new Lens visualization.
2. Filter: `event.module: suricata` (no alert filter — include all event types)
3. Configure:
    - **Type:** Donut
    - **Slice by:** `event.type` or `suricata.eve.event_type` (Top values)
    - **Size:** Count
4. Title: **Suricata Event Types**
5. Save.

### Step 6.5: Build the Dashboard

1. Navigate to **Dashboard > Create dashboard**.
2. Add all four visualizations.
3. Arrange:
    - Alert Volume Over Time (top, full width)
    - Top Alert Signatures (middle left)
    - Suricata Event Types (middle right)
    - Alert Sources and Signatures (bottom, full width)
4. Title: **Suricata Intrusion Detection**
5. Save.

**Capture a screenshot of the completed dashboard.**

---

## Part 7: Sensor Tuning

**Estimated Time:** 30 minutes

**ELO Mapping:** 8C.8

### Background

A newly deployed IDS typically generates a high volume of alerts, many of which are false positives or low-priority informational alerts. Sensor tuning reduces noise so that analysts can focus on genuinely suspicious events. Tuning is an iterative process that requires understanding the network baseline and evaluating each alert in context.

### Step 7.1: Analyze Current Alert Volume

Identify which rules are firing most frequently:

```bash
# Count alerts by signature (top 20 noisiest rules)
sudo cat /var/log/suricata/eve.json | \
    jq -r 'select(.event_type=="alert") | .alert.signature_id' | \
    sort | uniq -c | sort -rn | head -20
```

Record the top five noisiest rules:

| Rank | SID | Count | Signature |
| --- | --- | --- | --- |
| 1 |  |  |  |
| 2 |  |  |  |
| 3 |  |  |  |
| 4 |  |  |  |
| 5 |  |  |  |

### Step 7.2: Evaluate Alert Legitimacy

For each noisy rule, determine:
- Is it a true positive (real threat)?
- Is it a false positive (benign activity matching the rule)?
- Is it true but unactionable (known, accepted behavior)?

### Step 7.3: Apply Threshold Rules

Create or edit the threshold configuration file:

```bash
sudo nano /etc/suricata/threshold.config
```

Add threshold and suppression rules for your identified noisy signatures:

```
# Limit ICMP ping alerts to 1 per source per 60 seconds
threshold gen_id 1, sig_id 9000001, type limit, track by_src, count 1, seconds 60

# Suppress SSH alerts from the Admin network (known admin traffic)
suppress gen_id 1, sig_id 9000002, track by_src, ip 192.168.200.0/24

# Suppress alerts from the vulnerability scanner (if applicable)
# suppress gen_id 1, sig_id 0, track by_src, ip 192.168.10.100
```

Threshold types:

| Type | Behavior |
| --- | --- |
| `limit` | Alert on the first N matches per time period, then suppress remaining |
| `threshold` | Alert only after N matches per time period |
| `both` | Alert once per time period after N matches |

### Step 7.4: Apply and Validate

```bash
# Restart Suricata to apply threshold changes
sudo systemctl restart suricata

# Generate the same test traffic again
ping -c 20 192.168.10.50

# Compare alert volume (should be reduced)
sudo cat /var/log/suricata/eve.json | \
    jq -r 'select(.event_type=="alert") | .alert.signature_id' | \
    sort | uniq -c | sort -rn | head -10
```

Document your before-and-after comparison:

| SID | Before Tuning (count) | After Tuning (count) | Reduction |
| --- | --- | --- | --- |
|  |  |  |  |
|  |  |  |  |

### Step 7.5: Document Tuning Changes

Complete the tuning log:

| Date | SID | Action | Justification | Analyst |
| --- | --- | --- | --- | --- |
|  | 9000001 | Threshold: limit 1/60s |  |  |
|  | 9000002 | Suppress from Admin net |  |  |

### Knowledge Check: Sensor Tuning

1. After deploying Suricata, you observe 50,000 alerts from SID 2100498 in the first hour, all triggered by normal DNS traffic. What is the most appropriate tuning action?
    1. Delete the rule entirely from the ruleset
    2. Disable all DNS-related rules
    3. Increase Suricata’s processing threads
    4. **Apply a threshold or suppress rule to limit alerts for this SID while keeping the detection capability available for unusual volumes**
    
    💡
    Deleting or disabling a rule eliminates the detection capability entirely. Threshold and suppress rules maintain the detection logic but reduce the alert volume to a manageable level. A `limit` threshold allows the first alert through per time period so analysts remain aware, while a `suppress` for known-good sources eliminates alerts from trusted traffic.
    
2. What is the primary difference between a `threshold` and a `suppress` rule in Suricata?
    1. Threshold rules apply to inbound traffic; suppress rules apply to outbound
    2. Threshold rules work on TCP; suppress rules work on UDP
    3. **A threshold controls how many times a rule fires (rate-limiting), while a suppress prevents a rule from firing for specific IP addresses or networks entirely**
    4. There is no functional difference; they are synonyms
    
    💡
    Thresholds limit alert frequency (e.g., “only alert once per minute per source”) but still allow the rule to fire for all sources. Suppress rules prevent a specific rule from generating alerts for specified IP addresses or networks, effectively whitelisting known-good sources for that particular signature.
    

---

## Lab Completion Checklist

Before submitting this lab, verify:

- [ ]  Suricata installed and configuration test passed
- [ ]  HOME_NET and interface correctly configured
- [ ]  EVE JSON logging enabled with alert, HTTP, DNS, TLS, and files types
- [ ]  Community rules updated via suricata-update
- [ ]  Five custom rules written in local.rules
- [ ]  Local rules loaded and Suricata restarted
- [ ]  Filebeat Suricata module enabled and configured
- [ ]  Suricata events appearing in Kibana Discover
- [ ]  Test traffic generated and custom rule alerts verified locally
- [ ]  Custom rule alerts visible in Kibana
- [ ]  Four visualizations created
- [ ]  Intrusion detection dashboard assembled and saved
- [ ]  Top noisy rules identified and analyzed
- [ ]  Threshold/suppress rules applied
- [ ]  Before-and-after alert volume documented
- [ ]  Tuning log completed
- [ ]  All knowledge check questions answered
- [ ]  All required screenshots captured

### Screenshots Required

1. Successful configuration test (Part 1)
2. Suricata running with rules loaded (Part 3)
3. Suricata alerts in Kibana Discover (Part 5)
4. Completed Suricata intrusion detection dashboard (Part 6)

---

## Troubleshooting Guide

| Symptom | Possible Cause | Resolution |
| --- | --- | --- |
| Suricata fails to start | YAML syntax error in suricata.yaml | Run `suricata -T` for validation details |
| No alerts generated | HOME_NET misconfigured | Verify HOME_NET matches actual network |
| Custom rules not loading | SID conflict or syntax error | Check suricata.log for rule parse errors |
| EVE log empty | Interface not capturing traffic | Verify interface name and promiscuous mode |
| Alerts in EVE but not Kibana | Filebeat module not configured | Verify suricata.yml path matches eve.json location |
| High CPU usage | Too many active rules | Disable unneeded rule categories; tune performance settings |

---

## Summary

In this lab, you deployed and operated an intrusion detection system by:

1. **Installing Suricata** and configuring it for the lab network environment with proper network variables and capture settings
2. **Configuring EVE JSON logging** to provide structured output suitable for SIEM ingestion
3. **Managing detection rules** including updating community rulesets, understanding rule syntax, and writing five custom detection rules for environment-specific threats
4. **Establishing a log pipeline** using Filebeat’s Suricata module to forward alerts and events to Elasticsearch
5. **Validating detection** by generating test traffic and confirming the full chain from network capture through to Kibana
6. **Building monitoring dashboards** for operational awareness of alert volumes, top signatures, and source analysis
7. **Tuning the sensor** using thresholds and suppression to reduce false positive alerts while maintaining detection capability

This implementation aligns with CWP 3-2.1 Security Alerting capabilities and directly supports the T0471 task of managing rules and signatures on specialized cyber defense applications.

---

*Document Version: 1.0*

*Classification: UNCLASSIFIED // FOR TRAINING USE ONLY*