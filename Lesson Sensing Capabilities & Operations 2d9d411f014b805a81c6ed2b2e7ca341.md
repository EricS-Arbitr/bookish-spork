# Lesson: Sensing Capabilities & Operations

Owner: Eric Starace
Last edited by: Wendy Schey

| **Lesson Reference** |  |
| --- | --- |
| **Lesson Author** | Arbitr |
| **Lesson ID (LES-XXX)** | LES-XXX |
| **Lesson Name** | Sensing Capabilities and Operations |
| **Duration (x.x)** |  |
| **Terminal Learning Objectives (TLOs)** | **Given** instruction on cyberspace sensing concepts, the eight core sensing capabilities, sensing goals and objectives, boundary-specific requirements, and indicator/analytics development, **the learner** deploys, configures, and supports sensing capabilities that enable detection of adversary activity, **demonstrating** the ability to implement sensing per CWP 3-2.1 requirements, configure sensors at appropriate boundaries, and coordinate indicator development **in accordance with** CWP 3-2.1, CWP 3-2, CWP 3-33.4, and applicable USCYBERCOM guidance. |
| **Enabling Learning Objectives (ELOs)** | - Explain the purpose of sensing in Defensive Cyberspace Operations |
|  | - Describe the eight core sensing capabilities per CWP 3-2.1 |
|  | - Explain the three sensing goals and nine supporting objectives |
|  | - Identify sensing requirements for each boundary type |
|  | - Differentiate between indicators and analytics |
|  | - Deploy and configure basic sensing capabilities |
|  | - Support indicator and analytics development efforts |
| **DCWF KSATs** | K0059A - Knowledge of Intrusion Detection System (IDS)/Intrusion Prevention System (IPS) tools and applications |
|  | K0087A - Knowledge of network traffic analysis (tools, methodologies, processes) |
|  | S0227 - Skill in tuning sensors |
|  | T2772 - Build, install, configure, and test dedicated cyber defense hardware |
|  | T0471 - Coordinate with Cyber Defense Analysts to manage and administer the updating of rules and signatures |
| **JQR Line Items** |  |
| **Dependency (Tools, DB, Etc.)** |  |

**This confluence page contains Controlled Unclassified Information (CUI) and must be handled within the protections of that data.**

---

## How to Use This Lesson

This lesson introduces the critical concept of cyberspace sensing—the foundation of situational awareness in Defensive Cyberspace Operations (DCO). Building on understanding of network architecture (Lesson 4), defense-in-depth boundaries (Lesson 4), Mission Relevant Terrain (Lesson 5), and access controls (Lesson 6), learners develop skills to deploy and configure sensing capabilities that enable detection of adversary activity.

**Recommended Approach:**

1. Read each section thoroughly before attempting exercises
2. Complete all “Check Your Understanding” questions and compare to answer keys
3. Perform hands-on exercises in the lab environment
4. Use the self-assessment checklists to verify progress
5. Review any areas scoring below 80% before proceeding

**Icons Used in This Lesson:**
- 💡 **Key Concept** - Important information to remember
- ⚠️ **Important** - Critical information requiring attention

**Prerequisites:**
Before starting this lesson, learners must have completed:
- Lesson 1: Foundations of Cybersecurity
- Lesson 2: DoD Cyberspace Operations Framework
- Lesson 3: Network Infrastructure and Protocols
- Lesson 4: Network Security Architecture
- Lesson 5: Mission Relevant Terrain in Cyberspace (MRT-C)
- Lesson 6: Access Control Mechanisms

---

## Overview

Sensing is the foundation of situational awareness in cyberspace defense. This lesson covers the eight core sensing capabilities defined in CWP 3-2.1 (USCYBERCOM Operational Guidance for Sensing), the three sensing goals and their supporting objectives, sensing deployment requirements by boundary type, and the development of indicators and analytics. The content provides the doctrinal foundation for deploying and configuring sensing technologies in DoD environments.

### Terminal Learning Objective (TLO)

**Given** instruction on cyberspace sensing concepts, the eight core sensing capabilities, sensing goals and objectives, boundary-specific requirements, and indicator/analytics development, **the learner** deploys, configures, and supports sensing capabilities that enable detection of adversary activity, **demonstrating** the ability to implement sensing per CWP 3-2.1 requirements, configure sensors at appropriate boundaries, and coordinate indicator development **in accordance with** CWP 3-2.1, CWP 3-2, CWP 3-33.4, and applicable USCYBERCOM guidance.

### Enabling Learning Objectives (ELOs)

Upon completion of this lesson, learners are able to:

 **Objective 1:** Explain the purpose of sensing in Defensive Cyberspace Operations

 **Objective 2:** Describe the eight core sensing capabilities per CWP 3-2.1

 **Objective 3:** Explain the three sensing goals and nine supporting objectives

 **Objective 4:** Identify sensing requirements for each boundary type

 **Objective 5:** Differentiate between indicators and analytics

 **Objective 6:** Deploy and configure basic sensing capabilities

 **Objective 7:** Support indicator and analytics development efforts

### KSAT Coverage

This lesson addresses the following Knowledge, Skills, Abilities, and Tasks:

| KSAT ID | Type | Description |
| --- | --- | --- |
| K0059A | Knowledge (Core) | Intrusion Detection System (IDS)/Intrusion Prevention System (IPS) tools and applications |
| K0087A | Knowledge (Core) | Network traffic analysis (tools, methodologies, processes) |
| S0227 | Skill (Additional) | Tuning sensors |
| T2772 | Task (Core) | Build, install, configure, and test dedicated cyber defense hardware |
| T0471 | Task (Additional) | Coordinate with Cyber Defense Analysts to manage and administer the updating of rules and signatures |

### Doctrinal References

This lesson is based primarily on:
- **CWP 3-2.1**, USCYBERCOM Operational Guidance for Sensing (April 2017)
- **CWP 3-2**, Defensive Cyberspace Operations (March 2017)
- **CWP 3-33.4**, CPT Organization, Functions, and Employment (May 2022)

---

## Section 7.1: Introduction to Cyberspace Sensing

 **Learning Objective:** Explain the purpose of sensing in DCO and its relationship to situational awareness

---

### 7.1.1 Purpose of Sensing in DCO

Effective defense of DoD cyberspace requires awareness of what is happening within that cyberspace. Sensing provides the data necessary to achieve this awareness.

<aside>
💡

**Key Concept - Sensing Purpose:**
 *Per CWP 3-2.1:* “USCYBERCOM must gain and maintain situational awareness of activity within Department of Defense (DOD) cyberspace in order to accomplish its assigned mission.”

</aside>

### Why Sensing Matters

Situational awareness in cyberspace comes from two sources:

1. **Awareness of Friendly Activity:**
    - Command and Control (C2) channels
    - Network management functions
    - DODIN Operations reporting
2. **Awareness of Adverse Activity:**
    - Requires dedicated sensing capabilities
    - Cannot rely solely on reporting
    - Must detect activity that adversaries attempt to hide

 *Per CWP 3-2.1:* “Awareness of friendly activity alone is insufficient. USCYBERCOM and all who are assigned to protect DOD cyberspace terrain must also gain and maintain awareness of adverse activity occurring within that terrain.”

### The Challenge

![04e71d34-aceb-4321-bca8-586e517cc9fb.png](04e71d34-aceb-4321-bca8-586e517cc9fb.png)

---

### 7.1.2 Sensing vs. Sensors

Understanding the distinction between sensing (the capability) and sensors (the tools) is fundamental.

<aside>
💡

**Key Concept - Sensing vs. Sensors:**

- **Sensing** is the *capability* to collect and process data about cyberspace activity
- **Sensors** are the *tools and technologies* that provide sensing capabilities
- A single sensor may provide multiple sensing capabilities
- A single sensing capability may require multiple sensors
</aside>

### Sensing as a Capability

Sensing capabilities are defined by what data they collect and how that data supports defensive operations:

| Capability | What It Provides | How It Supports Defense |
| --- | --- | --- |
| **Passive Sensing** | Network traffic metadata | Pattern analysis, anomaly detection |
| **Full Packet Capture** | Complete packet content | Deep inspection, forensics |
| **Security Alerting** | Automated notifications | Real-time awareness |
| **Endpoint Awareness** | Host behavior data | Threat detection on hosts |

### Sensors as Tools

Sensors are the technical implementations that deliver sensing capabilities:

| Sensor Type | Example Tools | Capabilities Provided |
| --- | --- | --- |
| Network TAP | Gigamon, IXIA | Passive Sensing, Full Packet Capture |
| IDS/IPS | Snort, Suricata, Zeek | Passive Sensing, Security Alerting |
| SIEM | Splunk, Elastic, ArcSight | Security Alerting, Analysis |
| EDR | CrowdStrike, Carbon Black | Endpoint Awareness |

---

### 7.1.3 Situational Awareness Through Sensing

Sensing enables situational awareness—the understanding of what is happening in the cyberspace environment.

### Components of Situational Awareness

![image.png](image%204.png)

### From Sensing to Decision

 *Per CWP 3-2.1:* “Improved and more rapid decision making requires access to accurate, timely and complete information. This information must provide situational awareness of the current state of the environment; the condition, disposition and actions of friendly forces; as well as the condition, disposition and actions of adversaries.”

**The Decision Cycle:**

1. **Sensing** collects raw data
2. **Analysis** transforms data into information
3. **Assessment** provides context and meaning
4. **Decision** enables action
5. **Action** affects the environment
6. **Sensing** observes the results (cycle repeats)

---

### 7.1.4 Relationship to DCO-IDM

Sensing is integral to Defensive Cyberspace Operations - Internal Defensive Measures (DCO-IDM).

### DCO-IDM Framework Integration

The Comprehensive DCO-IDM Framework provides context for sensing requirements by defining:

**Tasks (From NIST Cyber Security Framework):**

| Task | Definition |
| --- | --- |
| **Identify** | Develop understanding to manage cyber risk |
| **Protect** | Implement safeguards for critical services |
| **Detect** | Identify cybersecurity events |
| **Respond** | Take action regarding detected events |
| **Recover** | Restore impaired capabilities |

**Activities (From Cyber Kill Chain):**

- Reconnaissance
- Weaponization
- Delivery
- Exploitation
- Installation
- Command & Control
- Actions on Objectives

**Locations (Defense Layers):**

- Perimeter (Enterprise/Regional/Local Boundaries)
- Internal Network
- Endpoint
- Application
- Data

 *Per CWP 3-2.1 Appendix D:* Sensing objectives map to the Protect, Detect, and Respond tasks across all Kill Chain stages and defense layers.

### Sensing Role in DCO-IDM

![image.png](image%205.png)

---

### 7.1.5 Area of Concern for Sensing

Sensing capabilities must cover all DoD cyberspace terrain.

 *Per CWP 3-2.1:* “The area of concern for the development, selection, deployment and operation of sensing capabilities includes all DOD cyberspace terrain, to include Platform Information Technology (PIT), Industrial Control System/Supervisory Control and Data Acquisition (ICS/SCADA), and Special Purpose Networks (SPN) systems.”

### Terrain Types Requiring Sensing

| Terrain Type | Description | Sensing Considerations |
| --- | --- | --- |
| **DODIN** | DoD Information Network | Full sensing suite at all boundaries |
| **PIT** | Platform IT (weapons systems) | Specialized, non-disruptive sensing |
| **ICS/SCADA** | Industrial control systems | Protocol-aware, safety-conscious |
| **SPN** | Special Purpose Networks | Mission-specific requirements |
| **Assigned Terrain** | External terrain assigned to defend | Deployable sensing capabilities |

⚠️ **Important:** Sensing requirements extend beyond DoD network boundaries when directed to defend assigned terrain within friendly cyberspace.

---

### Check Your Understanding - Section 7.1

### Knowledge Check: Sensing Purpose

What is the primary purpose of sensing in DCO according to CWP 3-2.1?

1. To replace network management systems
2. To eliminate the need for human analysts
3. **To gain and maintain situational awareness of activity within DoD cyberspace**
4. To automate all defensive responses

<aside>
💡

*Per CWP 3-2.1, the primary purpose is to “gain and maintain situational awareness of activity within Department of Defense (DOD) cyberspace” to accomplish USCYBERCOM’s mission. This includes awareness of both friendly and adverse activity.*

</aside>

### Knowledge Check: Sensing vs Sensors

What is the difference between “sensing” and “sensors”?

1. They are the same thing
2. Sensing is hardware; sensors are software
3. **Sensing is the capability to collect data; sensors are the tools that provide that capability**
4. Sensors collect data; sensing analyzes it

<aside>
💡

*Sensing is the capability to collect and process data about cyberspace activity. Sensors are the tools and technologies that provide sensing capabilities. A single sensor may provide multiple sensing capabilities, and multiple sensors may be needed for a single sensing capability.*

</aside>

### Knowledge Check: Situational Awareness Sources

What two types of awareness does cyberspace situational awareness require?

1. Internal and external awareness
2. Strategic and tactical awareness
3. **Awareness of friendly activity and awareness of adverse activity**
4. Real-time and historical awareness

<aside>
💡

*Cyberspace situational awareness requires awareness of friendly activity (from C2 channels and network management) and awareness of adverse activity (from dedicated sensing capabilities). Awareness of friendly activity alone is insufficient because adversaries actively attempt to evade detection.*

</aside>

### Knowledge Check: NIST Framework Tasks

Which tasks from the NIST Cyber Security Framework does the DCO-IDM Framework use?

1. Plan, Do, Check, Act
2. Prevent, Detect, Correct
3. **Identify, Protect, Detect, Respond, Recover**
4. Assess, Authorize, Monitor

<aside>
💡

*The five NIST Cyber Security Framework tasks are: Identify (develop understanding to manage cyber risk), Protect (implement safeguards for critical services), Detect (identify cybersecurity events), Respond (take action regarding detected events), and Recover (restore impaired capabilities).*

</aside>

### Knowledge Check: Sensing and NIST Tasks

Which three NIST tasks does sensing primarily support?

1. Identify, Protect, Recover
2. **Protect, Detect, Respond**
3. Identify, Detect, Recover
4. Protect, Respond, Recover

<aside>
💡

*Sensing primarily supports Protect (informs automated countermeasures), Detect (core sensing function, identifies adversary activity), and Respond (enables incident scoping and forensic analysis). Per CWP 3-2.1 Appendix D, sensing objectives map to these three tasks across all Kill Chain stages and defense layers.*

</aside>

### Knowledge Check: Terrain Coverage

What types of DoD cyberspace terrain require sensing coverage per CWP 3-2.1?

1. Only DODIN and classified networks
2. Only enterprise and regional boundaries
3. **DODIN, PIT, ICS/SCADA, SPN, and Assigned Terrain**
4. Only networks with internet connectivity

<aside>
💡

*Per CWP 3-2.1, sensing must cover DODIN (DoD Information Network), PIT (Platform Information Technology), ICS/SCADA (Industrial Control Systems), SPN (Special Purpose Networks), and Assigned Terrain (external terrain assigned to defend).*

</aside>

### Knowledge Check: Friendly Activity Awareness

Why is awareness of friendly activity alone insufficient for cyberspace defense?

1. Friendly activity is not important
2. Network management provides all needed data
3. **Adversaries actively attempt to evade detection and operate covertly**
4. Friendly systems cannot be compromised

<aside>
💡

*Per CWP 3-2.1, awareness of friendly activity alone is insufficient because adversaries actively attempt to evade detection and operate covertly. Dedicated sensing capabilities are required to detect adverse activity that adversaries try to hide.*

</aside>

### Knowledge Check: Decision Cycle

How does sensing support the decision cycle?

1. Sensing replaces the need for decisions
2. Sensing only supports automated responses
3. **Sensing collects raw data that is analyzed, assessed, and used to enable decisions and actions**
4. Sensing provides final decisions to operators

<aside>
💡

*Sensing supports the decision cycle by collecting raw data, which analysis transforms into information, assessment provides context and meaning, decision enables action, action affects the environment, and sensing observes the results (cycle repeats). Improved and more rapid decision making requires access to accurate, timely, and complete information.*

</aside>

---

### Progress Checkpoint - Section 7.1

Before proceeding to Section 7.2, verify the ability to accomplish the following:

- [ ]  Explain the purpose of sensing per CWP 3-2.1
- [ ]  Differentiate between sensing capabilities and sensor tools
- [ ]  Describe the three levels of situational awareness
- [ ]  Explain how sensing supports DCO-IDM tasks
- [ ]  Identify the terrain types requiring sensing coverage
- [ ]  Explain why both friendly and adverse awareness is needed

**If all items are checked, proceed to Section 7.2.**

**If any items remain unchecked, review the relevant subsections before continuing.**

---

## Section 7.2: Core Sensing Capabilities

 **Learning Objective:** Describe the eight core sensing capabilities and their implementing technologies

---

### 7.2.1 Overview of Eight Core Sensing Capabilities

CWP 3-2.1 establishes eight core sensing capabilities that form the foundation of DoD cyberspace sensing.

<aside>
💡

**Key Concept - Eight Core Sensing Capabilities:**

1. Passive Sensing
2. Full Packet Capture
3. Encrypted/Obfuscated Traffic Inspection
4. Security Alerting
5. Asset and Configuration Management Data Collection
6. Endpoint Awareness
7. Application Logging
8. Post-Incident Analysis Data Collection
</aside>

![62bb031c-2e93-4114-b73d-97ac5ae78c7a.png](62bb031c-2e93-4114-b73d-97ac5ae78c7a.png)

---

### 7.2.2 Passive Sensing

Passive Sensing collects network traffic metadata without altering traffic flow.

<aside>
💡

**Key Concept - Passive Sensing:**
Passive Sensing provides bi-directional network traffic data to security platforms, supporting both signature and heuristic-based analysis. Data is provided out-of-band.

</aside>

### What Passive Sensing Provides

| Data Type | Description | Use Case |
| --- | --- | --- |
| **Metadata** | Header information, flow records | Traffic pattern analysis |
| **NetFlow/IPFIX** | Connection summaries | Baseline, anomaly detection |
| **Protocol Analysis** | Protocol behavior | Compliance checking |
| **Timing Data** | When traffic occurred | Correlation, sequencing |

### Implementing Technologies

| Technology | Description | Capabilities |
| --- | --- | --- |
| **Network TAPs** | Physical traffic mirroring | Complete traffic copy |
| **SPAN Ports** | Switch port mirroring | Traffic sampling |
| **NetFlow Collectors** | Flow data aggregation | Zeek, ntopng, SiLK |
| **NIDS** | Network Intrusion Detection | Snort, Suricata, Zeek |
| **Protocol Analyzers** | Deep protocol inspection | Wireshark, tcpdump |

### Deployment Considerations

 *Per CWP 3-2.1:* Passive Sensing provides bi-directional network traffic data at Enterprise Boundary, Regional Boundary, Local Boundary, PIT/ICS/SCADA/SPN Boundaries, and Assigned Terrain.

**Out-of-Band Requirements:**

- Data is provided out-of-band (not through production network)
- Out-of-band storage in network data repository
- Supports real-time and historical analysis

---

### 7.2.3 Full Packet Capture

Full Packet Capture (FPC) records complete network packets including payload content.

<aside>
💡

**Key Concept - Full Packet Capture:**
 *Per CWP 3-2.1:* Full Packet Capture “enable[s] collection of full payload content data for all bi-directional network traffic” and “should be available for retention, inspection and analysis.”

</aside>

### What Full Packet Capture Provides

| Capability | Description | Value |
| --- | --- | --- |
| **Complete Content** | Full packet including payload | Deep inspection |
| **Historical Record** | Stored for later analysis | Forensics, hunting |
| **Session Reconstruction** | Rebuild complete sessions | Attack analysis |
| **Evidence** | Legal/forensic evidence | Incident response |

### Storage Requirements

FPC generates significant data volumes:

| Traffic Rate | Daily Storage | Monthly Storage |
| --- | --- | --- |
| 100 Mbps | ~1 TB | ~30 TB |
| 1 Gbps | ~10 TB | ~300 TB |
| 10 Gbps | ~100 TB | ~3 PB |

 *Per CWP 3-2.1:* FPC “need only provide data on selected traffic content that is identified as informing situational awareness” and “only requires short duration retention to enable immediate inspection” in some objectives.

### Implementing Technologies

| Tool | Description | Features |
| --- | --- | --- |
| **Moloch/Arkime** | Open-source FPC | Indexed, searchable |
| **Zeek** | Network analysis framework | Connection logs, extracted files |
| **tcpdump** | Command-line capture | Lightweight, filtering |
| **Wireshark** | Protocol analyzer | GUI, deep decode |

### On Order Deployment

 *Per CWP 3-2.1:* FPC is frequently deployed “on order” rather than continuously, meaning it is activated when needed for specific operations or investigations.

---

### 7.2.4 Encrypted/Obfuscated Traffic Inspection

This capability enables inspection of traffic that would otherwise be opaque to network sensors.

<aside>
💡

**Key Concept - Encrypted Traffic Inspection:**
 *Per CWP 3-2.1:* “Encrypted/Obfuscated Traffic Inspection capabilities should only be applied to network communications that are not inspected at an EB by Encrypted/Obfuscated Traffic Inspection capabilities.”

</aside>

### The Challenge

Modern networks increasingly use encryption:

- TLS/HTTPS traffic
- VPN tunnels
- SSH sessions
- Application-layer encryption

Without inspection capability, this traffic is invisible to traditional sensors.

### Inspection Methods

| Method | Description | Considerations |
| --- | --- | --- |
| **TLS Interception** | Decrypt/inspect/re-encrypt | Requires trusted certificates |
| **TLS Proxy** | Terminate and re-establish | Performance impact |
| **Metadata Analysis** | JA3/JA3S fingerprinting | No decryption needed |
| **Endpoint Inspection** | Inspect before encryption | Requires endpoint agent |

### Deployment Constraints

⚠️ **Important:** Encrypted traffic inspection does NOT duplicate inspection. If inspected at Enterprise Boundary, do not re-inspect at Regional. Avoid performance degradation from redundant inspection. Document where inspection occurs.

---

### 7.2.5 Security Alerting

Security Alerting provides automated notifications when specific conditions are detected.

<aside>
💡

**Key Concept - Security Alerting:**
 *Per CWP 3-2.1:* “Security Alerting sensing should also be resident… to provide data on the activation of selected automated countermeasures.”

</aside>

### What Security Alerting Provides

| Function | Description | Example |
| --- | --- | --- |
| **Detection** | Identify suspicious activity | IDS alert |
| **Notification** | Inform operators | SIEM dashboard |
| **Correlation** | Link related events | Multi-source analysis |
| **Automation** | Trigger responses | Block, quarantine |

### Implementing Technologies

 *Per CWP 3-2.1 mapping to DCO-IDM Framework:*

| Technology | Category | Function |
| --- | --- | --- |
| **NIPS** | Network | Block malicious traffic |
| **HIPS/Host Firewall** | Host | Block host-level attacks |
| **Firewall** | Network | Perimeter enforcement |
| **Mail Filter** | Application | Email security |
| **Web Proxy** | Application | Web traffic security |
| **SIEM** | Correlation | Aggregate and analyze |

### Alert Management

**Alert Tuning Considerations:**

- False positive reduction
- Alert prioritization
- Threshold adjustment
- Signature optimization

**Alert Fatigue Prevention:**

- Aggregate related alerts
- Implement severity levels
- Automate low-priority handling
- Focus human attention on high-value alerts

---

### 7.2.6 Asset and Configuration Management Data Collection

This capability provides visibility into the state of infrastructure assets.

<aside>
💡

**Key Concept - Asset & Config Management:**
 *Per CWP 3-2.1:* Asset and Configuration Management Data Collection provides “data on the availability and function of enclave hardware and software.”

</aside>

### What This Capability Provides

| Data Type | Description | Value |
| --- | --- | --- |
| **Hardware Inventory** | What devices exist | Asset management |
| **Software Inventory** | What software is installed | Vulnerability management |
| **Configuration State** | Current settings | Compliance checking |
| **Availability Status** | Is it running? | Operational awareness |

### In-Band vs. Out-of-Band

 *Per CWP 3-2.1:* Asset and Configuration Management Data Collection “occurs in-band to provide data on the availability and function of enclave hardware and software.”

However, the data is migrated out-of-band: “this in-band data should be migrated to a network data repository that resides out-of-band.”

---

### 7.2.7 Endpoint Awareness

Endpoint Awareness provides visibility into host behavior.

<aside>
💡

**Key Concept - Endpoint Awareness:**
 *Per CWP 3-2.1:* “Endpoint Awareness sensing capabilities should provide data in-band on endpoint behavior” and “support both signature and heuristic-based determination of required reporting and automated countermeasures activation.”

</aside>

### What Endpoint Awareness Provides

| Data Type | Description | Detection Value |
| --- | --- | --- |
| **Process Activity** | Running processes | Malicious execution |
| **File Operations** | File creates/modifies | Malware installation |
| **Registry Changes** | Config modifications | Persistence mechanisms |
| **Network Connections** | Outbound comms | C2 communication |
| **User Activity** | User actions | Insider threat |

### Implementing Technologies

 *Per CWP 3-2.1 mapping:*

| Technology | Function |
| --- | --- |
| **AV (Antivirus)** | Malware detection |
| **DLP (Data Loss Prevention)** | Data exfiltration detection |
| **HIDS** | Host-based intrusion detection |
| **HIPS/Host Firewall** | Host-based prevention |
| **EDR** | Endpoint Detection & Response |

### Roll-Up Reporting

 *Per CWP 3-2.1:* Endpoint data is collected locally, then “aggregated and analyzed” with results “rolled-up” to an enterprise endpoint data repository.

---

### 7.2.8 Application Logging

Application Logging captures application-level events and behaviors.

<aside>
💡

**Key Concept - Application Logging:**
 *Per CWP 3-2.1:* “Application Logging should provide data in-band on application behavior of specified endpoints.”

</aside>

### What Application Logging Provides

| Log Type | Content | Detection Value |
| --- | --- | --- |
| **Web Server Logs** | HTTP requests | Web attacks, recon |
| **Database Logs** | Queries, access | SQL injection, data theft |
| **Authentication Logs** | Login events | Credential attacks |
| **Transaction Logs** | Business operations | Fraud, abuse |
| **Error Logs** | Application failures | Exploitation attempts |

### On Order Deployment

 *Per CWP 3-2.1:* Application Logging is frequently deployed “on order” for specific endpoints, rather than universally enabled for all applications.

---

### 7.2.9 Post-Incident Analysis Data Collection

This capability supports forensic analysis after security incidents.

<aside>
💡

**Key Concept - Post-Incident Analysis:**
 *Per CWP 3-2.1:* “Post-Incident Analysis Data Collection should also be available to provide out-of-band data on cybersecurity incidents for analysis and correlation with network data repository records.”

</aside>

### What This Capability Provides

| Function | Description | Value |
| --- | --- | --- |
| **Incident Data** | Details of security events | Root cause analysis |
| **Forensic Images** | System snapshots | Evidence preservation |
| **Timeline Data** | Sequence of events | Attack reconstruction |
| **Correlation Data** | Links across sources | Complete picture |

### Forensic Retention Requirements

 *Per CWP 3-2.1:* Data “should be stored, either locally or remotely, in accordance with specified forensic retention requirements.”

---

### 7.2.10 Sensing Capabilities Summary

| Capability | Primary Data | Collection Method | Storage |
| --- | --- | --- | --- |
| **Passive Sensing** | Network metadata | Out-of-band | Network data repo |
| **Full Packet Capture** | Complete packets | Out-of-band | Network data repo |
| **Encrypted Traffic Inspection** | Decrypted content | Out-of-band | Network data repo |
| **Security Alerting** | Alert notifications | Out-of-band | SIEM/data repo |
| **Asset & Config Mgmt** | Infrastructure state | In-band (migrate out) | Data repository |
| **Endpoint Awareness** | Host behavior | In-band (roll-up) | Endpoint data repo |
| **Application Logging** | App events | In-band (migrate out) | Data repository |
| **Post-Incident Analysis** | Forensic data | Out-of-band | Per retention req |

---

### Check Your Understanding - Section 7.2

### Knowledge Check: Eight Capabilities

How many core sensing capabilities does CWP 3-2.1 establish?

1. Five
2. Six
3. **Eight**
4. Ten

<aside>
💡

*CWP 3-2.1 establishes eight core sensing capabilities: Passive Sensing, Full Packet Capture, Encrypted/Obfuscated Traffic Inspection, Security Alerting, Asset and Configuration Management Data Collection, Endpoint Awareness, Application Logging, and Post-Incident Analysis Data Collection.*

</aside>

### Knowledge Check: Passive Sensing vs FPC

What is the difference between Passive Sensing and Full Packet Capture?

1. Passive Sensing is active; FPC is passive
2. FPC collects metadata; Passive Sensing collects content
3. **Passive Sensing collects metadata; FPC records complete packets including payload**
4. There is no difference

<aside>
💡

*Passive Sensing collects network traffic metadata (headers, flow records, protocol analysis) without capturing full content. Full Packet Capture records complete packets including payload content for deep inspection and forensics. Passive Sensing is always-on; FPC is often “on order” due to storage requirements.*

</aside>

### Knowledge Check: Encrypted Traffic Inspection

Why does Encrypted/Obfuscated Traffic Inspection not duplicate inspection at multiple boundaries?

1. It is not technically possible
2. Only Enterprise Boundaries have this capability
3. **Duplicate inspection causes performance degradation and wastes resources**
4. Regional Boundaries cannot decrypt traffic

<aside>
💡

*Per CWP 3-2.1, encrypted traffic inspection is applied only to communications “not inspected at an EB by Encrypted/Obfuscated Traffic Inspection capabilities.” Duplicate inspection causes performance degradation, wastes computational resources, provides no additional security benefit, and complicates certificate management.*

</aside>

### Knowledge Check: Security Alerting Technologies

Which technologies provide Security Alerting per CWP 3-2.1? (Select all that apply)

1. **NIPS**
2. **SIEM**
3. Network TAP
4. **Firewall**

<aside>
💡

*Technologies providing Security Alerting per CWP 3-2.1 include NIPS (Network Intrusion Prevention System), HIPS/Host Firewall, Firewall, Mail Filter, Web Proxy/Web Content Filtering, SIEM (correlation engine), and Peak Flow Analysis. Network TAPs provide Passive Sensing and Full Packet Capture, not Security Alerting.*

</aside>

### Knowledge Check: In-Band vs Out-of-Band

Which statement correctly describes in-band and out-of-band data collection?

1. All sensing capabilities use out-of-band collection
2. In-band collection is more secure than out-of-band
3. **In-band collection occurs through production network; out-of-band uses separate channels**
4. Out-of-band collection requires endpoint agents

<aside>
💡

*In-band collection occurs through the production network and is used by Asset & Config Management, Endpoint Awareness, and Application Logging. Out-of-band collection occurs through separate network/channel, not affecting production, and is used by Passive Sensing, Full Packet Capture, Encrypted Traffic Inspection, Security Alerting, and Post-Incident Analysis. In-band data is migrated out-of-band for storage and analysis.*

</aside>

### Knowledge Check: Roll-Up Reporting

What does “roll-up reporting” mean for Endpoint Awareness?

1. Reports are summarized and shortened
2. Endpoint data is encrypted before transmission
3. **Endpoint agents collect data locally, then aggregate and report to an enterprise repository**
4. Reports roll up from analysts to commanders

<aside>
💡

*Roll-up reporting means endpoint agents collect data locally, then aggregate and report that data up to an enterprise endpoint data repository. This reduces network overhead, centralizes endpoint data, enables enterprise-wide analysis, and supports real-time visualization.*

</aside>

### Knowledge Check: Application Logging Deployment

When is Application Logging typically deployed—continuously or “on order”?

1. Always continuously
2. **“On order” for specified endpoints**
3. Only during incidents
4. Only at Enterprise Boundaries

<aside>
💡

*Per CWP 3-2.1, Application Logging is typically deployed “on order” for specified endpoints rather than continuously for all applications. This conserves resources and focuses logging where needed.*

</aside>

### Knowledge Check: Post-Incident Analysis Purpose

What is the purpose of Post-Incident Analysis Data Collection?

1. To prevent future incidents
2. To automate incident response
3. **To provide data for analysis and correlation with network repository records after incidents**
4. To replace forensic tools

<aside>
💡

*Per CWP 3-2.1, Post-Incident Analysis Data Collection provides “out-of-band data on cybersecurity incidents for analysis and correlation with network data repository records.” It supports root cause analysis, attack reconstruction, evidence preservation, and correlation across sources.*

</aside>

---

### Progress Checkpoint - Section 7.2

Before proceeding to Section 7.3, verify the ability to accomplish the following:

- [ ]  List all eight core sensing capabilities
- [ ]  Explain what data each capability collects
- [ ]  Identify implementing technologies for each capability
- [ ]  Distinguish between in-band and out-of-band collection
- [ ]  Explain when “on order” deployment is appropriate
- [ ]  Describe roll-up reporting for endpoint data
- [ ]  Map capabilities to detection scenarios

**If all items are checked, proceed to Section 7.3.**

**If any items remain unchecked, review the relevant subsections before continuing.**

---

## Section 7.3: Sensing Goals and Objectives

 **Learning Objective:** Explain the three sensing goals and nine supporting objectives per CWP 3-2.1

---

### 7.3.1 Overview of Sensing Goals

CWP 3-2.1 establishes three overarching goals for sensing capabilities.

<aside>
💡

**Key Concept - Three Sensing Goals:**
 *Per CWP 3-2.1:*

- **Goal 1:** Enhance protection of DOD cyberspace terrain
- **Goal 2:** Enhance real-time situational awareness
- **Goal 3:** Enhance threat-specific defensive operations
</aside>

Each goal is supported by three objectives, creating nine total objectives.

![4a3b7848-904c-4423-b29d-92999c089334.png](4a3b7848-904c-4423-b29d-92999c089334.png)

---

### 7.3.2 Goal 1: Enhance Protection of DOD Cyberspace Terrain

 *Per CWP 3-2.1:* “Protection is defined in reference (a), JP 3-0, as a joint function with a focus on preserving the joint force’s fighting potential.”

### Objective 1.1: Enable Enhanced Defense-in-Depth

**Purpose:** Facilitate automated countermeasures at designated network boundaries.

 *Per CWP 3-2.1:* “Given the increasing volume and sophistication of attempted intrusions against DOD cyberspace, a multi-tiered multifaceted defensive approach that maximizes automation of countermeasures is essential.”

**Key Points:**

- Single defensive boundary is certain to fail against persistent adversaries
- Multiple countermeasure technologies at designated boundaries
- Automation enables rapid response to new intrusion techniques
- Preserves human resources for advanced threats

⚠️ **Important:** Adequate measures must prevent adversary manipulation of automated systems (conflicting rules, excessive rules, resource exhaustion).

### Objective 1.2: Enable Host-Based Automated Reporting and Response

**Purpose:** Extend defense-in-depth to endpoint protection.

 *Per CWP 3-2.1:* “Protection of endpoints is a necessary element of defense in depth. As with network boundary protection, automation of endpoint countermeasures enables rapid response to previously unidentified intrusion techniques.”

**Key Points:**

- Network boundaries alone are insufficient
- Persistent adversaries will bypass boundary defenses
- Endpoints need self-protection capability
- “Hosts” = endpoints with sufficient computing resources for self-protection

### Objective 1.3: Enable Development of Improved Indicators and Analytics

**Purpose:** Support continuous improvement of detection capabilities.

 *Per CWP 3-2.1:* “In the face of ever increasing and evolving cyberspace threats, attaining the situational awareness required for effective protection necessitates continuous development and improvement of indicators and analytics.”

**Key Definitions:**

| Term | Definition |
| --- | --- |
| **Indicator** | “A discrete occurrence of an event or data that highlights potential adversary activity or an adverse condition” |
| **Analytics** | “Procedures and logic that are applied against data sets, often collected over a period of time, to identify subtle and/or persistent adversary or adverse activity” |

---

### 7.3.3 Goal 2: Enhance Real-Time Situational Awareness

 *Per CWP 3-2.1:* Goal 2 focuses on providing decision-makers with timely, accurate information about the state of DoD cyberspace.

### Objective 2.1: Enable Real-Time Query at Any Operational Level

**Purpose:** Allow any authorized operator to query sensing data in real-time.

**Key Points:**

- Supports tactical through strategic levels
- Enables immediate access to current data
- Supports both general and specific queries

### Objective 2.2: Enable Analysis of Aggregated Sensing Data

**Purpose:** Support centralized analysis of data from multiple sources.

 *Per CWP 3-2.1:* Analysis “at the lowest practical level increases the volume of data analyzed, the frequency with which the data is analyzed, and the number of individuals examining the analysis results. These effects improve the likelihood of detection of adverse activity.”

**Key Points:**

- Aggregate data from all sensing capabilities
- Enable correlation across sources
- Apply advanced analytical techniques
- Federate analysis for broader coverage

### Objective 2.3: Enable Agile Maneuver in Cyberspace

**Purpose:** Support rapid defensive response to emerging situations.

**Key Points:**

- Enable rapid reposition of defensive capabilities
- Support dynamic response to adversary actions
- Maintain initiative in defensive operations

---

### 7.3.4 Goal 3: Enhance Threat-Specific Defensive Operations

 *Per CWP 3-2.1:* “The dynamic and complex nature of cyberspace often results in the inability of deployed sensing capabilities to provide awareness of new or highly sophisticated threats. Insight into such threats is generally provided via two sources, intelligence and incidents.”

**Threat Intelligence Flow:**

- **Proactive:** Intelligence provides threat-specific information enabling focused defensive action
- **Reactive:** Adversary success generates incidents requiring expulsion and restoration

### Objective 3.1: Enable Remote and Dynamic Reconfiguration

**Purpose:** Allow tailored collection based on threat-specific indicators.

 *Per CWP 3-2.1:* “If threat-specific indicators are available, mission objectives may require tailored collection or handling of data already collected by in-place sensing capabilities.”

**Key Points:**

- Reconfigure existing sensors without physical access
- Adjust collection parameters dynamically
- Apply threat-specific signatures/indicators
- Reconfiguration is out-of-band (except Asset & Config Mgmt)

### Objective 3.2: Enable Activation/Deployment of Additional Sensing

**Purpose:** Augment sensing when in-place capabilities are insufficient.

 *Per CWP 3-2.1:* “Threat-specific cyberspace operations frequently require collection of unique or additional data beyond what is normally collected by in-place sensing capabilities.”

**Key Points:**

- Activate dormant capabilities
- Deploy additional sensors (fly-away kits)
- Enhance existing collection depth/breadth
- Ensure timely data migration to designated repository

### Objective 3.3: Enable Advanced Forensic Analysis

**Purpose:** Support detailed post-compromise investigation.

 *Per CWP 3-2.1:* “Following a compromise, determination of an adversary’s level of access on a targeted system and how the system was manipulated is critical.”

**Key Points:**

- Determine adversary level of access
- Reconstruct adversary activities over time
- Support advanced forensic techniques
- Store data per forensic retention requirements

---

### 7.3.5 Goals and Objectives Summary Table

| Goal | Objective | Primary Purpose |
| --- | --- | --- |
| **Goal 1** | 1.1 | Automated countermeasures at boundaries |
|  | 1.2 | Host-based automated response |
|  | 1.3 | Indicator and analytics development |
| **Goal 2** | 2.1 | Real-time query capability |
|  | 2.2 | Aggregated data analysis |
|  | 2.3 | Agile defensive maneuver |
| **Goal 3** | 3.1 | Remote/dynamic reconfiguration |
|  | 3.2 | Additional sensing activation |
|  | 3.3 | Advanced forensic analysis |

---

### Check Your Understanding - Section 7.3

### Knowledge Check: Three Sensing Goals

What are the three sensing goals per CWP 3-2.1?

1. Detect, Prevent, Respond
2. **Enhance protection, enhance situational awareness, enhance threat-specific operations**
3. Identify, Protect, Recover
4. Monitor, Analyze, Report

<aside>
💡

*The three sensing goals per CWP 3-2.1 are: Goal 1 - Enhance protection of DOD cyberspace terrain; Goal 2 - Enhance real-time situational awareness; Goal 3 - Enhance threat-specific defensive operations. Each goal is supported by three objectives, creating nine total objectives.*

</aside>

### Knowledge Check: Objective 1.1 Rationale

What is the rationale for Objective 1.1 (automated countermeasures)?

1. To reduce staffing requirements
2. To eliminate human error
3. **A single defensive boundary is certain to fail; automation enables rapid response to new intrusion techniques**
4. To simplify network architecture

<aside>
💡

*Per CWP 3-2.1, the rationale for Objective 1.1 includes: increasing volume and sophistication of intrusion attempts, single defensive boundary is certain to fail against persistent adversaries, multi-tiered multifaceted defense requires automation, automation enables rapid response to new techniques, and preserves human resources for advanced threats.*

</aside>

### Knowledge Check: Indicator vs Analytics

How does CWP 3-2.1 define “indicator” versus “analytics”?

1. Indicators are automated; analytics are manual
2. **Indicators are discrete events; analytics are procedures applied over time to identify subtle activity**
3. Indicators detect known threats; analytics detect unknown threats
4. Indicators are network-based; analytics are host-based

<aside>
💡

*Per CWP 3-2.1, an Indicator is “a discrete occurrence of an event or data that highlights potential adversary activity or an adverse condition.” Analytics are “procedures and logic that are applied against data sets, often collected over a period of time, to identify subtle and/or persistent adversary or adverse activity.”*

</aside>

### Knowledge Check: Lowest Practical Level

Why does Objective 2.2 recommend data analysis at “the lowest practical level”?

1. To reduce network traffic
2. To minimize storage requirements
3. **To increase volume analyzed, frequency of analysis, and number of individuals examining results**
4. To simplify reporting

<aside>
💡

*Per CWP 3-2.1, analyzing at the lowest practical level increases the volume of data analyzed, increases the analysis frequency, and increases the number of individuals examining results. These effects improve likelihood of detecting adverse activity.*

</aside>

### Knowledge Check: Threat Intelligence Sources

What two sources provide insight into new or sophisticated threats per Goal 3?

1. Sensors and analytics
2. **Intelligence and incidents**
3. Vendors and researchers
4. SIEM and EDR

<aside>
💡

*Per CWP 3-2.1, two sources provide threat insight: Intelligence (provides threat-specific information enabling proactive, focused defensive action) and Incidents (adversary success generates incidents requiring reactive operations including expulsion and restoration).*

</aside>

### Knowledge Check: On Order Meaning

What does “on order” mean for sensing capability deployment?

1. Capabilities are ordered from vendors
2. Capabilities require commander approval to use
3. **Capabilities are activated when needed rather than continuously**
4. Capabilities are deployed in a specific sequence

<aside>
💡

*“On order” means the capability is not continuously active but is activated when needed for specific operations, investigations, or when directed by commanders. This conserves resources (especially storage for FPC) and focuses collection where most needed.*

</aside>

### Knowledge Check: Out-of-Band Reconfiguration

Why is sensing reconfiguration (Objective 3.1) performed out-of-band?

1. To increase reconfiguration speed
2. **To prevent adversaries from detecting reconfiguration activity**
3. To reduce bandwidth consumption
4. To simplify network architecture

<aside>
💡

*Reconfiguration is out-of-band to prevent adversaries from detecting reconfiguration activity, avoid tipping off adversaries to defensive changes, protect management traffic from compromise, and ensure reconfiguration succeeds even if production network is compromised.*

</aside>

### Knowledge Check: Forensic Analysis Objective

Which objective specifically supports post-compromise investigation?

1. Objective 1.3
2. Objective 2.2
3. Objective 3.1
4. **Objective 3.3**

<aside>
💡

*Objective 3.3: Enable advanced forensic analysis specifically supports post-compromise investigation. It enables determination of adversary access level and reconstruction of adversary activities over time.*

</aside>

---

### Progress Checkpoint - Section 7.3

Before proceeding to Section 7.4, verify the ability to accomplish the following:

- [ ]  State the three sensing goals
- [ ]  Explain the three objectives under each goal
- [ ]  Define “indicator” and “analytics” per doctrine
- [ ]  Explain the rationale for defense-in-depth automation
- [ ]  Describe how sensing supports threat-specific operations
- [ ]  Explain “on order” vs. continuous deployment
- [ ]  Identify which objectives support which defensive needs

**If all items are checked, proceed to Section 7.4.**

**If any items remain unchecked, review the relevant subsections before continuing.**

---

## Section 7.4: Sensing Deployment by Boundary Type

 **Learning Objective:** Identify sensing requirements for each boundary type per CWP 3-2.1

---

### 7.4.1 Boundary Types Overview

CWP 3-2.1 defines sensing requirements for each boundary type within the defense-in-depth architecture.

<aside>
💡

**Key Concept - Boundary Types:**
Per CWP 3-2.1, sensing requirements are defined for Enterprise Boundary (EB), Regional Boundary (RB), Local Boundary (LB), Network Endpoints, PIT/ICS/SCADA/SPN Boundaries, and Assigned Terrain.

</aside>

![243cab4e-06df-436d-b061-eb6dd17d8634.png](243cab4e-06df-436d-b061-eb6dd17d8634.png)

---

### 7.4.2 Enterprise Boundary Sensing Requirements

The Enterprise Boundary is the outermost defensive perimeter, typically managed by DISA.

 *Per CWP 3-2.1:* Enterprise Boundary sensing provides the most comprehensive capability set.

### Key EB Sensing Characteristics

 *Per CWP 3-2.1:*

- “Passive Sensing, Full Packet Capture and Encrypted/Obfuscated Traffic Inspection capabilities should provide bi-directional network traffic data”
- Data “should be provided out-of-band and support both signature and heuristic-based security platforms”
- “Security Alerting sensing should also be resident at the EB to provide data on the activation of selected automated countermeasures”

**Required Capabilities:**

- Passive Sensing (all objectives)
- Full Packet Capture (continuous and on order)
- Encrypted/Obfuscated Traffic Inspection
- Security Alerting
- Post-Incident Analysis Data Collection
- Asset & Config Management (Objectives 3.2, 3.3 only)

---

### 7.4.3 Regional Boundary Sensing Requirements

Regional Boundaries aggregate multiple local enclaves, typically managed by Services or CCMDs.

### Key RB Sensing Characteristics

 *Per CWP 3-2.1:*

- “Encrypted/Obfuscated Traffic Inspection capabilities should only be applied to network communications that are not inspected at an EB by Encrypted/Obfuscated Traffic Inspection capabilities”
- Avoids duplicate decryption/inspection overhead
- “Security Alerting sensing should enable individual security platforms to provide out-of-band data to inform the analytic logic of other security platforms”

**Required Capabilities:** Same as EB, except encrypted traffic inspection only applies to traffic not already inspected at EB.

---

### 7.4.4 Local Boundary Sensing Requirements

Local Boundaries protect individual enclaves/installations.

### Key LB Sensing Characteristics

 *Per CWP 3-2.1:*

- No Encrypted Traffic Inspection (done at EB/RB)
- “Asset and Configuration Management Data Collection which occurs in-band to provide data on the availability and function of enclave hardware and software”
- “This data is utilized by LB security platforms for automated countermeasure activation”

**Required Capabilities:**

- Passive Sensing
- Full Packet Capture (on order for most objectives)
- Security Alerting
- Asset & Configuration Management Data Collection
- Post-Incident Analysis Data Collection
- NO Encrypted Traffic Inspection

---

### 7.4.5 Endpoint Sensing Requirements

Endpoints are the hosts within enclaves that have sufficient computing resources for self-protection.

### Key Endpoint Sensing Characteristics

 *Per CWP 3-2.1:*

- Primary capability is **Endpoint Awareness**
- “Endpoint Awareness sensing capabilities should provide data in-band on endpoint behavior”
- Supports “both signature and heuristic-based determination of required reporting and automated countermeasures activation”
- Application Logging available “on order”

**Required Capabilities:**

- Endpoint Awareness (primary capability)
- Application Logging (on order/selective)
- Post-Incident Analysis Data Collection

---

### 7.4.6 PIT/ICS/SCADA/SPN Boundary Sensing Requirements

These boundaries protect specialized systems with unique operational requirements.

### Key PIT/ICS/SCADA Characteristics

 *Per CWP 3-2.1:*

- “Passive Sensing capabilities should identify deviations from specified traffic formats and standards”
- Uses **whitelist-based comparison** rather than signature-based detection
- “Asset and Configuration Management Data Collection should provide information on hardware connections and software execution”

**Required Capabilities:**

- Passive Sensing (whitelist-focused)
- Security Alerting
- Asset & Configuration Management Data Collection
- Full Packet Capture (Objectives 3.2, 3.3 only)
- Encrypted Traffic Inspection (Objective 3.2 only)

---

### 7.4.7 Assigned Terrain Sensing Requirements

Assigned Terrain is cyberspace external to DoD boundaries that DoD is ordered to defend.

### Key Assigned Terrain Characteristics

 *Per CWP 3-2.1:*

- “Passive Sensing capabilities should provide bi-directional network traffic data from identified locations”
- Supports “general and critical asset-specific situational awareness”
- Requires deployable/fly-away sensing capabilities

**Required Capabilities:**

- Passive Sensing (deployable)
- Full Packet Capture (Objectives 3.2, 3.3 only)
- Limited to network-based sensing (no host-based)

---

### 7.4.8 Sensing Deployment Summary

![9ec37b7e-7174-4cde-9404-405e01f05680.png](9ec37b7e-7174-4cde-9404-405e01f05680.png)

---

### Check Your Understanding - Section 7.4

### Knowledge Check: Encrypted Traffic Inspection Boundaries

At which boundary types is Encrypted/Obfuscated Traffic Inspection required?

1. All boundary types
2. Only Enterprise Boundary
3. **Enterprise Boundary and Regional Boundary (only if not done at EB)**
4. Local Boundary and Endpoints

<aside>
💡

*Encrypted/Obfuscated Traffic Inspection is required at Enterprise Boundary (full inspection) and Regional Boundary (only for traffic not inspected at EB). PIT/ICS/SCADA/SPN Boundary has it only for Objective 3.2 (additional sensing). Local Boundaries and Endpoints do not require it.*

</aside>

### Knowledge Check: Local Boundary No Encrypted Inspection

Why does the Local Boundary NOT require Encrypted Traffic Inspection?

1. Local Boundaries cannot decrypt traffic
2. Local Boundary traffic is not encrypted
3. **Traffic has already been inspected at the EB or RB**
4. Local Boundaries use whitelist-based detection instead

<aside>
💡

*Local Boundary does not require Encrypted Traffic Inspection because traffic has already been inspected at the EB or RB. Duplicate inspection wastes resources and adds latency. Per CWP 3-2.1, inspection “should only be applied to network communications that are not inspected at an EB.”*

</aside>

### Knowledge Check: Endpoint Primary Capability

What is the primary sensing capability for Network Endpoints?

1. Passive Sensing
2. Security Alerting
3. **Endpoint Awareness**
4. Full Packet Capture

<aside>
💡

*The primary sensing capability for Network Endpoints is Endpoint Awareness. It provides data on endpoint behavior and supports both signature and heuristic-based automated countermeasures. Application Logging is available “on order.”*

</aside>

### Knowledge Check: PIT/ICS Detection Method

What type of comparison does PIT/ICS/SCADA boundary sensing support?

1. Signature-based comparison
2. Anomaly-based comparison
3. **Whitelist-based comparison**
4. Heuristic-based comparison

<aside>
💡

*Per CWP 3-2.1, PIT/ICS/SCADA boundary sensing supports whitelist comparisons. The sensing identifies “deviations from specified traffic formats and standards” rather than looking for known-bad signatures. This is appropriate because these systems have predictable, defined traffic patterns.*

</aside>

### Knowledge Check: Universal Sensing Capability

Which sensing capability is required at ALL boundary types?

1. Full Packet Capture
2. Security Alerting
3. **Passive Sensing**
4. Endpoint Awareness

<aside>
💡

*Passive Sensing is required at all boundary types: Enterprise, Regional, Local Boundaries; PIT/ICS/SCADA/SPN Boundaries; and Assigned Terrain. It provides the foundational network traffic data for all defensive operations.*

</aside>

### Knowledge Check: Assigned Terrain Uniqueness

What makes Assigned Terrain sensing requirements unique?

1. It requires all eight sensing capabilities
2. It uses only host-based sensing
3. **It is external to DoD boundaries and requires deployable capabilities**
4. It has no FPC requirement

<aside>
💡

*Assigned Terrain sensing is unique because it is external to DoD network boundaries, DoD is ordered to defend it (not organic terrain), it requires deployable/fly-away sensing capabilities, it is limited to Passive Sensing and Full Packet Capture, and has no host-based sensing capabilities.*

</aside>

### Knowledge Check: Asset & Config Collection Method

Where does Asset and Configuration Management Data Collection occur for Local Boundaries?

1. Out-of-band only
2. Through endpoint agents only
3. **In-band, then migrated to out-of-band repository**
4. At the Enterprise Boundary

<aside>
💡

*Per CWP 3-2.1, Asset and Configuration Management Data Collection for Local Boundaries “occurs in-band to provide data on the availability and function of enclave hardware and software.” However, this data is then migrated to an out-of-band repository for storage and analysis.*

</aside>

### Knowledge Check: FPC On Order Deployment

At what boundaries is Full Packet Capture often deployed “on order” rather than continuously?

1. Only at Assigned Terrain
2. Only at Enterprise Boundary
3. **Enterprise, Regional, and Local Boundaries (for various objectives)**
4. FPC is always deployed continuously

<aside>
💡

*Full Packet Capture is often “on order” at Enterprise Boundary (for Objectives 1.3, 2.1), Regional Boundary (for Objectives 1.3, 2.1), and Local Boundary (for most objectives). This is due to storage requirements; FPC generates significant data volume.*

</aside>

---

### Progress Checkpoint - Section 7.4

Before proceeding to Section 7.5, verify the ability to accomplish the following:

- [ ]  Identify the six boundary types in CWP 3-2.1
- [ ]  Describe sensing requirements for each boundary type
- [ ]  Explain why Encrypted Traffic Inspection varies by boundary
- [ ]  Identify which capabilities are boundary-specific
- [ ]  Explain whitelist-based sensing for PIT/ICS/SCADA
- [ ]  Describe Assigned Terrain sensing requirements

**If all items are checked, proceed to Section 7.5.**

**If any items remain unchecked, review the relevant subsections before continuing.**

---

## Section 7.5: Indicators and Analytics Development

 **Learning Objective:** Differentiate between indicators and analytics and support development efforts

---

### 7.5.1 Indicators vs. Analytics

Understanding the distinction between indicators and analytics is essential for effective cyber defense.

<aside>
💡

**Key Concept - Indicators and Analytics:**
 *Per CWP 3-2.1:*

- **Indicator:** “A discrete occurrence of an event or data that highlights potential adversary activity or an adverse condition created by friendly forces or systems”
- **Analytics:** “Procedures and logic that are applied against data sets, often collected over a period of time, to identify subtle and/or persistent adversary or adverse activity”
</aside>

### Comparison

| Aspect | Indicators | Analytics |
| --- | --- | --- |
| **Nature** | Discrete event or data point | Procedures and logic |
| **Scope** | Single occurrence | Data sets over time |
| **Detection** | Specific, known activity | Subtle, persistent activity |
| **Example** | Known malware hash | Beaconing pattern detection |
| **Update** | When new IOCs identified | When new TTPs understood |

![8476f6b5-d31b-4529-ba2c-b48514ab82d1.png](8476f6b5-d31b-4529-ba2c-b48514ab82d1.png)

---

### 7.5.2 Types of Indicators

### Indicator Categories

| Category | Examples | Source |
| --- | --- | --- |
| **Network** | IP addresses, domains, URLs | Threat intel, incidents |
| **Host** | File hashes, file names, paths | Malware analysis |
| **Email** | Sender addresses, subjects | Phishing campaigns |
| **Behavioral** | Process names, registry keys | Attack analysis |

### Indicator Formats

| Format | Description | Use |
| --- | --- | --- |
| **STIX** | Structured Threat Information Expression | Standardized sharing |
| **TAXII** | Trusted Automated Exchange | Transport protocol |
| **OpenIOC** | Mandiant/FireEye format | Detection rules |
| **YARA** | Pattern matching rules | File/memory scanning |
| **Sigma** | Generic signature format | SIEM rules |
| **Snort/Suricata** | Network signatures | IDS/IPS rules |

### Indicator Lifecycle

![image.png](image%206.png)

---

### 7.5.3 Types of Analytics

### Analytic Categories

| Category | Description | Example |
| --- | --- | --- |
| **Statistical** | Mathematical analysis | Baseline deviation |
| **Behavioral** | Pattern recognition | User behavior analytics |
| **Machine Learning** | Automated pattern discovery | Anomaly detection |
| **Rule-based** | Logical conditions | SIEM correlation rules |

### Analytic Examples

**Beaconing Detection:**

- Analyze outbound connections over time
- Identify regular intervals (C2 heartbeat)
- Flag connections with consistent timing

**Data Exfiltration:**

- Baseline normal outbound data volumes
- Detect anomalous large transfers
- Identify unusual destinations

**Lateral Movement:**

- Track authentication across systems
- Identify unusual access patterns
- Detect credential reuse

---

### 7.5.4 Manual Development Methods

 *Per CWP 3-2.1:* Sensing data must “enable manual development efforts” for indicators and analytics.

### Indicator Development Process

1. **Collection** - Gather IOCs from threat intelligence, extract from incidents, obtain from sharing partners
2. **Analysis** - Validate accuracy, assess relevance to environment, determine detection method
3. **Documentation** - Record in standard format, include context and confidence, note expiration/review date
4. **Implementation** - Create detection rules, deploy to appropriate sensors, configure alerting
5. **Validation** - Test detection capability, tune for false positives, verify operational effectiveness

---

### 7.5.5 AI/ML Application to Sensing Data

 *Per CWP 3-2.1:* Sensing data must “enable manual development efforts as well as the application of artificial intelligence/machine learning methods.”

### Machine Learning Applications

| Application | ML Approach | Use Case |
| --- | --- | --- |
| **Anomaly Detection** | Unsupervised learning | Identify unusual patterns |
| **Malware Classification** | Supervised learning | Categorize malware families |
| **User Behavior** | Behavioral modeling | Insider threat detection |
| **Network Traffic** | Clustering | Identify traffic types |

### Considerations for ML in Security

**Advantages:**

- Can detect unknown threats
- Scales to large data volumes
- Adapts to changing patterns
- Reduces manual analysis burden

**Challenges:**

- Requires quality training data
- May produce false positives
- Adversaries can evade/poison
- “Black box” decision making

---

### 7.5.6 Data Repositories and Out-of-Band Storage

 *Per CWP 3-2.1:* Sensing data is stored in “out-of-band network data repositories” that support indicator and analytics development.

### Repository Requirements

| Requirement | Purpose |
| --- | --- |
| **Out-of-Band** | Protect data from compromise |
| **Scalable** | Handle large data volumes |
| **Queryable** | Enable analysis and search |
| **Standardized** | Support common formats |
| **Correlated** | Link data across sources |
| **Retained** | Meet forensic requirements |

---

### 7.5.7 Supporting CPT and CSSP Operations

Cyber Defense Infrastructure Support Specialists support Cyber Protection Teams (CPTs) and Cybersecurity Service Providers (CSSPs) in their indicator and analytics development work.

### Support Functions

| Function | How Infrastructure Specialists Support |
| --- | --- |
| **Sensor Deployment** | Install, configure, maintain sensing infrastructure |
| **Data Collection** | Ensure required data is being captured |
| **Data Access** | Provide access to stored sensing data |
| **Signature Updates** | Coordinate rule and signature deployment |
| **Tuning** | Adjust sensors to reduce false positives |
| **Capacity** | Ensure storage and processing capacity |

### Coordination with Analysts

 *Per KSAT T0471:* “Coordinate with Cyber Defense Analysts to manage and administer the updating of rules and signatures (e.g., intrusion detection/protection systems, anti-virus, and content blacklists) for specialized cyber defense applications.”

**Coordination Activities:**

- Receive indicator updates from analysts
- Test signatures before deployment
- Deploy to production sensors
- Monitor for issues
- Report detection statistics
- Identify data gaps

---

### Check Your Understanding - Section 7.5

### Knowledge Check: Indicator vs Analytics Definition

What is the key difference between indicators and analytics per CWP 3-2.1?

1. Indicators are manual; analytics are automated
2. **Indicators are discrete events; analytics are procedures applied over time**
3. Indicators are host-based; analytics are network-based
4. Indicators detect known threats; analytics prevent threats

<aside>
💡

*Per CWP 3-2.1, an Indicator is “a discrete occurrence of an event or data” while Analytics are “procedures and logic applied against data sets, often collected over a period of time.” The key difference is that indicators are point-in-time matches against specific data; analytics are patterns/logic applied over time to identify subtle activity.*

</aside>

### Knowledge Check: Indicator Formats

Which are valid indicator formats used in cyber defense? (Select all that apply)

1. **STIX**
2. **YARA**
3. **Snort/Suricata**
4. NetFlow

<aside>
💡

*Valid indicator formats include STIX (Structured Threat Information Expression), YARA (pattern matching rules), Snort/Suricata (network signatures), OpenIOC, and Sigma. NetFlow is a data collection format, not an indicator format.*

</aside>

### Knowledge Check: Indicator Lifecycle

What are the stages of the indicator lifecycle?

1. Create, Test, Deploy, Delete
2. Collect, Analyze, Store, Report
3. **Discovery, Validation, Deployment, Retirement**
4. Identify, Classify, Distribute, Archive

<aside>
💡

*The indicator lifecycle stages are: Discovery (found through intel, incidents, hunting), Validation (confirmed as malicious, tested for accuracy), Deployment (pushed to sensors, SIEM, endpoints), and Retirement (no longer relevant when adversary changes).*

</aside>

### Knowledge Check: ML Advantages and Challenges

What are advantages AND challenges of using ML for security analytics?

1. Advantages: speed, accuracy; Challenges: cost, complexity
2. **Advantages: detect unknown threats, scale to large data; Challenges: requires quality training data, false positives**
3. Advantages: eliminates human error; Challenges: cannot detect known threats
4. Advantages: simple to implement; Challenges: slow performance

<aside>
💡

*Advantages of ML include: can detect unknown threats, scales to large data volumes, adapts to changing patterns, reduces manual analysis burden. Challenges include: requires quality training data, may produce false positives, adversaries can evade/poison, and “black box” decision making.*

</aside>

### Knowledge Check: Out-of-Band Storage

Why is sensing data stored in out-of-band repositories?

1. To increase query speed
2. To reduce storage costs
3. **To protect data from compromise if the production network is breached**
4. To simplify data management

<aside>
💡

*Out-of-band storage protects data from compromise (if production network breached), separates management from production traffic, ensures data availability for analysis, and supports forensic retention requirements.*

</aside>

### Knowledge Check: Infrastructure Specialist Role

What role does the Cyber Defense Infrastructure Support Specialist play in indicator development?

1. Creates and validates all indicators
2. Analyzes threat intelligence
3. **Deploys sensors, coordinates signature updates, and ensures data is captured**
4. Develops machine learning models

<aside>
💡

*The Cyber Defense Infrastructure Support Specialist deploys and configures sensing infrastructure, ensures required data is being captured, coordinates signature/rule updates with analysts, tests signatures before production deployment, tunes sensors to reduce false positives, and maintains storage and processing capacity.*

</aside>

### Knowledge Check: CWP 3-2.1 on AI/ML

What does CWP 3-2.1 say about AI/ML application to sensing data?

1. AI/ML is not recommended for sensing
2. AI/ML should replace manual analysis
3. **Sensing data must enable both manual development and AI/ML methods**
4. AI/ML is required at all boundaries

<aside>
💡

*Per CWP 3-2.1, sensing data must “enable manual development efforts as well as the application of artificial intelligence/machine learning methods.” This means data must be collected and stored in ways that support both human analysis and automated ML processing.*

</aside>

### Knowledge Check: Analytics Types

What are three types of analytics used in cyber defense?

1. Basic, intermediate, advanced
2. **Statistical, behavioral, machine learning**
3. Network, host, application
4. Real-time, historical, predictive

<aside>
💡

*Three types of analytics used in cyber defense are: Statistical (baseline deviation, mathematical analysis), Behavioral (user/entity behavior, pattern recognition), Machine Learning (anomaly detection, classification), and Rule-based (SIEM correlation rules).*

</aside>

---

### Progress Checkpoint - Section 7.5

Before proceeding to the Lesson Lab, verify the ability to accomplish the following:

- [ ]  Define “indicator” and “analytics” per CWP 3-2.1
- [ ]  Identify common indicator formats
- [ ]  Describe the indicator lifecycle
- [ ]  Explain how ML applies to sensing data
- [ ]  Describe out-of-band repository requirements
- [ ]  Explain the Infrastructure Specialist’s role in indicator development

**If all items are checked, proceed to the Lesson Lab.**

**If any items remain unchecked, review the relevant subsections before continuing.**

---

## Conclusion

This lesson established the doctrinal foundation for cyberspace sensing essential for Cyber Defense Infrastructure Support Specialists deploying and configuring detection capabilities in DoD environments. This knowledge enables effective implementation of sensing per CWP 3-2.1 requirements and support for indicator and analytics development efforts.

### Key Takeaways

**Introduction to Cyberspace Sensing**
Sensing provides the data needed to gain and maintain situational awareness of DoD cyberspace. Awareness of friendly activity alone is insufficient—dedicated sensing capabilities are required to detect adverse activity that adversaries attempt to hide. Sensing (capability) and sensors (tools) are distinct; a single sensor may provide multiple capabilities, and a single capability may require multiple sensors. Sensing supports three NIST framework tasks: Protect, Detect, and Respond. Sensing coverage extends to all DoD terrain including DODIN, PIT, ICS/SCADA, SPN, and Assigned Terrain.

**Core Sensing Capabilities**
CWP 3-2.1 establishes eight core sensing capabilities: Passive Sensing, Full Packet Capture, Encrypted/Obfuscated Traffic Inspection, Security Alerting, Asset and Configuration Management Data Collection, Endpoint Awareness, Application Logging, and Post-Incident Analysis Data Collection. Network-focused capabilities (Passive Sensing, FPC, Encrypted Traffic Inspection) provide out-of-band data. Host-focused capabilities (Endpoint Awareness, Application Logging) use in-band collection with roll-up reporting. “On order” deployment conserves resources for storage-intensive capabilities like FPC and Application Logging.

**Sensing Goals and Objectives**
Three sensing goals structure nine objectives: Goal 1 (Enhance Protection) includes automated countermeasures at boundaries, host-based response, and indicator/analytics development. Goal 2 (Enhance Situational Awareness) includes real-time query, aggregated analysis, and agile maneuver. Goal 3 (Enhance Threat-Specific Operations) includes remote reconfiguration, additional sensing activation, and forensic analysis. Indicators are discrete events; analytics are procedures applied over time. Analysis at the lowest practical level increases detection likelihood.

**Sensing Deployment by Boundary Type**
Enterprise and Regional Boundaries require the full capability suite including encrypted traffic inspection. Local Boundaries include Asset & Config Management but not encrypted traffic inspection (done at EB/RB). Endpoints use Endpoint Awareness as the primary capability with Application Logging on order. PIT/ICS/SCADA uses whitelist-based comparison rather than signature-based detection. Assigned Terrain requires deployable Passive Sensing and FPC capabilities.

**Indicators and Analytics Development**
Indicators are discrete data points (IP, hash, domain) matched at a point in time. Analytics are procedures and logic applied against data sets over time to identify subtle activity. Common formats include STIX, YARA, Sigma, and Snort/Suricata rules. The indicator lifecycle progresses from discovery through validation, deployment, and retirement. Infrastructure Specialists support development by deploying sensors, coordinating signature updates, and ensuring data capture. Sensing data must support both manual development and AI/ML methods.

### KSAT Application

| KSAT ID | Application in This Lesson |
| --- | --- |
| K0059A | IDS/IPS tools and applications covered in Security Alerting and sensor technologies |
| K0087A | Network traffic analysis methodologies in Passive Sensing and Full Packet Capture |
| S0227 | Sensor tuning concepts in Security Alerting management and indicator development |
| T2772 | Building and configuring cyber defense hardware in sensing deployment by boundary |
| T0471 | Coordinating rules and signatures with analysts in indicators and analytics development |

### Preparation for the Lab

The next Lab provides hands-on application of sensing concepts. Prior to beginning the lab, ensure mastery of the following:

- Eight core sensing capabilities and their purposes
- In-band vs. out-of-band data collection
- Sensing requirements by boundary type
- Passive Sensing implementation with Zeek
- Security Alerting implementation with Suricata
- Endpoint Awareness implementation with Wazuh/Sysmon
- Indicator formats (STIX, YARA, Snort/Suricata rules)
- Out-of-band storage architecture

The lab environment presents realistic scenarios requiring deployment of network sensors, configuration of security alerting, and coordination of signature updates.

### Bridge to upcoming concepts

The Cyber Defense Tools and Technologies Lesson builds directly on this sensing foundation. This lesson provided the doctrinal foundation for sensing; the next one focuses on the specific tools that implement these capabilities, including installing, configuring, and maintaining IDS/IPS systems, managing anti-virus and anti-malware solutions, configuring VPN devices and encryption, implementing web filtering technologies, and tuning sensors for optimal performance.

---

## Appendix A: Glossary

| Term | Definition |
| --- | --- |
| **Analytics** | Procedures and logic applied against data sets to identify subtle/persistent activity |
| **Assigned Terrain** | Cyberspace external to DoD boundaries that DoD is ordered to defend |
| **DCO-IDM** | Defensive Cyberspace Operations - Internal Defensive Measures |
| **Endpoint Awareness** | Sensing capability providing data on host behavior |
| **Full Packet Capture** | Recording complete network packets including payload |
| **ICS/SCADA** | Industrial Control System / Supervisory Control and Data Acquisition |
| **Indicator** | Discrete event or data highlighting potential adversary activity |
| **On Order** | Capability activated when directed rather than continuously |
| **Out-of-Band** | Data path separate from production network |
| **Passive Sensing** | Network traffic metadata collection without affecting traffic flow |
| **PIT** | Platform Information Technology (weapons systems IT) |
| **Roll-Up Reporting** | Endpoint data aggregation to central repository |
| **Security Alerting** | Automated notification of detected conditions |
| **SPN** | Special Purpose Network |

---

## Appendix B: CWP 3-2.1 Quick Reference

### Three Goals

1. Enhance protection of DOD cyberspace terrain
2. Enhance real-time situational awareness
3. Enhance threat-specific defensive operations

### Nine Objectives

- 1.1: Automated countermeasures at boundaries
- 1.2: Host-based automated response
- 1.3: Indicator and analytics development
- 2.1: Real-time query capability
- 2.2: Aggregated data analysis
- 2.3: Agile maneuver
- 3.1: Remote/dynamic reconfiguration
- 3.2: Additional sensing activation
- 3.3: Advanced forensic analysis

### Eight Core Capabilities

1. Passive Sensing
2. Full Packet Capture
3. Encrypted/Obfuscated Traffic Inspection
4. Security Alerting
5. Asset and Configuration Management Data Collection
6. Endpoint Awareness
7. Application Logging
8. Post-Incident Analysis Data Collection

---

## Appendix C: Additional Resources

### Doctrinal References

- CWP 3-2.1, USCYBERCOM Operational Guidance for Sensing
- CWP 3-2, Defensive Cyberspace Operations
- CWP 3-33.4, CPT Organization, Functions, and Employment
- NIST Cybersecurity Framework

### Tool Documentation

- Zeek: https://docs.zeek.org/
- Suricata: https://suricata.readthedocs.io/
- Wazuh: https://documentation.wazuh.com/
- Sysmon: Microsoft Sysinternals documentation

---

*End of Lesson*