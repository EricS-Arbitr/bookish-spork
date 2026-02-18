# LAB-XX3: Network Analysis

Owner: Eric Starace, Cameron Murphy
Last edited by: Cameron Murphy

> This document contains Controlled Unclassified Information (CUI) and must be handled within the protections of that data.
> 

---

| **Lab Reference** |  |
| --- | --- |
| **Lab ID** | LAB-003-004 |
| **Lab Name** | Network Traffic Analysis and Security Architecture Design |
| **Associated Lessons** | Lesson 3: Network Infrastructure and Protocols; Lesson 4: Network Security Architecture |
| **Duration** | 8 hours (recommended: 2 sessions of 4 hours) |
| **Environment** | Open Terrain Lab Environment with Windows Server, Windows 10, Linux (Ubuntu) |

---

Learning Objectives

Upon completion of this lab, learners demonstrate the ability to:

1. Capture and analyze network traffic to establish performance baselines using tcpdump and Wireshark
2. Identify anomalous traffic patterns indicative of potential security threats including beaconing, data exfiltration, and lateral movement
3. Analyze protocol-level security for DHCP, DNS, and Active Directory authentication traffic
4. Design multi-zone network security architectures with appropriate segmentation and device placement
5. Apply DoD boundary requirements from CWP 3-2.1 to sensing capability deployment
6. Create firewall rules and access control lists implementing defense-in-depth principles

---

## KSAT Coverage

This lab addresses the following Knowledge, Skills, Abilities, and Tasks from the DCWF Cyber Defense Infrastructure Support Specialist work role:

| KSAT ID | Type | Description |
| --- | --- | --- |
| K0022 | Knowledge | Computer networking concepts and protocols, and network security methodologies |
| K0081A | Knowledge | Network protocols such as TCP/IP, Dynamic Host Configuration, Domain Name System (DNS), and directory services |
| K0087A | Knowledge | Network traffic analysis (tools, methodologies, processes) |
| K0092B | Knowledge | How traffic flows across the network (TCP, IP, OSI Model) |
| K0093 | Knowledge | Packet-level analysis |
| K1072 | Knowledge | Network security architecture concepts including topology, protocols, components, and principles (defense-in-depth, Zero Trust) |
| K0049 | Knowledge | Host/network access control mechanisms (e.g., access control list) |
| K0063 | Knowledge | Cybersecurity principles and organizational requirements (CIA, authentication, non-repudiation) |
| K1074A | Knowledge | Transmission records (Wi-Fi, RFID, Bluetooth, VoIP, cellular, satellite) and jamming techniques |
| S0157 | Skill | Applying host/network access controls (e.g., access control list) |
| T0481A | Task | Create, edit, and manage network access control lists on specialized cyber defense systems |
| T5090 | Task | Assist in assessing the impact of implementing and sustaining a dedicated cyber defense infrastructure |
| T0960 | Task | Assist in identifying, prioritizing, and coordinating the protection of critical cyber defense infrastructure |

---

## Doctrinal References

- **CWP 3-2.1**, Sensing (March 2017) - Defense-in-depth boundaries, sensing capabilities, passive sensing requirements
- **CWP 3-2**, Defensive Cyberspace Operations (March 2017) - DCO concepts and planning considerations
- **CWP 3-33.4**, CPT Organization, Functions, and Employment (May 2022) - Network discovery, mission analysis
- **JP 3-12**, Cyberspace Operations (June 2018) - DODIN architecture, physical/logical network layers

---

## Prerequisites

Before beginning this lab, ensure completion of the following:

- Lesson 3: Network Infrastructure and Protocols (including all knowledge checks)
- Lesson 4: Network Security Architecture (including all knowledge checks)
- Familiarity with Wireshark interface and basic capture/filter operations
- Basic understanding of Linux command line and Windows PowerShell
- Understanding of OSI model, TCP/IP stack, and common network protocols

---

## Lab Environment

[https://github.com/uki-code/ukilrn-courses/blob/arbitr/dev-cameron/modules/labs/LAB-185/lab.json](https://github.com/uki-code/ukilrn-courses/blob/arbitr/dev-cameron/modules/labs/LAB-185/lab.json)

### Network Topology

The lab environment simulates a small DoD enclave network with multiple security zones:

| Zone | Subnet | Systems | Purpose |
| --- | --- | --- | --- |
| External | 172.16.31.0/24 | caldera | Simulated internet/external network |
| DMZ | 172.16.1.0/24 | DMZ-WEB | Public-facing web server |
| User | 172.16.2.0/24 | USER-WS | User workstations |
| Server | 172.16.3.0/24 | DC01, SRV01 | Domain controller, file server |
| Management | 172.16.4.0/24 | analyst01 | Security monitoring (Ubuntu) |

### System Details

| System Name | OS | IP Address | Role |
| --- | --- | --- | --- |
| dc1 | Windows Server 2022 | 172.16.3.10 | Domain Controller, DNS, DHCP |
| srv01 | Windows Server 2022 | 172.16.3.20 | File Server, IIS |
| dmz-web | Ubuntu 22.04 | 172.16.1.10 | Apache Web Server |
| user-ws | Windows 10 | DHCP (172.16.2.x) | User Workstation |
| analyst01 | Ubuntu 22.04 | 172.16.4.10 | Security Monitoring |
| caldera | Ubuntu 22.04 | 172.16.31.100 | Kali/Traffic Generator |

### Credentials

| System | Username | Password |
| --- | --- | --- |
| Windows Domain | militaryops.local\admin | Supertooradmin! |
| Linux Systems | learner | learner |

### Required Tools (Pre-installed)

- Wireshark 4.x (Windows and Linux systems)
- tcpdump (Linux systems)
- Microsoft Visio or draw.io (for network diagrams)
- Text editor (Notepad++, nano, or vim)
- Windows Firewall with Advanced Security
- iptables/nftables (Linux systems)

---

## Exercise 1: Traffic Baseline Development and Anomaly Detection

**Duration:** 90 minutes

**KSAT Focus:** K0087A, K0092B, K0093

### Objective

Capture network traffic during normal operations, calculate baseline metrics, and identify anomalous patterns indicative of potential security threats. This exercise develops foundational traffic analysis skills essential for detecting adversary activity within DoD networks.

### Background

Per CWP 3-2.1, passive sensing provides metadata that characterizes network traffic without active probing. Effective anomaly detection requires establishing baseline traffic patterns against which deviations are measured. Cyber Defense Infrastructure Support Specialists must understand normal traffic characteristics to identify indicators of compromise such as beaconing behavior, unusual data transfers, and lateral movement attempts.

### Scenario

Your unit has deployed to support a tactical network operations center. The network has been operational for 72 hours with standard user activity (web browsing, email, file sharing, authentication). Intelligence reports indicate APT activity targeting similar networks in the region. Your task is to establish traffic baselines and identify any anomalous activity that may indicate adversary presence.

### Procedures

### Part A: Traffic Capture Setup

1. Log into SENSOR (Ubuntu) using the provided credentials.
2. Open a terminal and verify network interface configuration:
    
    ```bash
    ip addr show
    ```
    
3. Identify the interface connected to the monitored network segment (typically eth1 or ens192).
4. Create a directory for capture files:
    
    ```bash
    mkdir -p ~/lab_captures/exercise1
    ```
    
5. Begin capturing traffic using tcpdump. Capture for 10 minutes to establish baseline:
    
    ```bash
    sudo tcpdump -i eth1 -w ~/lab_captures/exercise1/baseline_capture.pcap -G 600 -W 1
    ```
    
6. While tcpdump runs, generate normal traffic by logging into YOURNAME-USER-WS and performing typical activities (browse internal web server, access file shares, authenticate to domain resources).

### Part B: Baseline Metric Calculation

1. After capture completes, open the PCAP file in Wireshark:
    
    ```bash
    wireshark ~/lab_captures/exercise1/baseline_capture.pcap &
    ```
    
2. Access capture statistics via **Statistics > Capture File Properties**. Document the following metrics:
    - Total packets captured
    - Total bytes captured
    - Average packets per second
    - Average bytes per second
    - Capture duration
3. Navigate to **Statistics > Protocol Hierarchy**. Record the percentage distribution of protocols. Expected normal traffic should show:
    - TCP: 70-85%
    - UDP: 10-20%
    - DNS: 3-8%
    - HTTP/HTTPS: 40-60%
    - SMB: 10-20%
4. Navigate to **Statistics > Conversations > IPv4**. Document the top 10 talkers by bytes transferred.
5. Navigate to **Statistics > IO Graphs**. Configure the graph to display packets per second over time. Identify any traffic spikes or patterns.

### Part C: Anomaly Detection

A pre-staged capture file containing both normal and suspicious traffic has been placed on the sensor system. Analyze this file for anomalies.

1. Open the pre-staged capture file:
    
    ```bash
    wireshark /opt/lab_data/suspicious_traffic.pcap &
    ```
    
2. Search for beaconing behavior. Apply the following display filter to identify periodic outbound connections:
    
    ```
    ip.dst == 10.0.0.0/8 and tcp.flags.syn == 1 and tcp.flags.ack == 0
    ```
    
3. Navigate to **Statistics > Conversations > TCP**. Sort by packets and look for connections with regular intervals (beaconing typically shows consistent packet counts over time).
4. Check for DNS tunneling indicators. Apply filter:
    
    ```
    dns.qry.name.len > 50
    ```
    
    Look for unusually long subdomain names (potential encoded data) or high volumes of TXT record queries.
    
5. Identify potential data exfiltration. Look for:
    - Large outbound transfers to external IPs
    - Connections to unusual ports (non-standard HTTP/HTTPS)
    - Encrypted traffic to unknown destinations
6. Check for lateral movement indicators. Apply filter:
    
    ```
    smb2 or dcerpc or tcp.port == 445 or tcp.port == 135
    ```
    
    Look for workstation-to-workstation SMB traffic (unusual in most environments) or multiple authentication attempts.
    
7. Document all anomalies discovered, including:
    - Source and destination IP addresses
    - Ports and protocols involved
    - Time stamps of suspicious activity
    - Potential MITRE ATT&CK technique mapping

### Deliverables

1. Traffic Baseline Report documenting normal traffic characteristics (protocol distribution, top talkers, bandwidth utilization)
2. Anomaly Detection Report listing all suspicious traffic identified with supporting evidence
3. Screenshots of Wireshark analysis supporting findings

---

## Exercise 2: Protocol Security Analysis

**Duration:** 75 minutes

**KSAT Focus:** K0081A, K0022, K0093

### Objective

Analyze protocol-level traffic for DHCP, DNS, and Active Directory authentication to identify security threats and misconfigurations. This exercise builds deep protocol knowledge required to detect sophisticated attacks targeting network infrastructure services.

### Scenario

Network administrators have reported intermittent connectivity issues and users receiving incorrect IP addresses. Additionally, authentication failures have increased 300% over the past 48 hours. Your task is to analyze protocol-level traffic to identify the root cause and any potential security incidents.

### Procedures

### Part A: DHCP Traffic Analysis

1. On SENSOR, open the pre-staged DHCP capture file:
    
    ```bash
    wireshark /opt/lab_data/dhcp_analysis.pcap &
    ```
    
2. Apply the DHCP display filter:
    
    ```
    dhcp or bootp
    ```
    
3. Identify the DORA (Discover, Offer, Request, Acknowledge) sequence. Document:
    - Client MAC addresses requesting IP addresses
    - DHCP server IP addresses responding
    - IP addresses being offered/assigned
    - Lease duration and options provided
4. Search for rogue DHCP server indicators. Look for DHCP Offer packets from IP addresses other than the authorized server (10.0.3.10). Filter:
    
    ```
    dhcp.type == 2 and ip.src != 10.0.3.10
    ```
    
5. Check for DHCP starvation attack indicators. Look for:
    - High volume of DHCP Discover packets from different MAC addresses in short timeframe
    - Spoofed MAC addresses (random vendor prefixes)
    - DHCP NAK responses indicating pool exhaustion

### Part B: DNS Traffic Analysis

1. Open the DNS analysis capture file:
    
    ```bash
    wireshark /opt/lab_data/dns_analysis.pcap &
    ```
    
2. Apply DNS filter and document normal DNS query patterns:
    
    ```
    dns
    ```
    
3. Navigate to **Statistics > DNS** to view query type distribution. Normal patterns show:
    - A records: 60-70% (IPv4 lookups)
    - AAAA records: 10-20% (IPv6 lookups)
    - PTR records: 5-15% (reverse lookups)
    - TXT records: less than 5%
4. Search for DNS tunneling indicators:
    
    ```
    dns.qry.name.len > 50 or dns.qry.type == 16
    ```
    
    Document any queries with unusually long subdomain names or high TXT record volume.
    
5. Check for DNS poisoning/spoofing indicators:
    - Multiple responses to single query (race condition)
    - Responses from non-authoritative servers
    - Mismatched TTL values
6. Identify potential DNS amplification attack indicators by looking for large response packets or queries to open resolvers.

### Part C: Active Directory Authentication Analysis

1. Open the authentication capture file:
    
    ```bash
    wireshark /opt/lab_data/auth_analysis.pcap &
    ```
    
2. Filter for Kerberos authentication traffic:
    
    ```
    kerberos
    ```
    
3. Identify normal authentication flow components:
    - AS-REQ/AS-REP (Authentication Service exchange)
    - TGS-REQ/TGS-REP (Ticket Granting Service exchange)
    - AP-REQ/AP-REP (Application exchange)
4. Search for Kerberoasting indicators. Filter for TGS requests targeting service accounts:
    
    ```
    kerberos.msg_type == 13
    ```
    
    Look for high volume of TGS requests from single source targeting multiple SPNs.
    
5. Check for NTLM authentication (should be minimal in modern environments):
    
    ```
    ntlmssp
    ```
    
6. Search for failed authentication attempts. Filter for Kerberos errors:
    
    ```
    kerberos.error_code
    ```
    
    Common error codes to watch:
    
    - KDC_ERR_PREAUTH_FAILED (24): Password incorrect
    - KDC_ERR_C_PRINCIPAL_UNKNOWN (6): Account does not exist
    - KDC_ERR_CLIENT_REVOKED (18): Account disabled/locked
7. Document all authentication anomalies and map to potential attack techniques (Pass-the-Hash, Pass-the-Ticket, Kerberoasting, Golden Ticket).

### Deliverables

1. Protocol Analysis Report with sections for DHCP, DNS, and Authentication findings
2. Security incident documentation for any threats identified
3. Recommendations for protocol-level security improvements

---

## Exercise 3: Network Security Architecture Design

**Duration:** 90 minutes

**KSAT Focus:** K1072, K0063, T5090

### Objective

Design a multi-zone network security architecture implementing defense-in-depth principles. Apply security zone concepts, device placement strategies, and segmentation techniques to create a secure network topology aligned with DoD requirements.

### Scenario

Your unit is establishing a new tactical network operations center that will support both unclassified and mission-critical operations. The network must provide public-facing web services, internal collaboration tools, and secure access to sensitive mission data. Design a network architecture that implements appropriate security zones, device placement, and traffic flow controls per CWP 3-2.1 defense-in-depth requirements.

### Requirements

The network architecture must include the following components:

- **External Zone:** Connection to external networks (simulated internet)
- **DMZ:** Public-facing web server, mail relay, reverse proxy
- **User Zone:** 50 user workstations across 2 departments
- **Server Zone:** Domain controllers, file servers, application servers
- **Management Zone:** Security monitoring, backup systems, network management
- **Restricted Zone:** Mission-critical systems requiring enhanced protection

### Procedures

### Part A: Zone Definition and Trust Levels

1. Open the network diagramming tool (Visio or draw.io) on your workstation.
2. Create a new document and define the following security zones with IP addressing:

| Zone | Subnet | Trust Level | Description |
| --- | --- | --- | --- |
| External | 10.100.0.0/24 | Untrusted | External network connection |
| DMZ | 10.100.1.0/24 | Semi-Trusted | Public-facing services |
| User-Dept1 | 10.100.10.0/24 | Trusted | Department 1 workstations |
| User-Dept2 | 10.100.11.0/24 | Trusted | Department 2 workstations |
| Server | 10.100.20.0/24 | Highly Trusted | Infrastructure servers |
| Management | 10.100.30.0/24 | Highly Trusted | Security and management |
| Restricted | 10.100.40.0/24 | Restricted | Mission-critical systems |
1. Document the trust relationships between zones. Create a matrix showing permitted traffic flows:
    - External to DMZ: Permitted (HTTP/HTTPS only)
    - DMZ to Server: Permitted (specific application ports)
    - User to Server: Permitted (authentication, file access)
    - Management to All: Permitted (administrative access)
    - Restricted: Limited access from Management only

### Part B: Device Placement

1. Design a dual-firewall DMZ architecture. Place the following devices:
    - External Firewall (NGFW-EXT): Between External and DMZ
    - Internal Firewall (NGFW-INT): Between DMZ and Internal zones
    - WAF: In front of DMZ web server
2. Place intrusion detection/prevention systems:
    - NIDS-EXT: Mirror port on External-DMZ segment
    - NIPS-INT: Inline between Internal Firewall and Server zone
3. Add internal segmentation devices:
    - Layer 3 Switch: Core switch providing inter-VLAN routing
    - Internal Firewall (FW-RESTRICTED): Isolating Restricted zone
4. Position supporting infrastructure:
    - Log Collector: In Management zone
    - SIEM: In Management zone
    - Network TAPs: At each boundary crossing

### Part C: Defense-in-Depth Documentation

1. Create a defense-in-depth matrix documenting security controls at each layer:

| Layer | Controls | Purpose |
| --- | --- | --- |
| Perimeter | NGFW, WAF, NIDS | Filter external threats |
| Network | Segmentation, ACLs, NIPS | Limit lateral movement |
| Host | EDR, Host Firewall, AV | Endpoint protection |
| Application | Authentication, Input validation | Application security |
| Data | Encryption, DLP, Access controls | Data protection |
1. Document traffic flow paths for common use cases:
    - External user accessing public web server
    - Internal user accessing file share
    - Administrator accessing restricted system
2. Complete the network architecture diagram with all zones, devices, and traffic flows clearly labeled.

### Deliverables

1. Network Security Architecture Diagram showing all zones, devices, and connections
2. Zone Trust Matrix documenting permitted traffic flows between zones
3. Defense-in-Depth Documentation mapping controls to security layers
4. Device Placement Justification explaining security device positioning decisions

---

## Exercise 4: DoD Boundary Implementation Planning

**Duration:** 75 minutes

**KSAT Focus:** K1072, T0960, T5090

### Objective

Apply DoD boundary model requirements from CWP 3-2.1 to plan sensing capability deployment. Map the network architecture from Exercise 3 to DoD boundary types and determine appropriate sensing capabilities for each boundary.

### Background

CWP 3-2.1 defines five boundary types within the DoD cyberspace defense architecture: Enterprise Boundary (EB), Regional Boundary (RB), Local Boundary (LB), Endpoint, and PIT/ICS/SCADA. Each boundary type has specific sensing requirements to achieve the three sensing goals: enhance protection, enhance situational awareness, and enable threat-specific response operations.

### Procedures

### Part A: Boundary Type Mapping

1. Using the network architecture from Exercise 3, map each zone to the appropriate DoD boundary type:

| Network Zone | DoD Boundary | Rationale |
| --- | --- | --- |
| External-DMZ | Local Boundary | Perimeter of local enclave |
| DMZ-Internal | Local Boundary | Internal boundary within enclave |
| User Zones | Endpoint | User workstation boundary |
| Server Zone | Endpoint | Server system boundary |
| Restricted Zone | PIT/ICS/SCADA (if applicable) | Mission-critical systems requiring specialized protection |
1. Document the boundary hierarchy showing how local boundaries connect to regional and enterprise boundaries in a typical DoD environment.

### Part B: Sensing Capability Requirements

1. Using CWP 3-2.1 requirements, complete the sensing capability matrix for each boundary:

| Sensing Capability | Local Boundary | Endpoint | PIT/ICS/SCADA |
| --- | --- | --- | --- |
| Passive Sensing | Required | N/A | Required |
| Full Packet Capture | On Order | N/A | On Order |
| Encrypted Traffic Inspection | Optional | N/A | N/A |
| Security Alerting | Required | Required | Required |
| Asset & Config Management | Required | Required | Required |
| Endpoint Awareness | N/A | Required | Required |
| Application Logging | N/A | On Order | On Order |
| Post-Incident Analysis | Required | Required | Required |
1. For PIT/ICS/SCADA boundaries, document the whitelist-based detection approach. These systems require behavioral analysis based on expected traffic patterns rather than signature-based detection.

### Part C: Sensing Deployment Plan

1. Create a sensing deployment plan that addresses out-of-band data collection requirements:
    - Network TAP placement for passive sensing
    - Dedicated management VLAN for security data
    - Log aggregation architecture
    - SIEM integration points
2. Document how the sensing deployment supports the three CWP 3-2.1 sensing goals:
    - **Enhance Protection:** How sensing enables proactive defense
    - **Enhance Situational Awareness:** How sensing provides network visibility
    - **Enable Threat-Specific Operations:** How sensing supports CPT operations
3. Update the network architecture diagram from Exercise 3 to include sensing capability placement.

### Deliverables

1. Boundary Type Mapping document aligning network zones to DoD boundaries
2. Sensing Capability Matrix showing required capabilities per boundary
3. Sensing Deployment Plan with out-of-band collection architecture
4. Updated Network Architecture Diagram with sensing capabilities

---

## Exercise 5: Firewall Rules and Access Control Implementation

**Duration:** 90 minutes

**KSAT Focus:** K0049, S0157, T0481A

### Objective

Implement firewall rules and access control lists to enforce the security zone policies defined in Exercise 3. Apply least privilege principles and document security policy implementation.

### Procedures

### Part A: External Firewall Rules (NGFW-EXT)

1. Log into the lab firewall simulation environment on YOURNAME-SENSOR.
2. Create inbound rules from External to DMZ:

| # | Source | Dest | Port | Protocol | Action | Description |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Any | 10.100.1.10 | 443 | TCP | ALLOW | HTTPS to web |
| 2 | Any | 10.100.1.10 | 80 | TCP | ALLOW | HTTP to web |
| 3 | Any | 10.100.1.20 | 25 | TCP | ALLOW | SMTP to mail |
| 999 | Any | Any | Any | Any | DENY | Default deny |
1. Create outbound rules from DMZ to External:

| # | Source | Dest | Port | Protocol | Action | Description |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 10.100.1.20 | Any | 25 | TCP | ALLOW | SMTP relay |
| 2 | 10.100.1.0/24 | Any | 53 | UDP/TCP | ALLOW | DNS queries |
| 999 | Any | Any | Any | Any | DENY | Default deny |

### Part B: Internal Firewall Rules (NGFW-INT)

1. Create rules for DMZ to Server zone traffic:

| # | Source | Dest | Port | Protocol | Action | Description |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 10.100.1.10 | 10.100.20.30 | 3306 | TCP | ALLOW | Web to DB |
| 2 | 10.100.1.10 | 10.100.20.10 | 389 | TCP | ALLOW | LDAP auth |
| 999 | Any | Any | Any | Any | DENY | Default deny |
1. Create rules for User to Server zone traffic:

| # | Source | Dest | Port | Protocol | Action | Description |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 10.100.10.0/23 | 10.100.20.10 | 88,389,636 | TCP/UDP | ALLOW | AD auth |
| 2 | 10.100.10.0/23 | 10.100.20.20 | 445 | TCP | ALLOW | File shares |
| 3 | 10.100.10.0/23 | 10.100.20.10 | 53 | UDP/TCP | ALLOW | DNS |
| 999 | Any | Any | Any | Any | DENY | Default deny |

### Part C: Linux iptables Implementation

1. On YOURNAME-DMZ-WEB (Ubuntu), implement host-based firewall rules using iptables:

```bash
# Flush existing rules
sudo iptables -F

# Set default policies
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Allow established connections
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow HTTP/HTTPS
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow SSH from Management zone only
sudo iptables -A INPUT -p tcp -s 10.100.30.0/24 --dport 22 -j ACCEPT

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT
```

1. Verify rules are active:

```bash
sudo iptables -L -v -n
```

1. Save rules for persistence:

```bash
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

### Part D: Windows Firewall Configuration

1. On YOURNAME-SRV01 (Windows Server), open Windows Defender Firewall with Advanced Security.
2. Create inbound rules to allow file sharing from User zones only:
    - New Rule > Port > TCP > 445 > Allow > Domain, Private
    - Scope: Remote IP 10.100.10.0/23
3. Create a rule to block all SMB from other zones.
4. Export firewall policy for documentation.

### Deliverables

1. Complete Firewall Ruleset document for external and internal firewalls
2. Linux iptables configuration file
3. Windows Firewall policy export
4. Access Control Policy Documentation explaining rule logic and least privilege implementation

---

## Lab Summary and Deliverables Checklist

### Complete Deliverables

Verify completion of all deliverables before submitting the lab:

### Exercise 1: Traffic Baseline Development and Anomaly Detection

- [ ]  Traffic Baseline Report (protocol distribution, top talkers, bandwidth metrics)
- [ ]  Anomaly Detection Report (suspicious traffic with evidence)
- [ ]  Wireshark screenshots supporting analysis

### Exercise 2: Protocol Security Analysis

- [ ]  Protocol Analysis Report (DHCP, DNS, Authentication sections)
- [ ]  Security incident documentation
- [ ]  Protocol security improvement recommendations

### Exercise 3: Network Security Architecture Design

- [ ]  Network Security Architecture Diagram
- [ ]  Zone Trust Matrix
- [ ]  Defense-in-Depth Documentation
- [ ]  Device Placement Justification

### Exercise 4: DoD Boundary Implementation Planning

- [ ]  Boundary Type Mapping document
- [ ]  Sensing Capability Matrix
- [ ]  Sensing Deployment Plan
- [ ]  Updated Network Architecture Diagram with sensing

### Exercise 5: Firewall Rules and Access Control Implementation

- [ ]  Complete Firewall Ruleset document
- [ ]  Linux iptables configuration file
- [ ]  Windows Firewall policy export
- [ ]  Access Control Policy Documentation

---

## Evaluation Criteria

| Criterion | Weight |
| --- | --- |
| Technical accuracy of traffic analysis and baseline metrics | 20% |
| Completeness of protocol security analysis | 15% |
| Quality of network architecture design and documentation | 20% |
| Proper application of CWP 3-2.1 boundary requirements | 15% |
| Effectiveness of firewall rules (least privilege, completeness) | 20% |
| Overall documentation quality and professionalism | 10% |

---

## Additional Resources

### Doctrinal References

- CWP 3-2.1, Sensing (March 2017)
- CWP 3-2, Defensive Cyberspace Operations (March 2017)
- CWP 3-33.4, CPT Organization, Functions, and Employment (May 2022)
- JP 3-12, Cyberspace Operations (June 2018)

### Technical References

- Wireshark User Guide: https://www.wireshark.org/docs/wsug_html/
- tcpdump manual: https://www.tcpdump.org/manpages/tcpdump.1.html
- iptables documentation: https://netfilter.org/documentation/
- MITRE ATT&CK Framework: https://attack.mitre.org/

---

*End of Lab*