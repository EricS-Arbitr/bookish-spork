# LAB: RMF Documentation for Cyber Defense Systems

Owner: Eric Starace
Last edited by: Eric Starace

# LAB: RMF Documentation for Cyber Defense Systems

## Cyber Defense Infrastructure Support Specialist Course

| **Estimated Completion Time** | 3–4 hours |
| --- | --- |
| **Prerequisites** | Lesson 11; Lab 8C (Suricata) or Lab 9A (System Hardening) recommended; Familiarity with NIST SP 800-37 and FIPS 199 concepts from lesson |
| **Lab Type** | Documentation and evidence collection |
| **Classification** | UNCLASSIFIED // FOR TRAINING USE ONLY |

---

## Terminal Learning Objective

Apply the Risk Management Framework to a cyber defense system by completing FIPS 199 security categorization, documenting security control implementations, collecting assessment evidence from a live system, and creating and closing a Plan of Action and Milestones (POA&M) entry with verified remediation.

## Enabling Learning Objectives

| ELO | Objective |
| --- | --- |
| 11A.1 | Complete a FIPS 199 security categorization for a cyber defense IDS, identifying information types and applying the high-water mark principle |
| 11A.2 | Document implementation details for three NIST SP 800-53 security controls as they apply to a Suricata IDS server |
| 11A.3 | Collect actual assessment evidence from a Linux server by running verification commands and capturing output |
| 11A.4 | Create a POA&M entry for an identified weakness, implement the remediation, and update the POA&M with completion evidence |

## KSAT Alignment

| KSAT ID | Type | Description |
| --- | --- | --- |
| K0108 | Knowledge (Core) | Knowledge of risk management processes (e.g., methods for assessing and mitigating risk) |
| K0984 | Knowledge (Core) | Knowledge of cyber defense policies, procedures, and regulations |
| T0654B | Task (Core) | Implement risk assessment and authorization requirements per the RMF process for dedicated cyber defense systems within the enterprise, and document and maintain records for them |

---

## Lab Environment

**Target System:** Suricata IDS Server (or the Linux server used in previous labs)

| System | Role | IP Address |
| --- | --- | --- |
| Ubuntu Server 22.04 LTS | Cyber Defense IDS (YOURSERVER) | 192.168.10.100 |

If Suricata is not installed from Lab 8C, the documentation and evidence collection exercises still apply — adapt the system description to reflect whichever cyber defense tools are installed (Zeek, Wazuh, Elastic Stack, etc.).

---

## Exercise 1: System Categorization (FIPS 199)

**Estimated Time:** 45 minutes

**ELO Mapping:** 11A.1

### Background

Security categorization is RMF Step 1. Per FIPS 199, every federal information system must be categorized based on the potential impact of a loss of confidentiality, integrity, or availability. The categorization determines which security control baseline (Low, Moderate, High) applies to the system. As a Cyber Defense Infrastructure Support Specialist, you support this process by providing accurate system descriptions and impact justifications.

### Step 1.1: Document the System Description

Complete the following system identification record:

| Field | Value |
| --- | --- |
| **System Name** | Cyber Defense IDS |
| **System Identifier** | CD-IDS-001 |
| **System Owner** | [Your Organization] |
| **System Type** | Major Application / General Support System |
| **Operational Status** | Operational |
| **System Description** | Suricata-based network intrusion detection system that monitors network traffic on the 192.168.10.0/24 network for malicious activity by comparing packets against signature databases and generating alerts for security analysts. |

Document the system boundary — the components that fall within this authorization:

| Component | Description |
| --- | --- |
| Hardware | Ubuntu Server 22.04 host at 192.168.10.100 |
| Software | Suricata 6.x, Filebeat (log shipper), auditd |
| Data | EVE JSON alert logs, network traffic metadata, system configuration files, user authentication records |
| Network Interfaces | Monitoring interface (promiscuous mode), management interface (SSH on port 22) |

### Step 1.2: Identify Information Types

Using NIST SP 800-60 categories, identify the information types processed by the system:

| Information Type | SP 800-60 Category | Description |
| --- | --- | --- |
| Network traffic metadata | C.3.5.1 Information Sharing | Connection records, protocol data, flow information |
| Alert data | D.14.1 IT Security | Signature matches, threat detections, alert metadata |
| System configuration | D.14.1 IT Security | Suricata rules, YAML config, service parameters |
| User authentication data | D.14.1 IT Security | SSH login records, account credentials, session logs |

### Step 1.3: Complete the Security Categorization

For each security objective, determine the potential impact level (Low, Moderate, or High) if that objective were compromised. Write a justification specific to this system.

| Security Objective | Impact Level | Justification |
| --- | --- | --- |
| **Confidentiality** |  | (What is the impact if alert data or configuration is disclosed to unauthorized parties?) |
| **Integrity** |  | (What is the impact if alert data or rules are modified without authorization?) |
| **Availability** |  | (What is the impact if the IDS is unavailable for an extended period?) |

**Overall System Categorization:** ___________

> **Reminder:** FIPS 199 uses the high-water mark principle — the overall categorization equals the highest individual impact level across all three objectives.
> 

### Knowledge Check: System Categorization

1. The IDS categorization rates Integrity as HIGH because modified alert data could hide active attacks. An analyst argues it should be MODERATE because “it’s just a detection tool, not a protection tool.” How do you respond?
    1. Agree — detection tools have lower integrity requirements than prevention tools
    2. Compromise at MODERATE and document the disagreement
    3. **The integrity of detection data directly affects the ability to identify threats; if an attacker can modify or suppress alerts, active compromises go undetected, making the impact HIGH regardless of whether the tool blocks traffic**
    4. Escalate to NIST for a formal ruling on IDS categorization
    
    💡
    The categorization is based on impact to the mission, not on the tool’s technical function. An IDS with compromised integrity cannot be trusted — analysts making decisions based on manipulated alert data may miss active intrusions or waste time investigating fabricated alerts. The impact of undetected compromise to the defended network justifies a HIGH integrity rating.
    

---

## Exercise 2: Control Documentation and Evidence Collection

**Estimated Time:** 75 minutes

**ELO Mapping:** 11A.2, 11A.3

### Background

RMF Steps 3 (Implement) and 4 (Assess) require documenting how security controls are implemented and collecting evidence that demonstrates compliance. The System Security Plan (SSP) contains the implementation descriptions, while assessment evidence proves the controls are operating as documented. In this exercise, you document three controls and then collect real evidence from the server.

### Step 2.1: Document AC-2 (Account Management)

Complete the following control documentation:

| Field | Value |
| --- | --- |
| **Control ID** | AC-2 |
| **Control Title** | Account Management |
| **Implementation Status** | Implemented / Partially Implemented / Planned / Not Applicable |

**Implementation Description** (complete each section):

**(a) Account types on this system:**
- Administrator accounts: (describe — e.g., sudo group members)
- Analyst accounts: (describe — e.g., read-only access to logs)
- Service accounts: (describe — e.g., suricata user, no login shell)

**(b) Account authorization process:**
- How are new accounts requested?
- Who approves account creation?
- How are accounts created?

**(c) Account review and monitoring:**
- How often are accounts reviewed?
- What happens when personnel depart?
- How are failed login attempts monitored?

### Step 2.2: Document AU-2 (Audit Events)

| Field | Value |
| --- | --- |
| **Control ID** | AU-2 |
| **Control Title** | Audit Events |
| **Implementation Status** |  |

**Implementation Description:**

**(a) Authentication events logged:**
- Source file(s):
- Events captured:

**(b) Application events logged (Suricata/Zeek/other):**
- Source file(s):
- Events captured:

**(c) System events logged:**
- Source file(s):
- Events captured:

**(d) Log retention:**
- Local retention period:
- SIEM retention period (if applicable):

### Step 2.3: Document SI-2 (Flaw Remediation)

| Field | Value |
| --- | --- |
| **Control ID** | SI-2 |
| **Control Title** | Flaw Remediation |
| **Implementation Status** |  |

**Implementation Description:**

**(a) Patch identification process:**
- How are patches/updates identified?
- What sources are monitored?

**(b) Patch deployment timelines:**

| Severity | Testing Window | Deployment Window |
| --- | --- | --- |
| Critical |  |  |
| High |  |  |
| Moderate |  |  |
| Low |  |  |

**(c) Verification method:**
- How is successful patching confirmed?

### Step 2.4: Collect Assessment Evidence

Connect to the Ubuntu server and run the following commands to collect evidence for each control. Record the output.

**Evidence for AC-2 (Account Management):**

```bash
# List user accounts with login shells
cat /etc/passwd | grep -v nologin | grep -v false

# List sudo group members
getent group sudo

# List application-specific groups (adjust group name to your setup)
getent group suricata-users 2>/dev/null || echo "Group not configured"

# Show the suricata service account (should have no login shell)
grep suricata /etc/passwd

# Show recent authentication events
tail -15 /var/log/auth.log
```

Record: How many user accounts exist? How many have sudo access? Does the service account have a login shell?

**Evidence for AU-2 (Audit Events):**

```bash
# Verify syslog configuration
cat /etc/rsyslog.d/50-default.conf 2>/dev/null | head -20

# Show recent auth log entries (authentication events)
tail -10 /var/log/auth.log

# Show Suricata logging configuration (if installed)
grep "eve-log" /etc/suricata/suricata.yaml -A 15 2>/dev/null || echo "Suricata not installed"

# Show recent Suricata events (if installed)
tail -3 /var/log/suricata/eve.json 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "No eve.json"

# Show auditd rules (if configured in Lab 9A)
sudo auditctl -l 2>/dev/null || echo "auditd not configured"
```

**Evidence for SI-2 (Flaw Remediation):**

```bash
# Check for available security updates
apt list --upgradable 2>/dev/null | head -20

# Show recent patch history
tail -30 /var/log/apt/history.log

# Show OS version and patch level
lsb_release -a

# Show Suricata version (if installed)
suricata --build-info 2>/dev/null | head -5 || echo "Suricata not installed"
```

**Capture screenshots of each evidence collection set (AC-2, AU-2, SI-2).**

### Knowledge Check: Control Documentation

1. While collecting evidence for AU-2, you discover that auditd is not configured on the server. The control documentation says “Implemented.” What is the correct course of action?
    1. Change the documentation to say “Implemented” anyway since other logging exists
    2. Delete the auditd reference from the control description
    3. **Update the implementation status to “Partially Implemented,” document what is and is not in place, and create a POA&M entry for the gap**
    4. Disable all logging to reset the control status to “Planned”
    
    💡
    RMF requires honest and accurate documentation. If a control is only partially implemented, the SSP must reflect that. The gap between what is documented and what is actually in place becomes a finding, which is tracked through a POA&M entry with milestones and a completion date. Misrepresenting implementation status is a significant compliance failure that undermines the entire authorization decision.
    

---

## Exercise 3: POA&M Creation and Remediation

**Estimated Time:** 45 minutes

**ELO Mapping:** 11A.4

### Background

A Plan of Action and Milestones (POA&M) tracks identified weaknesses and the plan to remediate them. Every finding from a security assessment that is not immediately resolved must have a POA&M entry. In this exercise, you create a POA&M entry for a realistic finding, implement the fix, and close the entry with evidence.

### Step 3.1: Identify the Weakness

**Scenario:** During assessment evidence collection, you discover that SSH on the IDS server allows password authentication. Per the security baseline (and Lab 9A hardening standards), only public key authentication should be permitted.

Verify the current state:

```bash
grep "^PasswordAuthentication" /etc/ssh/sshd_config
```

> **Note:** If you completed Lab 9A, password authentication may already be disabled. In that case, choose one of these alternative findings to document:
- SSH allows more than 3 authentication attempts (`MaxAuthTries` not set or >3)
- Root login is not explicitly disabled
- SSH login banner is not configured
> 
> 
> Verify whichever finding applies and proceed with that weakness.
> 

### Step 3.2: Create the POA&M Entry

Complete the following POA&M record:

| Field | Value |
| --- | --- |
| **Weakness ID** | POAM-CD-IDS-001 |
| **Date Identified** | [Today’s date] |
| **Source** | Security Control Assessment |
| **Control** | IA-2 (Identification and Authentication) |
| **Weakness Description** |  |
| **Risk Level** | (Low / Moderate / High) |
| **Justification for Risk Level** |  |
| **Responsible POC** | [Your name], System Administrator |
| **Scheduled Completion** | [30 days from today] |

**Milestones:**

| # | Milestone | Target Date | Status |
| --- | --- | --- | --- |
| 1 | Verify/generate SSH keys for all users | Day 7 |  |
| 2 | Test key-based authentication | Day 14 |  |
| 3 | Disable password authentication in sshd_config | Day 21 |  |
| 4 | Verify fix and collect evidence | Day 28 |  |
| 5 | Close POA&M entry | Day 30 |  |

**Resources Required:** Estimated 2 hours administrator time

### Step 3.3: Implement the Remediation

Apply the fix (adjust commands to match your specific finding):

**If remediating password authentication:**

```bash
# Verify SSH key exists for your user
ls -la ~/.ssh/id_ed25519* 2>/dev/null || ls -la ~/.ssh/id_rsa* 2>/dev/null

# If no key exists, generate one
ssh-keygen -t ed25519 -C "admin@ids-server"

# Ensure key is in authorized_keys
cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Test key-based login (from another terminal or workstation)
# ssh -i ~/.ssh/id_ed25519 admin@192.168.10.100

# Disable password authentication
sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config

# Validate and restart
sudo sshd -t
sudo systemctl restart sshd

# Verify the change
grep "^PasswordAuthentication" /etc/ssh/sshd_config
```

### Step 3.4: Update and Close the POA&M

Update the POA&M entry with completion details:

| Field | Value |
| --- | --- |
| **Status** | Completed |
| **Actual Completion Date** | [Today’s date] |
| **Verification Method** | Confirmed PasswordAuthentication set to “no” in sshd_config; verified password login attempt is rejected |
| **Evidence** | Screenshot of sshd_config setting; screenshot of failed password authentication attempt |

Collect the closing evidence:

```bash
# Evidence 1: Configuration shows password auth disabled
grep "PasswordAuthentication" /etc/ssh/sshd_config

# Evidence 2: Attempt password login (should fail)
ssh -o PubkeyAuthentication=no admin@192.168.10.100
```

**Capture screenshots of the remediation evidence.**

### Knowledge Check: POA&M Management

1. A POA&M entry has a scheduled completion date of 30 days, but the system administrator is unavailable and the fix will take 60 days. What should happen?
    1. Delete the POA&M entry and create a new one with the correct date
    2. Leave the entry unchanged and fix it when possible
    3. Mark the entry as “Completed” to avoid the overdue status
    4. **Update the POA&M with a revised completion date, document the reason for the delay, and obtain approval from the Authorizing Official for the schedule extension**
    
    💡
    POA&M entries are living documents. Schedules can change, but changes must be documented with justification and approved by the appropriate authority (typically the ISSO or AO). An overdue POA&M without explanation is a compliance finding in itself. Never mark an item complete before the fix is verified, and never delete entries to hide delays.
    

---

## Lab Completion Checklist

**Exercise 1 — System Categorization:**
- [ ] System description and boundary documented
- [ ] Information types identified with SP 800-60 categories
- [ ] Confidentiality, Integrity, Availability impact levels determined with justifications
- [ ] Overall categorization determined using high-water mark
- [ ] Knowledge check answered

**Exercise 2 — Control Documentation and Evidence:**
- [ ] AC-2 (Account Management) implementation documented
- [ ] AU-2 (Audit Events) implementation documented
- [ ] SI-2 (Flaw Remediation) implementation documented
- [ ] AC-2 evidence collected from server (accounts, groups, service accounts)
- [ ] AU-2 evidence collected from server (log configs, sample events)
- [ ] SI-2 evidence collected from server (patch status, version info)
- [ ] Evidence screenshots captured

**Exercise 3 — POA&M:**
- [ ] Weakness identified and verified on server
- [ ] POA&M entry created with milestones and risk level
- [ ] Remediation implemented
- [ ] Fix verified with evidence
- [ ] POA&M entry updated to “Completed”
- [ ] Closing evidence screenshots captured

### Screenshots Required

1. AC-2 evidence: user accounts, group memberships, service account (Exercise 2)
2. AU-2 evidence: log configuration, sample log entries (Exercise 2)
3. SI-2 evidence: patch status, version information (Exercise 2)
4. POA&M remediation: configuration change and verification (Exercise 3)

---

## Troubleshooting Guide

| Symptom | Possible Cause | Resolution |
| --- | --- | --- |
| No Suricata installed | Lab 8C not completed | Adapt documentation to whichever tools are installed (Zeek, Wazuh, Elastic) |
| `/var/log/auth.log` empty | System uses journald only | Use `journalctl -u ssh --since "1 hour ago"` instead |
| No auditd rules | Lab 9A not completed | Document as “Not Implemented” and include in POA&M |
| SSH already hardened | Lab 9A completed | Choose an alternative finding (see Step 3.1 note) |
| `apt list --upgradable` shows errors | Repository issues | Run `sudo apt update` first |

---

## Summary

In this lab you applied the Risk Management Framework to a cyber defense system by:

1. **Completing FIPS 199 security categorization** by identifying information types, assessing impact levels for confidentiality, integrity, and availability, and applying the high-water mark principle to determine the overall system categorization
2. **Documenting security control implementations** for three NIST SP 800-53 controls (AC-2, AU-2, SI-2), describing how each control is implemented on the IDS server
3. **Collecting real assessment evidence** by running verification commands on the Linux server to demonstrate that documented controls are actually in place
4. **Creating and closing a POA&M entry** by identifying a security weakness, documenting a remediation plan with milestones, implementing the fix, and verifying the closure with evidence

These activities address KSATs K0108 (risk management processes), K0984 (cyber defense policies and regulations), and T0654B (implementing RMF requirements and maintaining records for cyber defense systems).

---

*Document Version: 1.0*

*Classification: UNCLASSIFIED // FOR TRAINING USE ONLY*