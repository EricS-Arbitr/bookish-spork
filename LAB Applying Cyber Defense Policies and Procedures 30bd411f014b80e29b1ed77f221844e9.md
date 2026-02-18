# LAB: Applying Cyber Defense Policies and Procedures

Owner: Eric Starace
Last edited by: Eric Starace

# LAB: Applying Cyber Defense Policies and Procedures

## Cyber Defense Infrastructure Support Specialist Course

| **Estimated Completion Time** | 3–4 hours |
| --- | --- |
| **Prerequisites** | Lesson 12 (Cyber Defense Policies and Procedures); Lesson 11 (Risk Management Framework); Lab 11A recommended; Familiarity with at least one deployed cyber defense tool (Suricata, Zeek, Wazuh, or Elastic Stack) from previous labs |
| **Lab Type** | Documentation, evidence collection, and compliance verification |
| **Classification** | UNCLASSIFIED // FOR TRAINING USE ONLY |

---

## Terminal Learning Objective

Apply cyber defense policies and procedures to operational scenarios by mapping governing policies to daily CDISS activities, developing a Standard Operating Procedure for a cyber defense task, completing a change request with security impact analysis, and collecting compliance evidence from a live system using automated and manual verification methods.

## Enabling Learning Objectives

| ELO | Objective |
| --- | --- |
| 12A.1 | Map a CDISS operational activity to the governing policies at each level of the hierarchy (National, DoD, Command, Local), identifying specific documents and requirements that apply |
| 12A.2 | Develop a complete Standard Operating Procedure for a cyber defense infrastructure task, including all required SOP components and appropriate policy references |
| 12A.3 | Complete a change request with security impact analysis for a modification to a cyber defense system, applying the change management process from the lesson |
| 12A.4 | Collect compliance evidence from a Linux server using manual commands and automated SCAP scanning, and document findings in a format suitable for inspection |

## KSAT Alignment

| KSAT ID | Type | Description |
| --- | --- | --- |
| K0984 | Knowledge (Core) | Knowledge of cyber defense policies, procedures, and regulations |
| T0654B | Task (Core) | Implement risk assessment and authorization requirements per the RMF process for dedicated cyber defense systems within the enterprise, and document and maintain records for them |

---

## Lab Environment

**Target System:** The Linux server used in previous labs (Suricata IDS, Zeek, Wazuh agent, or Elastic Stack host)

| System | Role | IP Address |
| --- | --- | --- |
| Ubuntu Server 22.04 LTS | Cyber Defense Platform (YOURSERVER) | 192.168.10.100 |

Adapt the system description and commands throughout this lab to match whichever cyber defense tools are installed on your server. The exercises apply regardless of the specific tool — the documentation and compliance principles are the same.

---

## Exercise 1: Policy Mapping for Cyber Defense Operations

**Estimated Time:** 45 minutes
**ELO Mapping:** 12A.1

### Background

Every action a CDISS performs is governed by policies at multiple levels of the hierarchy. Deploying a sensor, updating IDS signatures, reviewing logs, or hardening a system — each of these traces back through local SOPs, command directives, DoD instructions, and federal law. Understanding which policies apply to a given activity is a foundational skill for operating in compliance and for explaining *why* a procedure exists when asked.

In this exercise, you trace two common CDISS activities through the full policy hierarchy.

### Step 1.1: Map Activity — Deploying a New IDS Sensor

**Scenario:** Your team has been directed to deploy a new Suricata IDS sensor on a network segment to improve detection coverage. You need to identify which policies govern this activity at each level.

Complete the following policy mapping table. For each level, identify at least one governing document and describe what it requires for this activity. Use the policy references from Lesson 12 and Lesson 11.

| Policy Level | Governing Document(s) | Requirement for This Activity |
| --- | --- | --- |
| **National/Federal** | (Which NIST publications apply to deploying a new security capability?) |  |
| **DoD** | (Which DODI governs cybersecurity activities and DCO-IDM on the DODIN?) |  |
| **Command/Agency** | (Which CWP addresses sensing capability requirements and boundary deployment?) |  |
| **Local/Installation** | (What local documentation must be created or updated?) |  |

### Step 1.2: Map Activity — Updating IDS Signatures

**Scenario:** New threat intelligence has been published. You need to update the Suricata rule set on all IDS sensors in your area of responsibility.

Complete the policy mapping:

| Policy Level | Governing Document(s) | Requirement for This Activity |
| --- | --- | --- |
| **National/Federal** |  |  |
| **DoD** |  |  |
| **Command/Agency** |  |  |
| **Local/Installation** |  |  |

### Step 1.3: Identify RMF Touchpoints

For the sensor deployment scenario in Step 1.1, answer the following:

1. Which RMF step(s) are triggered by adding a new sensor to an authorized system?
2. What authorization documentation must be updated?
3. Who must be notified before the change is implemented?

Record your answers — these connect the policy mapping from this lesson to the RMF process covered in Lesson 11.

### Knowledge Check: Policy Application

1. A CDISS needs to add a new Zeek sensor to a network segment that already has an authorized IDS. The ISSO says “just install it — it’s the same type of tool.” What is the correct response?
    1. Install it immediately since similar tools are already authorized
    2. Wait until the annual reauthorization to add it
    3. **Even though a similar tool is authorized, adding a new sensor changes the system boundary and requires a change request, security impact analysis, and potentially an SSP update before installation**
    4. Request a completely new ATO for the Zeek sensor as a separate system
    
    💡
    Any change to an authorized system — including adding new components — requires evaluation through the change management process and assessment of impact to the existing authorization. The scope depends on the significance of the change: adding a sensor of the same type may be a minor SSP update, while adding a different tool (Zeek alongside Suricata) changes the system boundary, introduces new software, and may require AO notification per DODI 8510.01. The key principle is that no change bypasses the process, regardless of how similar it seems to what already exists.
    

---

## Exercise 2: SOP Development for Cyber Defense Operations

**Estimated Time:** 60 minutes
**ELO Mapping:** 12A.2

### Background

Standard Operating Procedures translate high-level policies into actionable, repeatable steps. The lesson introduced SOP structure and components; this exercise requires developing a complete SOP from scratch for a real cyber defense task. The SOP must reference the governing policies identified in Exercise 1 and be detailed enough that a newly assigned CDISS could execute the procedure independently.

### Step 2.1: Select and Scope the SOP

Write an SOP for the following task:

**SOP Topic: Weekly IDS Health Check and Signature Verification**

This SOP covers the weekly procedure for verifying that the IDS is operational, signatures are current, logs are flowing to the SIEM, and any issues are documented and escalated.

### Step 2.2: Complete the SOP

Using the template from Lesson 12 (Appendix B), develop the full SOP. Each section below must be completed.

**Header:**

| Field | Value |
| --- | --- |
| **SOP Number** | SOP-SEC-[assign a number] |
| **Title** | Weekly IDS Health Check and Signature Verification |
| **Version** | 1.0 |
| **Effective Date** | [Today’s date] |
| **Review Date** | [One year from today] |
| **Author** | [Your name / role] |
| **Approved By** | [ISSO or supervisor title] |

**Section 1 — Purpose:**

Write 2–3 sentences explaining why this SOP exists. Reference the operational need (maintaining detection capability) and the compliance requirement (continuous monitoring per NIST SP 800-137, DODI 8530.01).

**Section 2 — Scope:**

Define who must follow this SOP and what systems it covers. Be specific — identify the system type (IDS), the platform (Suricata/Zeek on Ubuntu), and the network segment.

**Section 3 — Responsibilities:**

| Role | Responsibilities |
| --- | --- |
| **CDISS / System Administrator** | (What does this person do?) |
| **ISSO** | (What does this person receive or approve?) |
| **Cyber Defense Analyst** | (What coordination is needed with analysts?) |

**Section 4 — Definitions:**

Define at least four terms a new CDISS would need to know to execute this procedure (e.g., SIEM, IDS, signature, EVE log).

**Section 5 — Procedure:**

Write the step-by-step procedure. Include the specific commands or actions for each step. The procedure should cover:

1. Verify IDS service status
2. Confirm signature/rule set version and last update date
3. Verify log generation (check that new events are being written)
4. Verify log forwarding to SIEM (confirm events appear in centralized logging)
5. Check disk space on the IDS server (log storage)
6. Document results in the weekly checklist
7. Escalation criteria (when and to whom issues are reported)

> **Tip:** Use the actual commands for your installed tool. For Suricata: `systemctl status suricata`, `suricata-update list-sources`, `tail /var/log/suricata/eve.json`, etc. For Zeek: `zeekctl status`, `zeek --version`, `tail /opt/zeek/logs/current/conn.log`, etc.
> 

**Section 6 — References:**

List at least three governing documents from different policy levels. Use the mapping from Exercise 1 to select appropriate references.

**Appendix A — Weekly IDS Health Check Checklist:**

Create a checklist with pass/fail fields:

| # | Check Item | Pass | Fail | Notes |
| --- | --- | --- | --- | --- |
| 1 | IDS service running |  |  |  |
| 2 | Signatures updated within 7 days |  |  |  |
| 3 | New events in log file within last hour |  |  |  |
| 4 | Events visible in SIEM |  |  |  |
| 5 | Disk usage below 80% |  |  |  |
| 6 | No unresolved alerts from previous week |  |  |  |

### Step 2.3: Validate the SOP Against the Live System

SSH into your server and execute each step of the procedure you wrote. Record the actual output.

```bash
# Example validation steps (adapt to your installed tool)

# Step 1: Verify service status
systemctl status suricata 2>/dev/null || systemctl status zeek 2>/dev/null || echo "Check your tool name"

# Step 2: Check signature currency
ls -la /var/lib/suricata/rules/ 2>/dev/null | head -5
# or for Zeek:
cat /opt/zeek/share/zeek/site/local.zeek 2>/dev/null | head -10

# Step 3: Verify log generation
tail -3 /var/log/suricata/eve.json 2>/dev/null || tail -3 /opt/zeek/logs/current/conn.log 2>/dev/null

# Step 5: Check disk usage
df -h / /var/log
```

If any step in your SOP does not work as written, **update the SOP**. This is the normal SOP development cycle — draft, test, revise.

**Capture a screenshot showing the completed SOP validation.**

### Knowledge Check: SOP Development

1. After writing and testing the SOP, you realize that one of the commands requires sudo privileges but the SOP assigns the task to a non-privileged analyst account. What should you do?
    1. Give the analyst sudo access to everything so the SOP works
    2. Remove the step that requires elevated privileges
    3. **Update the SOP to specify which steps require elevated privileges, document the minimum permissions needed (e.g., specific sudo rules), and coordinate with the account manager to provision appropriate access per AC-2 and least privilege**
    4. Add “run everything as root” to the SOP prerequisites
    
    💡
    SOPs must be executable by the assigned role with their actual permissions. Discovering a privilege gap during SOP validation is expected — it reveals an access control requirement that must be resolved through the proper account management process (AC-2), not by granting blanket elevated access. The SOP should document exactly which steps need elevated privileges and what the minimum required permissions are, so that account provisioning follows least privilege per NIST SP 800-53 AC-6.
    

---

## Exercise 3: Change Request and Security Impact Analysis

**Estimated Time:** 45 minutes
**ELO Mapping:** 12A.3

### Background

Lesson 12 covered the eight-step change management process and the requirement for security impact analysis on all changes to cyber defense systems. In this exercise, you complete a change request for a realistic modification — upgrading the IDS rule set delivery method to automated updates — and assess the security implications. This exercise connects the change management procedures from Lesson 12 to the RMF continuous monitoring requirements from Lesson 11.

### Step 3.1: Document the Current State

Before requesting a change, document what exists today. SSH into your server and record:

```bash
# Current signature/rule update method
# For Suricata:
suricata-update list-sources 2>/dev/null
cat /etc/cron.d/suricata-update 2>/dev/null || crontab -l 2>/dev/null | grep suricata
ls -la /var/lib/suricata/rules/*.rules 2>/dev/null | head -5

# For Zeek:
zeek -e 'print zeek_version()' 2>/dev/null
ls -la /opt/zeek/share/zeek/site/ 2>/dev/null | head -10
```

Record: Are signature updates currently manual or automated? When were they last updated?

### Step 3.2: Complete the Change Request

**Scenario:** You are requesting approval to configure automated daily signature updates for the IDS using `suricata-update` (or the equivalent for your tool) with a cron job that runs at 0200 local time, downloads the latest ET Open ruleset, and reloads the IDS.

Complete the change request form:

| Field | Value |
| --- | --- |
| **Request ID** | CR-[YYYY]-[number] |
| **Date Submitted** | [Today’s date] |
| **Requester** | [Your name], CDISS |
| **Change Category** | (Emergency / Standard / Normal / Major — select one and justify) |
| **System Affected** | CD-IDS-001 (Suricata IDS at 192.168.10.100) |
| **Description of Change** |  |
| **Justification** | (Why is this change needed? Reference DODI 8530.01 vulnerability management and CWP 3-2.1 sensing goals) |
| **Current State** | (From Step 3.1 — how are updates performed today?) |
| **Proposed State** | (Describe the automated configuration) |

### Step 3.3: Complete the Security Impact Analysis

For each question, provide a specific answer for this change:

| Security Impact Question | Assessment |
| --- | --- |
| **Does this change affect security controls?** | (Which controls? Does the cron job affect AU-2 logging, SI-2 flaw remediation, CM-3 configuration change control?) |
| **Does this change affect the attack surface?** | (Does automated downloading from an external source introduce risk? What if the source is compromised?) |
| **Does this change affect the system authorization?** | (Is this a significant change requiring AO notification, or a minor change within existing authorization scope?) |
| **Does this change impact other systems?** | (Could a bad rule update affect network traffic? Could it generate false positives that impact analyst workload?) |

### Step 3.4: Develop Supporting Plans

**Implementation Plan:**

| Step | Action | Responsible | Timeline |
| --- | --- | --- | --- |
| 1 |  |  |  |
| 2 |  |  |  |
| 3 |  |  |  |
| 4 |  |  |  |
| 5 |  |  |  |

**Test Plan** (describe how you will validate the change works correctly):

**Rollback Plan** (describe how you will reverse the change if it causes problems):

### Step 3.5: Implement and Verify (If Approved)

If your lab environment permits, implement the automated update:

```bash
# Create the cron job for automated updates
sudo tee /etc/cron.d/suricata-update-daily << 'EOF'
# Automated IDS signature update - CR-[YYYY]-[number]
# Approved by: [ISSO] on [date]
0 2 * * * root /usr/bin/suricata-update && /usr/bin/suricatasc -c reload-rules
EOF

# Verify the cron job is installed
cat /etc/cron.d/suricata-update-daily

# Verify suricata-update runs correctly (manual test)
sudo suricata-update --no-reload 2>&1 | tail -10
```

> **Note:** If Suricata is not installed, document the implementation plan without executing it. The change request documentation is the primary deliverable, not the technical implementation.
> 

**Record: What documentation must be updated as a result of this change?** (Consider: SSP, SOP from Exercise 2, configuration records, CMDB entry)

### Knowledge Check: Change Management

1. You have implemented the automated signature update and it is working. The next morning, the Cyber Defense Analyst reports a spike in false positive alerts. Investigation shows the new rule set includes an overly broad signature. What is the correct sequence of actions?
    1. Immediately delete the cron job and go back to manual updates
    2. Ignore it — false positives are normal after a rule update
    3. Wait for the next automated update to fix it
    4. **Disable the problematic rule, document the issue, coordinate with the Cyber Defense Analyst per T0471, and update the change record with the finding and corrective action taken**
    
    💡
    This scenario demonstrates why change management requires monitoring after implementation (the “Verify” step) and why coordination with Cyber Defense Analysts (KSAT T0471) is essential for signature management. The corrective action follows the change management process — document what happened, take appropriate action, and update records. Reverting the entire change is an overreaction; surgically disabling the problematic rule while maintaining the automated update capability preserves the operational benefit while addressing the specific issue.
    

---

## Exercise 4: Compliance Evidence Collection

**Estimated Time:** 45 minutes
**ELO Mapping:** 12A.4

### Background

Lesson 12 covered compliance verification methods (Examine, Interview, Test, Observe), evidence types, and automated tools including SCAP. Lesson 11 and Lab 11A addressed evidence collection for specific RMF controls. This exercise focuses on the *compliance inspection* perspective — collecting and organizing evidence as you would for a CCRI (Command Cyber Readiness Inspection) or CSIP (Cybersecurity Inspection Program), mapping findings to the policy requirements from Section 12.3.

This exercise builds on Lab 11A’s control-level evidence collection by organizing evidence into an inspection-ready format and introducing automated compliance scanning.

### Step 4.1: Manual Compliance Evidence Collection

Connect to your server and collect evidence for the following compliance areas. For each area, run the commands, record the output, and assess whether the finding is compliant (PASS) or non-compliant (FINDING).

**Area 1: Password and Authentication Policy (DODI 8500.01, NIST SP 800-53 IA-5)**

```bash
# Check password complexity requirements
grep -E "^minlen|^dcredit|^ucredit|^lcredit|^ocredit" /etc/security/pwquality.conf 2>/dev/null

# Check password aging
grep -E "^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE" /etc/login.defs

# Check for accounts with empty passwords
sudo awk -F: '($2 == "" ) {print $1}' /etc/shadow

# Check SSH authentication method
grep -E "^PasswordAuthentication|^PubkeyAuthentication|^PermitRootLogin" /etc/ssh/sshd_config
```

| Check | Expected Value | Actual Value | Status (Pass/Finding) |
| --- | --- | --- | --- |
| Minimum password length | ≥15 characters |  |  |
| Password complexity | Uppercase, lowercase, digit, special required |  |  |
| Max password age | ≤60 days |  |  |
| Accounts with empty passwords | None |  |  |
| SSH root login | Disabled |  |  |
| SSH password authentication | Disabled (key-only) |  |  |

**Area 2: Audit and Logging Configuration (DODI 8530.01, NIST SP 800-53 AU-2/AU-3)**

```bash
# Check if auditd is running
systemctl is-active auditd 2>/dev/null || echo "auditd not active"

# Check audit rules
sudo auditctl -l 2>/dev/null || echo "No audit rules loaded"

# Verify syslog is forwarding (check for remote destination)
grep -r "@@\|@" /etc/rsyslog.d/ 2>/dev/null
cat /etc/rsyslog.conf 2>/dev/null | grep -E "^[^#].*@"

# Check log retention (logrotate config)
cat /etc/logrotate.d/rsyslog 2>/dev/null | head -15

# Verify cyber defense tool logging
ls -la /var/log/suricata/eve.json 2>/dev/null || ls -la /opt/zeek/logs/current/ 2>/dev/null
```

| Check | Expected Value | Actual Value | Status (Pass/Finding) |
| --- | --- | --- | --- |
| auditd service running | Active |  |  |
| Audit rules configured | Rules loaded |  |  |
| Syslog forwarding to SIEM | Remote destination configured |  |  |
| Log retention | ≥90 days |  |  |
| Cyber defense tool logging | Active, recent entries |  |  |

**Area 3: System Hardening (DODI 8500.01, NIST SP 800-53 CM-6/CM-7)**

```bash
# Check for unnecessary services
systemctl list-units --type=service --state=running | grep -v -E "ssh|syslog|auditd|suricata|zeek|wazuh|elastic|cron|dbus|system|network|ufw"

# Check UFW/firewall status
sudo ufw status verbose 2>/dev/null || sudo iptables -L -n 2>/dev/null | head -20

# Check for unattended upgrades
dpkg -l unattended-upgrades 2>/dev/null | grep -E "^ii"

# Check file permissions on sensitive files
stat -c "%a %U %G %n" /etc/shadow /etc/gshadow /etc/passwd 2>/dev/null
```

| Check | Expected Value | Actual Value | Status (Pass/Finding) |
| --- | --- | --- | --- |
| Unnecessary services | None running |  |  |
| Host firewall | Enabled with rules |  |  |
| Automatic security updates | Configured |  |  |
| /etc/shadow permissions | 640 or more restrictive |  |  |

**Capture screenshots of each evidence collection area.**

### Step 4.2: Automated Compliance Scanning with OpenSCAP

Install and run an automated SCAP scan to compare the system against a security baseline.

```bash
# Install OpenSCAP tools
sudo apt update && sudo apt install -y libopenscap8 ssg-base ssg-debderived

# List available SCAP profiles
oscap info /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml 2>/dev/null | grep "Profile"
```

> **Note:** If the SSG content for Ubuntu 22.04 is not available, substitute with the available content for your OS version, or skip to Step 4.3 and document what a SCAP scan would produce. The documentation exercise is the primary objective.
> 

Run the scan:

```bash
# Run SCAP scan against the STIG profile (or Standard profile if STIG unavailable)
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_stig \
  --results /tmp/scap-results.xml \
  --report /tmp/scap-report.html \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml 2>&1 | tail -20

# View summary of results
grep -c "pass" /tmp/scap-results.xml 2>/dev/null
grep -c "fail" /tmp/scap-results.xml 2>/dev/null
```

If the HTML report was generated, open it and review the findings.

**Record:** How many rules passed? How many failed? What is the overall compliance percentage?

### Step 4.3: Organize Evidence for Inspection

Compile your findings from Steps 4.1 and 4.2 into an inspection-ready evidence summary. This is the format you would present during a CCRI or compliance inspection.

Complete the following evidence summary:

| # | Compliance Area | Policy Reference | Verification Method | Result | Evidence Location |
| --- | --- | --- | --- | --- | --- |
| 1 | Password Policy | NIST SP 800-53 IA-5, DISA Ubuntu STIG | Test | (Pass/Finding) | Screenshot 4.1 Area 1 |
| 2 | Audit Configuration | NIST SP 800-53 AU-2, DODI 8530.01 | Test | (Pass/Finding) | Screenshot 4.1 Area 2 |
| 3 | System Hardening | NIST SP 800-53 CM-6, DISA Ubuntu STIG | Test | (Pass/Finding) | Screenshot 4.1 Area 3 |
| 4 | SCAP Compliance | DISA STIG Benchmark | Test (Automated) | ___% compliant | SCAP Report HTML |

For any findings (non-compliant results), create a brief remediation recommendation:

| Finding # | Description | Recommended Corrective Action | Policy Reference |
| --- | --- | --- | --- |
|  |  |  |  |
|  |  |  |  |

> **Connection to Lesson 11:** Any findings that are not immediately resolved would become POA&M entries using the process you practiced in Lab 11A. This exercise demonstrates how compliance inspections *feed* the RMF continuous monitoring process.
> 

### Knowledge Check: Compliance Evidence

1. During a CCRI preparation review, you find that the IDS server passes the automated SCAP scan at 94% compliance, but the 6% of failed checks include a finding for “audit log storage capacity below threshold.” The system has 500MB of free log space. The ISSO says 94% is “good enough” and you should focus on other systems. What is the correct approach?
    1. Accept 94% — it exceeds most compliance thresholds
    2. Delete old logs to free space and rerun the scan
    3. **Document the finding with its risk (loss of audit data could mean undetected security events), create a remediation plan (expand storage or adjust retention), and present the risk to the ISSO with a recommendation — compliance is not about percentages, it is about ensuring each control is effective**
    4. Disable the SCAP check that is failing so the score improves
    
    💡
    Compliance percentages can be misleading. A system at 94% compliance may have the 6% of failures concentrated in a critical area — in this case, audit logging, which is essential for DCO-IDM operations per DODI 8530.01. If the IDS runs out of log storage, it either stops logging (losing detection evidence) or overwrites old data (losing forensic evidence). The correct approach is to assess each finding on its actual risk to the mission, not on its impact to a compliance score. Present findings with risk context so the ISSO can make an informed decision.
    

---

## Lab Completion Checklist

**Exercise 1 — Policy Mapping:**
- [ ] Sensor deployment activity mapped to all four policy hierarchy levels
- [ ] Signature update activity mapped to all four policy hierarchy levels
- [ ] RMF touchpoints identified for sensor deployment scenario
- [ ] Knowledge check answered

**Exercise 2 — SOP Development:**
- [ ] SOP header completed with all required fields
- [ ] Purpose section references governing policies
- [ ] Scope section identifies specific systems and personnel
- [ ] Responsibilities table completed for all roles
- [ ] Definitions section includes at least four terms
- [ ] Procedure section includes specific commands for each step
- [ ] References section cites documents from at least three policy levels
- [ ] Weekly checklist appendix created
- [ ] SOP validated against live system
- [ ] SOP updated based on validation findings (if any)
- [ ] Screenshot of SOP validation captured

**Exercise 3 — Change Request:**
- [ ] Current state documented from live system
- [ ] Change request form completed with all fields
- [ ] Change category selected with justification
- [ ] Security impact analysis completed for all four questions
- [ ] Implementation plan created with steps and timeline
- [ ] Test plan documented
- [ ] Rollback plan documented
- [ ] Affected documentation identified
- [ ] Knowledge check answered

**Exercise 4 — Compliance Evidence Collection:**
- [ ] Area 1 (Password/Authentication) evidence collected and assessed
- [ ] Area 2 (Audit/Logging) evidence collected and assessed
- [ ] Area 3 (System Hardening) evidence collected and assessed
- [ ] OpenSCAP scan attempted (or documented if tools unavailable)
- [ ] Evidence summary table completed
- [ ] Remediation recommendations documented for findings
- [ ] Evidence screenshots captured

### Screenshots Required

1. Exercise 2: SOP validation — commands executed on the live system matching SOP steps
2. Exercise 3: Current state evidence for the change request
3. Exercise 4: Manual compliance checks — password policy, audit configuration, hardening
4. Exercise 4: SCAP scan results (report or terminal output)

---

## Troubleshooting Guide

| Symptom | Possible Cause | Resolution |
| --- | --- | --- |
| No cyber defense tool installed | Previous labs not completed | Adapt exercises to whichever services are running (SSH, Apache, etc.); the documentation and compliance principles still apply |
| `oscap` command not found | OpenSCAP not installed | Run `sudo apt install -y libopenscap8 ssg-base ssg-debderived` |
| No SCAP content for Ubuntu 22.04 | SSG package outdated | Use available content for your OS version, or document what the scan would produce based on the manual checks |
| SCAP scan exits with errors | XML content path incorrect | Run `find /usr/share/xml/scap -name "*.xml" 2>/dev/null` to locate available content files |
| `suricata-update` not found | Suricata not installed | Use the manual compliance checks (Exercise 4 Step 4.1) as the primary deliverable; document the SCAP exercise conceptually |
| `/etc/security/pwquality.conf` missing | `libpam-pwquality` not installed | Run `sudo apt install -y libpam-pwquality` or document as a finding |
| `auditd` not running | Not installed from previous labs | Document as a finding in Exercise 4 — this is a valid compliance gap to report |
| Cron job doesn’t execute | Syntax error or permissions | Verify with `sudo crontab -l` or check `/var/log/syslog` for cron errors |

---

## Summary

In this lab you applied cyber defense policies and procedures to operational scenarios by:

1. **Mapping CDISS activities to the policy hierarchy** by tracing sensor deployment and signature update activities through National, DoD, Command, and Local policy levels, identifying specific governing documents and their requirements at each level
2. **Developing a complete Standard Operating Procedure** for a weekly IDS health check, including all required SOP components, specific technical procedures, policy references, and a validation checklist — then testing the SOP against a live system and revising as needed
3. **Completing a change request with security impact analysis** for automating IDS signature updates, assessing the impact to security controls, attack surface, system authorization, and dependent systems, and developing implementation, test, and rollback plans
4. **Collecting compliance evidence** using both manual verification commands and automated SCAP scanning, organizing findings into an inspection-ready format, and documenting remediation recommendations for non-compliant results

These activities address KSATs K0984 (cyber defense policies, procedures, and regulations) through direct application of the policy hierarchy to operational tasks, and T0654B (implementing RMF requirements and maintaining records) through the operational documentation that supports RMF Step 6 continuous monitoring — SOPs ensure consistent execution, change requests maintain configuration control, and compliance evidence demonstrates ongoing control effectiveness.

---

*Document Version: 1.0Classification: UNCLASSIFIED // FOR TRAINING USE ONLY*