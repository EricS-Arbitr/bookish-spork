# LAB: Deployment Exercise

Owner: Eric Starace
Last edited by: Eric Starace

# LAB: Deployment Exercise

## Cyber Defense Infrastructure Support Specialist Course

| **Estimated Completion Time** | 3–3.5 hours |
| --- | --- |
| **Prerequisites** | Lesson 18 (Implementation & Coordination); Lesson 17 (Testing & Evaluation); Previous labs with Elastic Stack installed; Ubuntu Server with Suricata or other cyber defense tool |
| **Lab Type** | Planning, documentation, and hands-on deployment |
| **Classification** | UNCLASSIFIED // FOR TRAINING USE ONLY |

---

## Terminal Learning Objective

Implement and deploy a cyber defense infrastructure component by developing a stakeholder coordination plan and deployment plan, executing the deployment with pre/post performance measurements, conducting an impact assessment across operational, performance, mission, and security dimensions, and identifying and prioritizing protection of critical infrastructure assets.

## Enabling Learning Objectives

| ELO | Objective |
| --- | --- |
| 18A.1 | Develop a stakeholder coordination plan identifying internal and external stakeholders, coordination requirements, communication channels, and a deployment plan with cutover strategy, rollback procedures, and change management documentation |
| 18A.2 | Execute a cyber defense tool deployment following the deployment plan, measure pre/post performance impact, validate functionality, and complete the change management record |
| 18A.3 | Conduct impact assessment across all five dimensions (operational, performance, mission, security, resource) and perform a critical infrastructure analysis identifying asset criticality, protection priorities, and MRT-C considerations |

## KSAT Alignment

| KSAT ID | Type | Description |
| --- | --- | --- |
| T0393B | Task (Core) | Coordinate with system administrators to create tools, test beds, and establish requirements |
| T2772 | Task (Core) | Build, install, configure, and test cyber defense hardware |
| T5090 | Task (Core) | Assess the impact of implementing and sustaining a dedicated cyber defense infrastructure |
| T0960 | Task (Core) | Assist in identifying, prioritizing, and coordinating the protection of critical cyber defense infrastructure and key resources |

---

## Lab Scenario

Your organization’s cyber defense infrastructure currently consists of a Suricata IDS and an Elastic Stack SIEM on a single server. The security operations leadership has directed that Windows Event Logs from the Domain Controller (DC01) be forwarded to the SIEM to improve endpoint visibility. This requires deploying Winlogbeat (or Filebeat) on DC01 and configuring Elasticsearch to receive and index the new log source.

This is a change to production cyber defense infrastructure. It requires stakeholder coordination, formal deployment planning, change management documentation, impact assessment, and an update to the organization’s critical infrastructure analysis.

**Lab Environment:**

| System | Role | IP Address | OS |
| --- | --- | --- | --- |
| YOURSERVER | Elastic Stack (Elasticsearch + Kibana) | 192.168.10.50 | Ubuntu Server 22.04 |
| DC01 | Windows Domain Controller / Log Source | 192.168.10.10 | Windows Server 2019/2022 |

> **Note:** This lab uses the Elastic Stack from previous labs. If DC01 is not available, adapt the deployment exercises to configure Filebeat on the Ubuntu server itself to forward syslog or auth.log as the new log source. The planning and documentation exercises apply regardless of which log source is used.
> 

---

## Exercise 1: Stakeholder Coordination and Deployment Planning

**Estimated Time:** 60 minutes
**ELO Mapping:** 18A.1
**KSAT Coverage:** T0393B, T2772

### Background

Before deploying any change to cyber defense infrastructure, the CDISS must identify who needs to be coordinated with, what requirements must be gathered, and how the deployment will be planned and executed. This exercise applies the stakeholder coordination concepts from Section 18.1 and the deployment planning phases from Section 18.2.

### Step 1.1: Stakeholder Identification and Coordination Plan

Identify the stakeholders for this deployment. For each, document their role, what coordination is required, and when.

**Stakeholder Coordination Plan:**

| Field | Value |
| --- | --- |
| **Project** | Windows Event Log Forwarding to SIEM |
| **Date** |  |
| **Prepared By** |  |

**Stakeholder Matrix:**

| Stakeholder | Role in This Deployment | Interest Level | What to Coordinate | When |
| --- | --- | --- | --- | --- |
| System Administrator (DC01) | Manages the Domain Controller | High | (What do you need from them? Access, maintenance window, dependencies?) |  |
| Network Administrator |  |  |  |  |
| ISSO / Security Management |  |  |  |  |
| CSSP |  |  |  |  |
| Operations Staff / Help Desk |  |  |  |  |
| Leadership / Command |  |  |  |  |

For the **System Administrator** specifically, detail the coordination process per Section 18.1.2:

| Coordination Phase | Activities for This Deployment |
| --- | --- |
| **Initial Engagement** | (How do you introduce the project? What do you explain about resource requirements on DC01?) |
| **Requirements Gathering** | (What system information do you need? DC01 OS version, available disk space, current CPU/memory load, firewall rules, Group Policy restrictions?) |
| **Planning** | (What maintenance window do you need? What is the rollback plan if Winlogbeat causes issues on the DC?) |
| **Execution** | (Who installs? Who monitors DC01 health during deployment?) |
| **Transition** | (Who maintains Winlogbeat after deployment? Who monitors for agent health?) |

### Step 1.2: Communication Plan

| Audience | Message | Channel | Frequency |
| --- | --- | --- | --- |
| System Admin (DC01) |  |  |  |
| ISSO |  |  |  |
| CSSP |  |  |  |
| Operations Staff |  |  |  |
| Leadership |  |  |  |

**Escalation Procedures:**

| Issue Type | Escalate To | Timeline |
| --- | --- | --- |
| DC01 performance degradation during deployment |  |  |
| Log forwarding not functioning after deployment |  |  |
| Rollback decision needed |  |  |

### Step 1.3: Deployment Plan

Complete the deployment plan for the Winlogbeat/Filebeat deployment.

**DEPLOYMENT PLAN**

| Field | Value |
| --- | --- |
| **Project** | Windows Event Log Forwarding to SIEM |
| **Version** | 1.0 |
| **Date** |  |

**Scope:**

| In Scope | Out of Scope |
| --- | --- |
| (What exactly is being deployed, where, on which system?) |  |
|  |  |

**Cutover Strategy:**

| Strategy | Selected? | Justification |
| --- | --- | --- |
| Big Bang | ☐ |  |
| Phased | ☐ |  |
| Parallel | ☐ |  |
| Pilot | ☐ |  |

> **Tip:** Consider that this is a single server deployment (DC01) adding a log forwarder. Which cutover strategy is appropriate for this scope? Would your answer change if the deployment were across 50 servers?
> 

**Deployment Schedule:**

| Phase | Activities | Duration | Owner |
| --- | --- | --- | --- |
| Preparation |  |  |  |
| Installation |  |  |  |
| Configuration |  |  |  |
| Validation |  |  |  |
| Transition |  |  |  |

**Rollback Plan:**

| Field | Value |
| --- | --- |
| **Rollback Triggers** | (What conditions cause you to roll back? DC01 CPU > X%? Authentication failures? Domain services degraded?) |
| **Rollback Procedure** | (Step-by-step: stop service, uninstall agent, verify DC01 returns to normal) |
| **Rollback Decision Authority** | (Who makes the call?) |
| **Maximum Time to Roll Back** |  |

**Success Criteria:**

| Criterion | Measurement | Target |
| --- | --- | --- |
| Windows Event Logs appearing in Elasticsearch | Query Elasticsearch for winlogbeat index | Events visible within 5 minutes of deployment |
| DC01 performance not degraded | CPU/memory comparison pre/post | < 5% CPU increase |
| No impact to Active Directory services | AD authentication functions normally | Zero authentication failures caused by deployment |
| CSSP log feed not disrupted | Existing log sources still forwarding | All pre-existing sources verified |

**Risks and Mitigations:**

| Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- |
| Winlogbeat consumes excessive DC01 resources |  |  |  |
| Agent installation requires reboot, disrupting AD |  |  |  |
| (Identify one additional risk) |  |  |  |

### Step 1.4: Change Management Record

Complete the change request per Section 18.2.4:

| Field | Value |
| --- | --- |
| **Change ID** | CR-[date]-001 |
| **Date Submitted** |  |
| **Requested By** |  |
| **Change Description** |  |
| **Justification** | (Why is this change needed? Reference operational requirement for endpoint visibility) |
| **Affected Systems** |  |
| **Risk Assessment** | Low / Medium / High — Justify |
| **Implementation Plan** | (Reference deployment plan above) |
| **Rollback Plan** | (Reference rollback plan above) |
| **Testing Completed** | (Reference Lab 17A if applicable, or note testing to be performed during deployment) |
| **CAB Approval** | ☐ Approved ☐ Denied — Date: |

### Knowledge Check: Stakeholder Coordination

1. The System Administrator for DC01 says the Domain Controller “cannot have any additional software installed without a 30-day review period.” Your leadership wants the deployment completed this week. What is the correct course of action?
    1. Install it anyway during off-hours — the System Administrator won’t notice
    2. Bypass the System Administrator and get leadership to override the policy
    3. **Coordinate with both the System Administrator and leadership to either expedite the review process through proper channels or adjust the timeline — the System Administrator’s policy exists to protect the Domain Controller (a critical asset), and bypassing it creates risk to Active Directory services and undermines the coordination relationship needed for ongoing support**
    4. Cancel the deployment entirely
    
    💡
    This scenario illustrates why stakeholder coordination is not a formality. The System Administrator manages the Domain Controller — the most critical authentication infrastructure on the network. Their review policy exists because changes to DCs can break Active Directory for every user on the domain. The correct approach coordinates between stakeholders to find a path that satisfies both the operational timeline and the change management requirements. Bypassing the process creates both technical risk and relationship damage that will complicate every future deployment.
    

---

## Exercise 2: Deployment Execution and Validation

**Estimated Time:** 75 minutes
**ELO Mapping:** 18A.2
**KSAT Coverage:** T2772, T5090

### Background

With the deployment plan and stakeholder coordination from Exercise 1 complete, this exercise executes the deployment. You will capture baseline performance metrics, install and configure the log forwarder, validate functionality, and measure post-deployment performance impact. This follows the implementation workflow from Section 18.2.2.

### Step 2.1: Pre-Deployment Baseline

Capture baseline measurements on both the SIEM server and the target system **before** making any changes.

**SIEM Server (Elastic Stack) Baseline:**

```bash
# Elasticsearch health and current indices
curl -s "http://localhost:9200/_cluster/health?pretty" 2>/dev/null | head -10
curl -s "http://localhost:9200/_cat/indices?v" 2>/dev/null

# Current resource usage
echo "=== SIEM BASELINE ===" > /tmp/siem_baseline.txt
date >> /tmp/siem_baseline.txt
top -bn1 | head -5 >> /tmp/siem_baseline.txt
free -h >> /tmp/siem_baseline.txt
df -h / /var >> /tmp/siem_baseline.txt
cat /tmp/siem_baseline.txt
```

| SIEM Metric | Baseline Value |
| --- | --- |
| Elasticsearch cluster status |  |
| Number of existing indices |  |
| CPU usage (%) |  |
| Memory used / total |  |
| Disk usage (/var) |  |

**Target System Baseline (DC01 or Ubuntu alternative):**

For **Windows DC01** (run in PowerShell):

```powershell
# System performance
Get-Counter '\Processor(_Total)\% Processor Time','\Memory\Available MBytes' -SampleInterval 2 -MaxSamples 3
# Disk space
Get-PSDrive C | Select-Object Used, Free
# Verify AD services running
Get-Service NTDS, DNS, Netlogon | Select-Object Name, Status
```

For **Ubuntu alternative** (if no Windows DC):

```bash
echo "=== TARGET BASELINE ===" > /tmp/target_baseline.txt
date >> /tmp/target_baseline.txt
top -bn1 | head -5 >> /tmp/target_baseline.txt
free -h >> /tmp/target_baseline.txt
df -h / >> /tmp/target_baseline.txt
systemctl is-active ssh syslog 2>/dev/null >> /tmp/target_baseline.txt
cat /tmp/target_baseline.txt
```

| Target System Metric | Baseline Value |
| --- | --- |
| CPU usage (%) |  |
| Available memory |  |
| Disk free space |  |
| Critical services status |  |

### Step 2.2: Pre-Deployment Checklist

Complete the checklist before proceeding. If any item fails, stop and resolve before continuing.

- [ ]  Deployment plan from Exercise 1 complete
- [ ]  Maintenance window confirmed (for this lab, you are the approver)
- [ ]  Stakeholder notifications sent (documented in Exercise 1)
- [ ]  Baseline measurements captured (Step 2.1)
- [ ]  Rollback procedure understood
- [ ]  Elasticsearch accessible and healthy

### Step 2.3: Execute Deployment

**Option A: Filebeat on Ubuntu (if no Windows DC available)**

```bash
# Step 1: Install Filebeat
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.12.0-amd64.deb 2>/dev/null || \
  sudo apt-get install -y filebeat 2>/dev/null

sudo dpkg -i filebeat-8.12.0-amd64.deb 2>/dev/null

# Step 2: Configure Filebeat to forward auth logs (simulating DC event logs)
sudo tee /etc/filebeat/filebeat.yml << 'EOF'
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/auth.log
      - /var/log/syslog
    fields:
      log_source: "deployment_exercise"
      system_role: "authentication_server"

output.elasticsearch:
  hosts: ["localhost:9200"]
  index: "deployment-exercise-%{+yyyy.MM.dd}"

setup.ilm.enabled: false
setup.template.name: "deployment-exercise"
setup.template.pattern: "deployment-exercise-*"
EOF

# Step 3: Start the service
sudo systemctl enable filebeat
sudo systemctl start filebeat

# Step 4: Verify service running
systemctl status filebeat | head -10
```

**Option B: Winlogbeat on Windows DC01** (run in elevated PowerShell)

```powershell
# Step 1: Download and extract Winlogbeat
Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.12.0-windows-x86_64.zip" -OutFile "$env:TEMP\winlogbeat.zip"
Expand-Archive "$env:TEMP\winlogbeat.zip" -DestinationPath "C:\Program Files"

# Step 2: Configure Winlogbeat
$config = @"
winlogbeat.event_logs:
  - name: Security
  - name: System
  - name: Application

output.elasticsearch:
  hosts: ["192.168.10.50:9200"]
  index: "winlogbeat-%{+yyyy.MM.dd}"

setup.ilm.enabled: false
setup.template.name: "winlogbeat"
setup.template.pattern: "winlogbeat-*"
"@
Set-Content "C:\Program Files\winlogbeat-8.12.0-windows-x86_64\winlogbeat.yml" $config

# Step 3: Install and start service
cd "C:\Program Files\winlogbeat-8.12.0-windows-x86_64"
.\install-service-winlogbeat.ps1
Start-Service winlogbeat
Get-Service winlogbeat
```

**Record deployment execution:**

| Step | Start Time | Status | Notes |
| --- | --- | --- | --- |
| Agent installation |  | ☐ Complete ☐ Failed |  |
| Configuration applied |  | ☐ Complete ☐ Failed |  |
| Service started |  | ☐ Complete ☐ Failed |  |
| Service verified running |  | ☐ Complete ☐ Failed |  |

**If any step fails, consult the rollback plan from Exercise 1 and determine if rollback is triggered.**

### Step 2.4: Validation Testing

Verify the deployment meets the success criteria from the deployment plan.

**Test 1: Log Ingestion Verification**

```bash
# Wait 60 seconds for initial data
sleep 60

# Check for new index in Elasticsearch
curl -s "http://localhost:9200/_cat/indices?v" | grep -E "deployment-exercise|winlogbeat"

# Query for recent events
curl -s "http://localhost:9200/deployment-exercise-*/_count" 2>/dev/null || \
  curl -s "http://localhost:9200/winlogbeat-*/_count" 2>/dev/null

# View sample events
curl -s "http://localhost:9200/deployment-exercise-*/_search?size=3&pretty" 2>/dev/null | head -30 || \
  curl -s "http://localhost:9200/winlogbeat-*/_search?size=3&pretty" 2>/dev/null | head -30
```

| Validation Test | Expected | Actual | Pass/Fail |
| --- | --- | --- | --- |
| New index created in Elasticsearch | Index visible in `_cat/indices` |  |  |
| Events being ingested | Document count > 0 |  |  |
| Events contain expected fields | Auth/security events with timestamp, source |  |  |
| Existing log sources unaffected | Pre-existing indices still receiving data |  |  |

**Test 2: Target System Health Check**

For **Ubuntu:**

```bash
# Post-deployment resource check
echo "=== POST-DEPLOYMENT ===" > /tmp/target_postdeploy.txt
date >> /tmp/target_postdeploy.txt
top -bn1 | head -5 >> /tmp/target_postdeploy.txt
free -h >> /tmp/target_postdeploy.txt
ps aux | grep filebeat | grep -v grep >> /tmp/target_postdeploy.txt
systemctl is-active ssh syslog 2>/dev/null >> /tmp/target_postdeploy.txt
cat /tmp/target_postdeploy.txt
```

For **Windows DC01:**

```powershell
Get-Counter '\Processor(_Total)\% Processor Time','\Memory\Available MBytes' -SampleInterval 2 -MaxSamples 3
Get-Service NTDS, DNS, Netlogon | Select-Object Name, Status
Get-Process winlogbeat | Select-Object CPU, WorkingSet
```

| Target System Metric | Baseline (Step 2.1) | Post-Deployment | Delta | Acceptable? |
| --- | --- | --- | --- | --- |
| CPU usage (%) |  |  |  | Yes / No |
| Available memory |  |  |  | Yes / No |
| Critical services status |  |  |  | Yes / No |
| Agent memory usage | N/A |  |  | Yes / No |

**Test 3: SIEM Server Health Check**

```bash
# Post-deployment SIEM check
curl -s "http://localhost:9200/_cluster/health?pretty" 2>/dev/null | head -5
echo "=== SIEM POST-DEPLOYMENT ===" > /tmp/siem_postdeploy.txt
date >> /tmp/siem_postdeploy.txt
top -bn1 | head -5 >> /tmp/siem_postdeploy.txt
free -h >> /tmp/siem_postdeploy.txt
df -h / /var >> /tmp/siem_postdeploy.txt
cat /tmp/siem_postdeploy.txt
```

| SIEM Metric | Baseline | Post-Deployment | Delta | Acceptable? |
| --- | --- | --- | --- | --- |
| Cluster status |  |  |  | Yes / No |
| CPU usage (%) |  |  |  | Yes / No |
| Memory used |  |  |  | Yes / No |
| Disk usage (/var) |  |  |  | Yes / No |

### Step 2.5: Complete Change Record

Update the change management record from Exercise 1 Step 1.4:

| Field | Value |
| --- | --- |
| **Implementation Date/Time** |  |
| **Implementation Result** | ☐ Success ☐ Partial ☐ Failed |
| **Rollback Required** | ☐ Yes ☐ No |
| **Issues Encountered** |  |
| **Resolutions Applied** |  |
| **Validation Passed** | ☐ Yes ☐ No |
| **Post-Deployment Actions** | ☐ Stakeholders notified ☐ Documentation updated ☐ Support transition initiated |

**Capture screenshots of validation test results and post-deployment measurements.**

### Knowledge Check: Deployment Execution

1. During Filebeat/Winlogbeat deployment, the target system’s CPU spikes to 95% and Active Directory authentication slows noticeably. The spike has lasted 3 minutes. Your rollback trigger says “> 80% CPU for 5 minutes.” What do you do?
    1. Immediately roll back — the system is degraded
    2. Ignore it — the rollback trigger hasn’t been met yet
    3. **Monitor actively and prepare to roll back — the trigger hasn’t been met (3 min < 5 min threshold), but you should be ready to execute the rollback procedure immediately if the condition persists, while also checking whether the spike is initial indexing activity that will subside versus a sustained resource problem**
    4. Increase the rollback threshold to 95% so you don’t have to roll back
    
    💡
    Rollback triggers exist to prevent impulsive decisions and to prevent ignoring real problems. The threshold hasn’t been met, so an immediate rollback may be premature — initial log agent indexing often causes a temporary CPU spike that subsides once the backlog is processed. However, the CDISS should be actively monitoring, have the rollback procedure ready to execute, and be communicating status to stakeholders. If the spike reaches the 5-minute mark, the rollback executes immediately — no further discussion. This is why rollback triggers must be specific and measurable, not subjective.
    

---

## Exercise 3: Impact Assessment and Critical Infrastructure Analysis

**Estimated Time:** 45 minutes
**ELO Mapping:** 18A.3
**KSAT Coverage:** T5090, T0960

### Background

With the deployment complete, this exercise assesses the full impact of the implementation across all five dimensions from Section 18.3 and performs the critical infrastructure analysis from Section 18.4. This analysis informs leadership on the deployment’s effect on operations, mission capability, and the organization’s critical asset posture.

### Step 3.1: Impact Assessment

Using the data collected during Exercise 2, complete the impact assessment:

**IMPACT ASSESSMENT — Windows Event Log Forwarding to SIEM**

| Field | Value |
| --- | --- |
| **Date** |  |
| **Assessor** |  |
| **Implementation** | Filebeat/Winlogbeat deployment to forward event logs to Elastic Stack |

**Operational Impact:**

| Factor | Assessment |
| --- | --- |
| **Availability** | Was there any system downtime? If so, how long? |
| **Functionality** | Were any existing capabilities affected? Did Active Directory / SSH continue to function normally? |
| **Processes** | Do any operational procedures need to change? (e.g., who monitors the new log source, who responds to new alert types?) |
| **Users** | Were end users affected? |
| **Support** | Does the help desk need to know about this change? |
| **Overall Operational Impact** | ☐ Minimal ☐ Moderate ☐ Significant ☐ Severe |

**Performance Impact** (transfer from Exercise 2 measurements):

| System | Metric | Baseline | Post-Deploy | Delta | Acceptable? |
| --- | --- | --- | --- | --- | --- |
| Target (DC01/Ubuntu) | CPU % |  |  |  |  |
| Target (DC01/Ubuntu) | Memory |  |  |  |  |
| SIEM Server | CPU % |  |  |  |  |
| SIEM Server | Disk usage |  |  |  |  |
| SIEM Server | Cluster health |  |  |  |  |

**Estimated daily log volume increase:** ______ (Check index size after 1 hour, extrapolate to 24 hours. This affects disk capacity planning.)

```bash
# Check new index size
curl -s "http://localhost:9200/_cat/indices?v&h=index,docs.count,store.size" | grep -E "deployment-exercise|winlogbeat"
```

**Mission Impact:**

| Factor | Assessment |
| --- | --- |
| **Mission Essential Functions** | Does this deployment affect any MEFs? (Authentication services, network operations, command and control?) |
| **Task Critical Assets** | Is the DC01 a TCA? If so, what tier? Was its availability or functionality affected? |
| **MRT-C** | Does the SIEM now qualify as MRT-C (or higher criticality MRT-C) because it ingests authentication data from a TCA? Does MRT-C mapping need to be updated? |
| **Operational Readiness** | Is the organization’s cyber defense readiness improved, degraded, or unchanged? |
| **Overall Mission Impact** | ☐ Positive (improved visibility) ☐ Neutral ☐ Negative (degradation) |

**Security Impact:**

| Factor | Assessment |
| --- | --- |
| **Security Posture Improvement** | What new detection capabilities does this provide? (Failed logon visibility, privilege escalation detection, account lockout monitoring?) |
| **Risk Reduction** | What specific risks are reduced by having Windows Event Logs in the SIEM? |
| **New Risks Introduced** | Does the log forwarder create any new attack surface? (Agent running on DC, network traffic from DC to SIEM, credentials for Elasticsearch connection?) |
| **Compliance** | Does this support any compliance requirements? (Audit logging per NIST 800-53 AU family?) |
| **Net Security Impact** | ☐ Positive ☐ Neutral ☐ Negative |

**Resource Impact:**

| Factor | Assessment |
| --- | --- |
| **Personnel** | Who maintains the agent? Who tunes alerts from the new data? |
| **Budget** | Additional licensing costs? (Elastic OSS = $0, but what about storage hardware for increased log volume?) |
| **Equipment** | Additional disk space needed for SIEM? Estimated growth rate? |
| **Sustainability** | What ongoing maintenance is required? (Agent updates, Elasticsearch index lifecycle management, storage expansion?) |

### Step 3.2: Critical Infrastructure Analysis

Analyze the critical infrastructure implications of this deployment using the asset hierarchy from Section 18.4.

**Asset Criticality Assessment:**

| Asset | Mission Supported | TCA Tier | Current Protection Priority |
| --- | --- | --- | --- |
| Domain Controller (DC01) | Authentication for all users, Group Policy enforcement | (Tier 1 / 2 / 3 — justify) |  |
| Elastic Stack (SIEM) | Centralized security monitoring, incident detection | (Tier 1 / 2 / 3 — justify) |  |
| Suricata IDS | Network intrusion detection | (Tier 1 / 2 / 3 — justify) |  |
| Network Firewall/Router | Network boundary defense, traffic control | (Tier 1 / 2 / 3 — justify) |  |

**Criticality-Threat-Vulnerability Assessment** (per CWP 3-33.4 methodology):

For the **Domain Controller (DC01)**:

| Factor | Assessment |
| --- | --- |
| **Criticality** | (How critical is DC01 to mission? What happens if it is incapacitated?) |
| **Threat** | (What adversary activity targets Domain Controllers? Reference MITRE ATT&CK: T1078 Valid Accounts, T1003 Credential Dumping, T1021 Lateral Movement) |
| **Vulnerability** | (What vulnerabilities exist? Is the new Winlogbeat agent a new vulnerability? Is the Elasticsearch connection encrypted?) |
| **Risk** | (Criticality × Threat × Vulnerability = what risk level?) |
| **Protection Priority** | P1 / P2 / P3 / P4 |

For the **SIEM (Elastic Stack)**:

| Factor | Assessment |
| --- | --- |
| **Criticality** | (Has criticality changed now that the SIEM ingests DC authentication logs? More valuable target for adversary?) |
| **Threat** | (What would an adversary gain by compromising or disabling the SIEM? Log tampering, detection evasion?) |
| **Vulnerability** | (Elasticsearch default configuration — is authentication enabled? Is the API exposed?) |
| **Risk** |  |
| **Protection Priority** | P1 / P2 / P3 / P4 |

**Protection Measures:**

| Asset | Protection Category | Specific Measures |
| --- | --- | --- |
| DC01 | Physical |  |
| DC01 | Logical | (Firewall rules, access controls, monitoring via the new SIEM integration?) |
| DC01 | Operational | (Patching, backup, change management — as exercised in this lab) |
| SIEM | Physical |  |
| SIEM | Logical | (Network segmentation, Elasticsearch authentication, TLS for agent connections?) |
| SIEM | Operational | (Index lifecycle management, backup, capacity monitoring) |

**MRT-C Mapping Update:**

| Question | Response |
| --- | --- |
| Does this deployment create new MRT-C? | (Does the log forwarding pipeline itself become MRT-C?) |
| Does it change existing MRT-C criticality? | (Is the SIEM more critical now with DC data?) |
| Are new dependencies created? | (SIEM now depends on DC01 agent health; DC01 now has network dependency to SIEM) |
| Does MRT-C mapping need to be updated? |  |
| Who needs to be notified of MRT-C changes? | (Reference JFHQ-DODIN coordination from Section 18.1.4) |

### Knowledge Check: Impact Assessment and Critical Infrastructure

1. After deploying the log forwarder, the SIEM now contains authentication logs from the Domain Controller, including failed logon attempts, privilege escalations, and account lockouts. An analyst asks: “Should we increase the SIEM’s TCA tier now that it has this data?” What is the correct analysis?
    1. No — the SIEM tier never changes because it’s not a “mission system”
    2. Yes — automatically elevate it to DCA because it has sensitive data
    3. **Evaluate based on mission impact: the SIEM’s criticality has increased because it now provides authentication visibility essential for detecting credential-based attacks; if loss of the SIEM would significantly degrade the ability to detect adversary activity against the DC (a likely TCA Tier 1 asset), then the SIEM’s TCA tier should be reviewed upward, and protection measures should be updated accordingly**
    4. Only the DC’s tier matters — the SIEM is just a supporting tool
    
    💡
    Critical asset tiers are not static labels. Per DODD 3020.40 and the criticality-threat-vulnerability methodology from CWP 3-33.4, asset criticality is assessed based on mission impact. When a SIEM begins ingesting authentication data from a Tier 1 TCA, its role in mission assurance increases — losing the SIEM now means losing visibility into attacks against the most critical authentication infrastructure. This is exactly the kind of change that triggers an MRT-C mapping update and a reassessment of protection priorities. The CDISS must think through these downstream effects for every deployment, not just whether the installation succeeded.
    

---

## Lab Completion Checklist

**Exercise 1 — Stakeholder Coordination and Deployment Planning:**
- [ ] Stakeholder matrix completed with all stakeholders identified
- [ ] System Administrator coordination process detailed for all five phases
- [ ] Communication plan completed with audience, message, channel, frequency
- [ ] Escalation procedures documented
- [ ] Deployment plan completed (scope, schedule, cutover, rollback, success criteria, risks)
- [ ] Change management record completed
- [ ] Knowledge check answered

**Exercise 2 — Deployment Execution and Validation:**
- [ ] Pre-deployment baselines captured (SIEM server and target system)
- [ ] Pre-deployment checklist completed — all items verified
- [ ] Agent installed and configured
- [ ] Service started and verified running
- [ ] Log ingestion verified in Elasticsearch
- [ ] Target system health confirmed (services running, CPU/memory acceptable)
- [ ] SIEM health confirmed (cluster status, resource usage acceptable)
- [ ] Performance comparison (baseline vs. post-deployment) documented
- [ ] Change record updated with implementation result
- [ ] Screenshots captured
- [ ] Knowledge check answered

**Exercise 3 — Impact Assessment and Critical Infrastructure Analysis:**
- [ ] Operational impact assessed (availability, functionality, users, processes, support)
- [ ] Performance impact documented with baseline comparisons
- [ ] Mission impact assessed (MEFs, TCAs, MRT-C, operational readiness)
- [ ] Security impact assessed (improvements, new risks, compliance)
- [ ] Resource impact assessed (personnel, budget, equipment, sustainability)
- [ ] Asset criticality table completed with TCA tier justifications
- [ ] Criticality-Threat-Vulnerability assessment completed for DC01 and SIEM
- [ ] Protection measures identified per asset
- [ ] MRT-C mapping update analysis completed
- [ ] Knowledge check answered

---

## Troubleshooting Guide

| Symptom | Possible Cause | Resolution |
| --- | --- | --- |
| Filebeat won’t start | YAML indentation error in config | Run `filebeat test config -c /etc/filebeat/filebeat.yml` to validate |
| No new index in Elasticsearch | Filebeat can’t reach Elasticsearch | Check `curl localhost:9200` from the agent host; check firewall rules |
| Index created but zero documents | Input paths don’t match actual log locations | Verify paths in filebeat.yml match actual log file locations with `ls -la /var/log/auth.log` |
| Winlogbeat install fails | PowerShell execution policy blocks script | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` |
| Elasticsearch cluster yellow/red | New index created with replica shards on single-node cluster | Set replicas to 0: `curl -X PUT "localhost:9200/deployment-exercise-*/_settings" -H 'Content-Type: application/json' -d '{"number_of_replicas":0}'` |
| High CPU after deployment | Initial log backlog being processed | Wait 10 minutes; if CPU doesn’t decrease, check Filebeat harvester count and consider limiting with `harvester_limit` |

---

## Summary

In this lab you implemented and deployed a cyber defense infrastructure component by:

1. **Developing stakeholder coordination and deployment plans** by identifying internal and external stakeholders, detailing the System Administrator coordination process through all five phases, creating a communication plan with escalation procedures, and producing a deployment plan with cutover strategy, rollback triggers, success criteria, and a formal change management record
2. **Executing the deployment with measured impact** by capturing pre-deployment baselines on both the SIEM and target system, completing a pre-deployment checklist, installing and configuring a log forwarding agent, validating log ingestion in Elasticsearch, confirming target system and SIEM health post-deployment, and completing the change record with implementation results
3. **Conducting impact assessment and critical infrastructure analysis** by assessing operational, performance, mission, security, and resource impacts using measured data from the deployment, performing a criticality-threat-vulnerability analysis for the Domain Controller and SIEM, identifying protection measures, and evaluating MRT-C mapping updates triggered by the new log source dependency

These activities address KSAT T0393B (coordinating with system administrators) through the stakeholder coordination plan and System Administrator coordination process, T2772 (building, installing, configuring, and testing cyber defense hardware) through the agent deployment, configuration, and validation testing, T5090 (assessing implementation impact) through the five-dimension impact assessment with measured baseline comparisons, and T0960 (identifying and prioritizing critical infrastructure protection) through the asset criticality assessment, criticality-threat-vulnerability analysis, and MRT-C mapping evaluation.

---

*Document Version: 1.0Classification: UNCLASSIFIED // FOR TRAINING USE ONLY*