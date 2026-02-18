# LAB: Testing and Evaluation of Cyber Defense Infrastructure

Owner: Eric Starace
Last edited by: Eric Starace

# LAB: Testing and Evaluation of Cyber Defense Infrastructure

## Cyber Defense Infrastructure Support Specialist Course

| **Estimated Completion Time** | 3–3.5 hours |
| --- | --- |
| **Prerequisites** | Lesson 17 (Testing & Evaluation); Previous labs with Suricata and Elastic Stack installed |
| **Lab Type** | Hands-on tool testing, conflict identification, and documentation |
| **Classification** | UNCLASSIFIED // FOR TRAINING USE ONLY |

---

## Terminal Learning Objective

Test and evaluate cyber defense infrastructure by creating an isolated test environment, developing and executing a test plan for an IDS rule update, identifying and resolving conflicts, and producing a final test report with a deployment recommendation.

## Enabling Learning Objectives

| ELO | Objective |
| --- | --- |
| 17A.1 | Set up and verify an isolated test environment, documenting the configuration and confirming isolation from production systems |
| 17A.2 | Develop a test plan with objectives, scope, and test cases, then execute the tests against a live IDS and document results |
| 17A.3 | Identify resource, functional, configuration, or security conflicts introduced by the tested changes, resolve them, and produce a final test report with a deployment recommendation |

## KSAT Alignment

| KSAT ID | Type | Description |
| --- | --- | --- |
| K1012A | Knowledge (Core) | Knowledge of test procedures and methodologies |
| T0393B | Task (Core) | Coordinate with system administrators to create tools, test beds, and establish requirements |
| T2772 | Task (Core) | Build, install, configure, and test cyber defense hardware |
| T0643A | Task (Core) | Identify conflicts with cyber defense tool implementation |

---

## Lab Scenario

Your organization is preparing to deploy a Suricata IDS rule update that includes a new custom rule set targeting lateral movement techniques (MITRE ATT&CK T1021). Before pushing the update to the production sensor, you must test it in an isolated environment to verify detection capability, confirm integration with the centralized SIEM, identify any conflicts or performance impacts, and document your findings in a formal test report.

**Lab Environment:**

| System | Role | IP Address |
| --- | --- | --- |
| Ubuntu Server (YOURSERVER) | Suricata IDS / Test Target | 192.168.10.100 |
| Elastic Stack Host | SIEM (Elasticsearch + Kibana) | 192.168.10.50 (or local) |
| Additional VM or localhost | Traffic generation / Test client | 192.168.10.x |

> **Note:** This lab uses the Suricata and Elastic Stack infrastructure from previous labs. If Suricata is not installed, complete the installation steps from Lab 7D before proceeding. If Elastic is not available, adapt the SIEM integration steps to use local log file verification instead.
> 

---

## Exercise 1: Test Environment Setup and Verification

**Estimated Time:** 45 minutes
**ELO Mapping:** 17A.1
**KSAT Coverage:** T0393B, K1012A

### Background

Before any testing begins, the test environment must be documented and verified as isolated from production. This exercise applies the test environment concepts from Section 17.2 — confirming the environment is isolated, controlled, representative, documented, and restorable.

### Step 1.1: Document the Test Environment

Record the current state of your lab environment:

**Test Environment Documentation:**

| Field | Value |
| --- | --- |
| **Environment Name** |  |
| **Purpose** | IDS rule update testing prior to production deployment |
| **Date Created** | [Today’s date] |
| **Created By** | [Your name / role] |

**Network Configuration:**

| System | Hostname | IP Address | OS / Version | Role in Test |
| --- | --- | --- | --- | --- |
| IDS Server |  |  |  | Suricata IDS under test |
| SIEM |  |  |  | Log collection and alert verification |
| Test Client |  |  |  | Traffic generation |

### Step 1.2: Verify Isolation

Confirm the test environment is isolated from any production network. Run these checks and record results:

```bash
# Check routing table — verify no routes to production networks
ip route show

# Check for unexpected network interfaces
ip addr show

# Verify DNS configuration (should not point to production DNS)
cat /etc/resolv.conf

# Verify no active connections to production systems
ss -tunap | grep -v "127.0.0.1\|192.168.10\."

# Test that production networks are unreachable (adjust IP to a known production address)
ping -c 2 -W 2 10.0.0.1 2>&1 || echo "Production network unreachable - GOOD"
```

**Isolation Verification:**

| Check | Expected Result | Actual Result | Pass/Fail |
| --- | --- | --- | --- |
| No routes to production | Only test network routes present |  |  |
| No unexpected interfaces | Only test network interfaces |  |  |
| DNS isolated | Points to test or local DNS only |  |  |
| No production connections | No established connections outside test network |  |  |
| Production unreachable | Ping fails / timeout |  |  |

### Step 1.3: Create Baseline Snapshot

Before making any changes, capture the current system state so you can restore if needed:

```bash
# Record current Suricata configuration
cp /etc/suricata/suricata.yaml /tmp/suricata.yaml.baseline

# Record current rule set
ls -la /var/lib/suricata/rules/ > /tmp/rules_baseline.txt
wc -l /var/lib/suricata/rules/*.rules 2>/dev/null >> /tmp/rules_baseline.txt

# Record current system resource usage (baseline)
echo "=== BASELINE RESOURCE SNAPSHOT ===" > /tmp/baseline_resources.txt
date >> /tmp/baseline_resources.txt
echo "--- CPU ---" >> /tmp/baseline_resources.txt
top -bn1 | head -5 >> /tmp/baseline_resources.txt
echo "--- Memory ---" >> /tmp/baseline_resources.txt
free -h >> /tmp/baseline_resources.txt
echo "--- Disk ---" >> /tmp/baseline_resources.txt
df -h / /var/log >> /tmp/baseline_resources.txt
echo "--- Suricata Process ---" >> /tmp/baseline_resources.txt
ps aux | grep suricata | grep -v grep >> /tmp/baseline_resources.txt

# View baseline
cat /tmp/baseline_resources.txt
```

**Record baseline values:**

| Metric | Baseline Value |
| --- | --- |
| CPU usage (overall %) |  |
| Memory used / total |  |
| Disk usage (/) |  |
| Disk usage (/var/log) |  |
| Suricata memory (RSS) |  |
| Number of loaded rules |  |

### Step 1.4: Verify Suricata Operational Status

Confirm the IDS is functioning before introducing changes:

```bash
# Service status
systemctl status suricata

# Verify Suricata is processing traffic
tail -5 /var/log/suricata/stats.log 2>/dev/null

# Verify log output
tail -3 /var/log/suricata/eve.json 2>/dev/null | python3 -m json.tool 2>/dev/null | head -20

# Check current rule count
suricata --build-info 2>/dev/null | grep -i "rules" || \
  grep -c "^alert\|^drop\|^pass" /var/lib/suricata/rules/*.rules 2>/dev/null
```

**Record:** Is Suricata running, processing traffic, and generating logs? Document any issues before proceeding.

**Capture a screenshot of the completed environment documentation and isolation verification.**

### Knowledge Check: Test Environment

1. During test environment setup, you discover the test server has a route to 10.10.0.0/16, which is the production management network. What should you do?
    1. Proceed with testing — the route is probably not used
    2. Add a firewall rule to block traffic to that network
    3. **Remove the route before any testing begins and re-verify isolation — an unintended route to production means test traffic (including attack simulations) could reach production systems, and any results would not reflect a controlled environment**
    4. Document it as a known limitation and continue
    
    💡
    Test environment isolation is not optional. A route to production means generated attack traffic (ICMP floods, port scans, exploit simulations) could reach live systems. It also means production traffic could contaminate test results, making them unreliable. The route must be removed and isolation re-verified before testing begins. This is why isolation verification is a mandatory step, not a formality.
    

---

## Exercise 2: Test Plan Development and Execution

**Estimated Time:** 90 minutes
**ELO Mapping:** 17A.2
**KSAT Coverage:** K1012A, T2772

### Background

This exercise applies the test planning concepts from Section 17.1 and the tool testing procedures from Section 17.3. You will develop a test plan for the IDS rule update, write specific test cases, execute them against the live system, and document results. This follows the NIST SP 800-115 phases: Planning → Discovery → Attack (Execute) → Reporting.

### Step 2.1: Write the Test Plan

Complete the test plan for the Suricata rule update:

**TEST PLAN: Suricata Custom Rule Set — Lateral Movement Detection**

| Field | Value |
| --- | --- |
| **Plan Author** | [Your name] |
| **Date** | [Today’s date] |
| **System Under Test** | Suricata IDS at [IP address] |

**Objectives:**

| # | Objective | Success Criteria |
| --- | --- | --- |
| 1 | Verify the custom rule detects lateral movement traffic | Alert generated for SMB/RDP/SSH brute force patterns with correct SID, source, and destination |
| 2 | Verify the rule does not generate false positives on normal traffic | No alerts from standard administrative SSH/RDP sessions |
| 3 | Verify alerts forward to the SIEM correctly | Alerts appear in Elasticsearch/Kibana within 60 seconds of generation |
| 4 | Measure performance impact of the new rules | CPU increase < 10% over baseline; no packet drops |

**Scope:**

| In Scope | Out of Scope |
| --- | --- |
| Custom lateral movement rules | Existing production rule set tuning |
| Detection accuracy (true/false positive) | Full penetration testing |
| SIEM integration for new alerts | Kibana dashboard creation |
| Performance impact on test server | Multi-sensor deployment |

**Resources Required:**

| Resource | Detail |
| --- | --- |
| Personnel | 1 CDISS (tester) |
| Equipment | (List your lab systems from Exercise 1) |
| Time | ~90 minutes for execution |
| Tools | Suricata, hping3/nmap (traffic generation), Elastic Stack |

**Risks and Mitigations:**

| Risk | Mitigation |
| --- | --- |
| New rules crash Suricata | Baseline config backed up in Exercise 1; restore procedure tested |
| Test traffic triggers existing rules | Document which alerts are from test vs. existing rules using SID ranges |
| (Add one additional risk you identify) |  |

### Step 2.2: Create and Load the Custom Rules

Create a test rule file targeting lateral movement indicators:

```bash
# Create custom rule file
sudo tee /var/lib/suricata/rules/local-lateral-movement.rules << 'EOF'
# Custom Lateral Movement Detection Rules - TEST
# MITRE ATT&CK: T1021 (Remote Services)

# Detect rapid SSH connection attempts (possible brute force / lateral movement)
alert tcp any any -> any 22 (msg:"LOCAL - Rapid SSH Connection Attempts Detected"; \
  flow:to_server,established; threshold:type both, track by_src, count 5, seconds 60; \
  classtype:attempted-admin; sid:9000001; rev:1;)

# Detect SMB connection to non-standard destination (possible lateral movement)
alert tcp any any -> any 445 (msg:"LOCAL - SMB Connection to Server Detected"; \
  flow:to_server,established; classtype:policy-violation; sid:9000002; rev:1;)

# Detect RDP connection attempts
alert tcp any any -> any 3389 (msg:"LOCAL - RDP Connection Attempt Detected"; \
  flow:to_server,established; classtype:policy-violation; sid:9000003; rev:1;)
EOF

# Verify the rule file was created
cat /var/lib/suricata/rules/local-lateral-movement.rules

# Ensure the rule file is included in suricata.yaml
grep -q "local-lateral-movement.rules" /etc/suricata/suricata.yaml || \
  echo "  - local-lateral-movement.rules" | sudo tee -a /etc/suricata/suricata.yaml

# Reload Suricata rules (without restarting)
sudo suricatasc -c reload-rules 2>/dev/null || sudo systemctl reload suricata

# Verify new rules loaded
grep -c "9000" /var/log/suricata/suricata.log 2>/dev/null || \
  sudo suricatasc -c "rule-stats" 2>/dev/null
```

**Record:** Were the custom rules loaded successfully? How many total rules are now active?

### Step 2.3: Execute Test Cases

Execute each test case, record results, and assess pass/fail.

**TC-001: Detection Test — SSH Lateral Movement**

```bash
# Generate rapid SSH connection attempts (simulates lateral movement)
# From test client or localhost:
for i in $(seq 1 10); do
  ssh -o ConnectTimeout=1 -o StrictHostKeyChecking=no \
    testuser@192.168.10.100 exit 2>/dev/null &
done
wait

# Wait 10 seconds for processing
sleep 10

# Check for alert
grep "9000001" /var/log/suricata/eve.json | tail -3
```

| Field | Value |
| --- | --- |
| **Test ID** | TC-001 |
| **Objective** | Verify SID 9000001 fires on rapid SSH connections |
| **Expected Result** | Alert generated with correct SID, source IP, destination IP |
| **Actual Result** |  |
| **Pass/Fail** |  |
| **Notes** |  |

**TC-002: Detection Test — SMB Connection**

```bash
# Generate SMB traffic (using nmap or direct connection)
nmap -sT -p 445 192.168.10.100 2>/dev/null || \
  echo "Q" | timeout 5 openssl s_client -connect 192.168.10.100:445 2>/dev/null || \
  nc -zv 192.168.10.100 445 2>&1

sleep 5

# Check for alert
grep "9000002" /var/log/suricata/eve.json | tail -3
```

| Field | Value |
| --- | --- |
| **Test ID** | TC-002 |
| **Objective** | Verify SID 9000002 fires on SMB connections |
| **Expected Result** | Alert generated for port 445 traffic |
| **Actual Result** |  |
| **Pass/Fail** |  |
| **Notes** |  |

**TC-003: False Positive Test — Normal Administrative SSH**

```bash
# Generate a single normal SSH session (should NOT trigger SID 9000001 threshold)
ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
  testuser@192.168.10.100 "echo 'normal admin session'" 2>/dev/null

sleep 10

# Check that SID 9000001 did NOT fire for this single connection
# Look for alerts in the last 15 seconds only
grep "9000001" /var/log/suricata/eve.json | \
  python3 -c "import sys,json; [print(json.loads(l).get('timestamp','')) for l in sys.stdin]" 2>/dev/null | tail -3
```

| Field | Value |
| --- | --- |
| **Test ID** | TC-003 |
| **Objective** | Verify single SSH session does NOT trigger rapid-connection alert |
| **Expected Result** | No new SID 9000001 alert for the single connection |
| **Actual Result** |  |
| **Pass/Fail** |  |
| **Notes** |  |

**TC-004: SIEM Integration Test**

```bash
# Check that Suricata alerts are reaching Elasticsearch
# Option A: Query Elasticsearch directly
curl -s "http://localhost:9200/suricata-*/_search?q=alert.signature_id:9000001&size=3" 2>/dev/null | \
  python3 -m json.tool 2>/dev/null | head -30

# Option B: If Elasticsearch is not available, verify log file forwarding
ls -la /var/log/suricata/eve.json
grep -c "9000001\|9000002\|9000003" /var/log/suricata/eve.json
```

| Field | Value |
| --- | --- |
| **Test ID** | TC-004 |
| **Objective** | Verify alerts from custom rules appear in SIEM |
| **Expected Result** | Alerts searchable in Elasticsearch or present in forwarded logs |
| **Actual Result** |  |
| **Pass/Fail** |  |
| **Notes** | (Record latency if measurable — time between alert generation and SIEM visibility) |

**TC-005: Performance Impact Measurement**

```bash
# Capture resource usage WITH new rules loaded
echo "=== POST-RULE RESOURCE SNAPSHOT ===" > /tmp/postrule_resources.txt
date >> /tmp/postrule_resources.txt
echo "--- CPU ---" >> /tmp/postrule_resources.txt
top -bn1 | head -5 >> /tmp/postrule_resources.txt
echo "--- Memory ---" >> /tmp/postrule_resources.txt
free -h >> /tmp/postrule_resources.txt
echo "--- Suricata Process ---" >> /tmp/postrule_resources.txt
ps aux | grep suricata | grep -v grep >> /tmp/postrule_resources.txt
echo "--- Suricata Stats ---" >> /tmp/postrule_resources.txt
tail -20 /var/log/suricata/stats.log 2>/dev/null >> /tmp/postrule_resources.txt

# Compare to baseline
echo ""
echo "=== COMPARISON ==="
echo "Baseline:"
grep -A1 "CPU\|Memory\|Suricata Process" /tmp/baseline_resources.txt
echo ""
echo "After rules:"
grep -A1 "CPU\|Memory\|Suricata Process" /tmp/postrule_resources.txt

# Check for packet drops
grep -i "drop\|kernel_drops" /var/log/suricata/stats.log 2>/dev/null | tail -5
```

| Field | Value |
| --- | --- |
| **Test ID** | TC-005 |
| **Objective** | Measure CPU and memory impact of new rules |
| **Expected Result** | CPU increase < 10% over baseline; no packet drops |
| **Actual Result** |  |
| **CPU Delta** | Baseline: ***% → With rules:*** % = ___% increase |
| **Memory Delta** | Baseline: ___ → With rules: ___ |
| **Packet Drops** | Yes / No |
| **Pass/Fail** |  |
| **Notes** |  |

**Capture screenshots of each test case execution and results.**

### Knowledge Check: Tool Testing

1. TC-001 passes (alert fires correctly) but TC-003 fails — a single normal SSH session also triggers the alert. What type of testing failure is this, and what is the next step?
    1. Integration failure — fix the SIEM connection
    2. Hardware failure — increase server resources
    3. **False positive failure — the rule’s threshold is too sensitive; adjust the threshold parameters (increase count or decrease time window) in the rule, reload, and re-execute both TC-001 and TC-003 to verify the fix doesn’t break detection while eliminating the false positive**
    4. Performance failure — the rule is consuming too much CPU
    
    💡
    This is the core value of testing before production deployment. A rule that fires on both attack traffic (TC-001) and normal traffic (TC-003) would generate alert fatigue in production, burying real detections in noise. The fix requires adjusting the threshold and then re-running both the detection test AND the false positive test — changing the threshold to eliminate false positives might also eliminate true positives. This is why regression testing matters: every fix must be verified against all existing test cases, not just the one that failed.
    

---

## Exercise 3: Conflict Identification and Final Report

**Estimated Time:** 45 minutes
**ELO Mapping:** 17A.3
**KSAT Coverage:** T0643A, K1012A

### Background

This exercise applies the conflict identification process from Section 17.4. During testing, conflicts may have emerged — resource contention, false positives between tools, configuration issues, or functional interference. Whether or not obvious conflicts appeared in Exercise 2, this exercise walks through the systematic conflict discovery process and produces the final test report that determines whether the rule update is ready for production.

### Step 3.1: Systematic Conflict Check

Review the data collected during Exercise 2 and check for each conflict type:

**Resource Conflicts:**

```bash
# Check for port conflicts
sudo ss -tlnp | grep -E "suricata|elastic|kibana|filebeat"

# Check for disk I/O pressure from logging
iostat -x 1 3 2>/dev/null || echo "iostat not installed - check with: iotop or dstat"

# Check if Suricata and another tool compete for the same network interface
cat /etc/suricata/suricata.yaml | grep "interface:" | head -3
```

| Resource Conflict Check | Finding | Conflict? |
| --- | --- | --- |
| Port conflicts between tools |  | Yes / No |
| CPU contention (compare baseline vs. current) |  | Yes / No |
| Memory pressure |  | Yes / No |
| Disk I/O (log volume) |  | Yes / No |

**Functional Conflicts:**

```bash
# Check if another tool is also inspecting the same traffic
# (e.g., Wazuh and Suricata both processing the same packets)
ps aux | grep -E "suricata|wazuh|zeek|snort" | grep -v grep

# Check for duplicate alert processing
# If Wazuh is installed, check if it's also alerting on the same activity
grep "ssh\|SMB\|445\|22" /var/ossec/logs/alerts/alerts.json 2>/dev/null | tail -3
```

| Functional Conflict Check | Finding | Conflict? |
| --- | --- | --- |
| Multiple tools inspecting same traffic |  | Yes / No |
| Duplicate alerting for same event |  | Yes / No |
| Tool interfering with another’s traffic capture |  | Yes / No |

**Configuration Conflicts:**

```bash
# Check for Suricata configuration warnings
grep -i "warn\|error" /var/log/suricata/suricata.log 2>/dev/null | tail -10

# Check for rule conflicts (duplicate SIDs)
grep -h "^alert\|^drop" /var/lib/suricata/rules/*.rules 2>/dev/null | \
  grep -oP "sid:\K[0-9]+" | sort | uniq -d | head -5
```

| Configuration Conflict Check | Finding | Conflict? |
| --- | --- | --- |
| Configuration warnings/errors in logs |  | Yes / No |
| Duplicate SIDs across rule files |  | Yes / No |
| Version or dependency issues |  | Yes / No |

**Security Conflicts:**

```bash
# Check if the firewall is blocking Suricata's log forwarding
sudo ufw status 2>/dev/null | grep -E "9200|5044|5601"

# Check if Suricata alerts are triggering on its own log forwarding traffic
grep "9000" /var/log/suricata/eve.json | grep "9200\|5044" | tail -3
```

| Security Conflict Check | Finding | Conflict? |
| --- | --- | --- |
| Firewall blocking log forwarding |  | Yes / No |
| IDS alerting on its own SIEM traffic |  | Yes / No |
| Tool traffic generating false positives |  | Yes / No |

### Step 3.2: Document and Resolve Conflicts

For each conflict identified (or if none were found, document one hypothetical conflict from the scenario to practice the documentation process):

**Conflict Report:**

| Field | Value |
| --- | --- |
| **Conflict ID** | CON-001 |
| **Date Discovered** |  |
| **Tools Involved** |  |
| **Symptom** |  |
| **Discovery Method** | (Which check from Step 3.1 revealed it?) |
| **Conflict Type** | Resource / Functional / Configuration / Security |
| **Severity** | Critical / High / Medium / Low |
| **Root Cause** |  |
| **Impact on Operations** |  |
| **Resolution Strategy** | (Reconfiguration / Sequencing / Resource allocation / Replacement / Architecture change / Exclusion) |
| **Resolution Steps Taken** |  |
| **Verification** | (How did you confirm the resolution worked?) |

If a conflict was resolved, verify the fix:

```bash
# Re-run the relevant test case(s) to confirm resolution
# Example: if a false positive conflict was fixed by adjusting a threshold
grep "9000001" /var/log/suricata/eve.json | tail -5

# Verify no new issues introduced (regression check)
systemctl is-active suricata
tail -3 /var/log/suricata/eve.json 2>/dev/null | python3 -m json.tool 2>/dev/null | head -10
```

### Step 3.3: Produce the Final Test Report

Compile all findings into the final test report. This is the deliverable that a decision-maker uses to approve or reject the production deployment.

**FINAL TEST REPORT**

| Field | Value |
| --- | --- |
| **Report Date** |  |
| **Test Lead** | [Your name] |
| **System Under Test** | Suricata IDS — Custom Lateral Movement Rule Set |
| **Test Period** | [Start time] to [End time] |
| **Overall Recommendation** | ☐ Ready for Production ☐ Ready with Conditions ☐ Not Ready |

**Test Results Summary:**

| Test ID | Category | Description | Result | Notes |
| --- | --- | --- | --- | --- |
| TC-001 | Detection | SSH rapid connection alert | Pass / Fail |  |
| TC-002 | Detection | SMB connection alert | Pass / Fail |  |
| TC-003 | False Positive | Normal SSH no alert | Pass / Fail |  |
| TC-004 | Integration | SIEM alert visibility | Pass / Fail |  |
| TC-005 | Performance | Resource impact | Pass / Fail |  |

**Performance Assessment:**

| Metric | Baseline | With Rules | Delta | Acceptable? |
| --- | --- | --- | --- | --- |
| CPU % |  |  |  | Yes / No |
| Memory |  |  |  | Yes / No |
| Packet Drops |  |  |  | Yes / No |

**Conflicts and Resolutions:**

| Conflict ID | Description | Resolution | Verified? |
| --- | --- | --- | --- |
|  |  |  | ☐ Yes ☐ No |
|  |  |  | ☐ Yes ☐ No |

**Compatibility Matrix:**

| Tool A | Tool B | Compatible? | Notes |
| --- | --- | --- | --- |
| Suricata (new rules) | Elastic Stack |  |  |
| Suricata (new rules) | Wazuh (if installed) |  |  |
| Suricata (new rules) | UFW/iptables |  |  |

**Recommendations:**

*Before Production Deployment:*
1.
2.

*Post-Deployment Monitoring:*
1.
2.

**Approval:**

| Role | Name | Date | Signature |
| --- | --- | --- | --- |
| Test Lead |  |  |  |
| Reviewer (ISSO/Supervisor) |  |  |  |

### Knowledge Check: Conflict Identification

1. During conflict checking, you discover that Suricata’s SID 9000002 (SMB detection) fires every time Wazuh sends its alerts to Elasticsearch over port 445. This is flooding the SIEM with false positives. What conflict type is this, and which resolution strategy is most appropriate?
    1. Resource conflict — allocate more CPU to Suricata
    2. Configuration conflict — change Suricata to a newer version
    3. **Security conflict (tool traffic generating false positives) — apply an exclusion by adding a BPF filter or pass rule that exempts Wazuh’s source IP from SID 9000002, then re-test to verify the exclusion does not create a detection blind spot**
    4. Functional conflict — replace Wazuh with a different agent
    
    💡
    This is a security conflict where one tool’s normal operation triggers false alerts in another tool. The correct resolution is an exclusion — configure Suricata to pass (not alert on) traffic from Wazuh’s known IP to the Elasticsearch port. The critical follow-up is regression testing: verify the exclusion only exempts the specific traffic and does not create a blind spot where real SMB lateral movement from the Wazuh host would go undetected. This is why the resolution process always ends with verification.
    

---

## Lab Completion Checklist

**Exercise 1 — Test Environment Setup:**
- [ ] Environment documentation completed (systems, IPs, roles)
- [ ] Isolation verification performed and recorded (all checks pass)
- [ ] Baseline snapshot created (config backup, resource measurements)
- [ ] Suricata operational status confirmed
- [ ] Screenshots captured

**Exercise 2 — Test Plan and Execution:**
- [ ] Test plan completed (objectives, scope, resources, risks)
- [ ] Custom rules created and loaded into Suricata
- [ ] TC-001 (SSH detection) executed and documented
- [ ] TC-002 (SMB detection) executed and documented
- [ ] TC-003 (False positive) executed and documented
- [ ] TC-004 (SIEM integration) executed and documented
- [ ] TC-005 (Performance impact) executed and documented
- [ ] Screenshots of all test case results captured

**Exercise 3 — Conflict Identification and Report:**
- [ ] Resource conflict checks completed
- [ ] Functional conflict checks completed
- [ ] Configuration conflict checks completed
- [ ] Security conflict checks completed
- [ ] At least one conflict documented with full report fields
- [ ] Resolution implemented and verified (or hypothetical documented)
- [ ] Final test report completed with all sections
- [ ] Deployment recommendation made and justified
- [ ] Compatibility matrix completed

---

## Troubleshooting Guide

| Symptom | Possible Cause | Resolution |
| --- | --- | --- |
| Suricata won’t reload rules | Syntax error in custom rule file | Run `suricata -T` to test configuration; check `/var/log/suricata/suricata.log` for parse errors |
| No alerts generated for any test | Suricata not listening on correct interface | Check `af-packet` interface in `suricata.yaml`; verify with `suricatasc -c "iface-list"` |
| TC-001 doesn’t trigger | Threshold not met (connections too slow) | Increase the number of SSH attempts or reduce the threshold count in the rule |
| `suricatasc` command not found | Suricata socket not enabled | Add `unix-command: enabled: yes` to `suricata.yaml` and restart |
| Elasticsearch query fails | Elasticsearch not running or index doesn’t exist | Check with `curl http://localhost:9200/_cat/indices` |
| `hping3` / `nmap` not installed | Traffic generation tools missing | Install with `sudo apt install -y hping3 nmap` |
| Rule file not loaded | Not included in `suricata.yaml` rule-files list | Add `- local-lateral-movement.rules` under `rule-files:` section |

---

## Summary

In this lab you tested and evaluated cyber defense infrastructure by:

1. **Setting up and verifying an isolated test environment** by documenting the system configuration, confirming network isolation from production through systematic checks, capturing a baseline snapshot for rollback capability, and verifying the IDS was operational before introducing changes
2. **Developing and executing a test plan** with defined objectives, scope, resources, and risk mitigations, then executing five test cases covering detection accuracy (true positive and false positive), SIEM integration, and performance impact, with documented pass/fail results for each
3. **Identifying conflicts and producing a final test report** by systematically checking for resource, functional, configuration, and security conflicts, documenting findings with root cause analysis and resolution strategies, and compiling all results into a formal report with a production deployment recommendation

These activities address KSAT K1012A (test procedures and methodologies) through the test plan development and systematic test execution, T0393B (creating tools and test beds) through the environment setup and isolation verification, T2772 (building, installing, configuring, and testing cyber defense hardware) through the IDS rule installation, configuration, and validation testing, and T0643A (identifying conflicts) through the systematic conflict discovery process and resolution documentation.

---

*Document Version: 1.0Classification: UNCLASSIFIED // FOR TRAINING USE ONLY*