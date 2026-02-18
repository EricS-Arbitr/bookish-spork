# CDISS Content Analysis: KSAT Coverage and Bloat Assessment

**Date:** 2026-02-17
**Scope:** All CDISS course lessons and labs, evaluated against Cyber Defense Infrastructure Support Specialist KSATs
**Purpose:** Identify KSAT coverage gaps, content redundancy, bloat, and quality issues

---

## Executive Summary

The CDISS course content is well-structured and broadly covers the required KSATs for the Cyber Defense Infrastructure Support Specialist work role. The labs are consistently strong -- realistic, hands-on, and directly aligned to the work role. The primary areas of concern are:

1. **Redundancy across lessons** -- several topics are taught in multiple lessons without clear cross-referencing, inflating total content
2. **Lesson conclusion sections** -- every lesson restates its entire body in a lengthy "Key Takeaways" section, adding ~100-130 lines of duplicated content per lesson
3. **Prerequisite re-teaching** -- Network+ level content is re-taught at depth despite being listed as a prerequisite
4. **Incomplete deliverables** -- Module 1 Assessment is empty, LAB-183 has a copy-paste error, LAB-XX2 has TODO placeholders
5. **One KSAT gap** -- K1074A (transmission technologies) receives minimal coverage

Overall, the content meets the KSAT requirements. The recommendations below focus on reducing development and maintenance costs by eliminating redundancy and trimming content that exceeds the role's scope.

---

## 1. KSAT Coverage Analysis

### 1.1 Core Tasks -- Coverage Status

| DCWF # | Task Description | Status | Where Covered |
|--------|-----------------|--------|---------------|
| T0960 | Assist in identifying, prioritizing, and coordinating protection of critical cyber defense infrastructure and key resources | **COVERED** | Lesson 18 (Section 18.4), Lab 18A (Exercise 3) |
| T2772 | Build, install, configure, and test dedicated cyber defense hardware | **COVERED** | Labs throughout Module 2 (Sysmon, Wazuh, Arkime, Defender, Zeek, Suricata, VPN, Hardening), Lab 17A, Lab 18A |
| T5090 | Assist in assessing the impact of implementing and sustaining a dedicated cyber defense infrastructure | **COVERED** | Lesson 18 (Section 18.3), Lab 18A (Exercise 3) |
| T0393B | Coordinate with system administrators to create cyber defense tools, test beds, and evaluate applications | **COVERED** | Lesson 17 (Section 17.2), Lesson 18 (Section 18.1), Lab 17A (Exercise 1), Lab 18A (Exercise 1) |
| T0643A | Identify potential conflicts with implementation of any cyber defense tools | **COVERED** | Lesson 17 (Section 17.4), Lab 17A (Exercise 3) |
| T0654B | Implement RMF requirements for dedicated cyber defense systems | **COVERED** | Lesson 11 (RMF), Lab 11A |
| T0471 (Additional) | Coordinate updating of rules and signatures for specialized cyber defense applications | **COVERED** | Lesson 8, Suricata Lab, Zeek Lab, Defender Lab |
| T0769 (Additional) | Perform system administration on specialized cyber defense applications and systems | **COVERED** | All Module 2 labs, Backup Lab |
| T0481A (Additional) | Create, edit, and manage network access control lists | **COVERED** | Lesson 6, Access Controls Lab, Network Analysis Lab |

### 1.2 Core Knowledge/Skills/Abilities -- Coverage Status

| DCWF # | KSA Description | Status | Where Covered |
|--------|----------------|--------|---------------|
| K0022 | Computer networking concepts, protocols, network security methodologies | **COVERED** | Lesson 3 (Network Infrastructure), Lesson 4 (Network Security Architecture) |
| K0108 | Risk management processes | **COVERED** | Lesson 11 (RMF) |
| K1157 | National and international laws, regulations, policies, ethics | **COVERED** | Lesson 1 (Section 1.4), Lesson 12 (Policies & Procedures) |
| K1158 | Cybersecurity principles | **COVERED** | Lesson 1 (Section 1.1) |
| K1159 | Cyber threats and vulnerabilities | **COVERED** | Lesson 1 (Section 1.2) |
| K6900 | Specific operational impacts of cybersecurity lapses | **COVERED** | Lesson 1 (Section 1.3) |
| K6935 | Cloud computing service models (SaaS, IaaS, PaaS) | **COVERED** | Lesson 13 (Section 13.1) |
| K6938 | Cloud computing deployment models | **COVERED** | Lesson 13 (Section 13.1) |
| K0049 | Host/network access control mechanisms | **COVERED** | Lesson 6, Access Controls Lab |
| K0061 | Incident response and handling methodologies | **COVERED** | Lesson 1, Lesson 13 (Section 13.5) |
| K0063 | Cybersecurity principles and organizational requirements (CIA, authentication, non-repudiation) | **COVERED** | Lesson 1 (Section 1.1) |
| K0148 | VPN security | **COVERED** | Lesson 8 (Section 8.4), VPN Lab |
| K0150 | What constitutes a network attack and relationship to threats/vulnerabilities | **COVERED** | Lesson 1 (Section 1.2), Lesson 3 (Section 3.2) |
| K0984 | Cyber defense policies, procedures, and regulations | **COVERED** | Lesson 12 (Policies & Procedures) |
| K1072 | Network security architecture concepts (topology, protocols, defense-in-depth, Zero Trust) | **COVERED** | Lesson 4 (Network Security Architecture) |
| S6700 | Troubleshooting and diagnosing cyber defense infrastructure anomalies | **COVERED** | Lab troubleshooting guides throughout, Lesson 17 (Section 17.4) |
| K1012A | Test procedures, principles, and methodologies (CMMI) | **COVERED** | Lesson 17 (Sections 17.1-17.2) |
| K0059A | IDS/IPS tools and applications | **COVERED** | Lesson 7, Lesson 8, Suricata Lab, Zeek Lab, Wazuh Lab |
| K0081A | Network protocols (TCP/IP, DHCP, DNS, directory services) | **COVERED** | Lesson 3 (Section 3.2) |
| K0087A | Network traffic analysis | **COVERED** | Lesson 3 (Section 3.3), Zeek Lab, Arkime Lab, Network Analysis Lab |
| K0092B | How traffic flows across the network (TCP, IP, OSI) | **COVERED** | Lesson 3 (Section 3.1) |

### 1.3 Additional Knowledge/Skills/Abilities -- Coverage Status

| DCWF # | KSA Description | Status | Where Covered |
|--------|----------------|--------|---------------|
| K0029 | Data backup, types of backups, and recovery concepts | **COVERED** | Lesson 10, Backup Lab |
| K0093 | Packet-level analysis | **COVERED** | Arkime Lab, Network Analysis Lab |
| S0157 | Applying host/network access controls | **COVERED** | Access Controls Lab |
| S0227 | Tuning sensors | **COVERED** | Suricata Lab (Part 7), Wazuh Lab (Part 5) |
| S0229 | Using incident handling methodologies | **COVERED** | Lesson 1, Lesson 13 (Section 13.5) |
| S0237 | Using VPN devices and encryption | **COVERED** | VPN Lab |
| S0893 | Securing network communications | **COVERED** | Lesson 9 (Section 9.4), Hardening Lab (Exercise 3) |
| S0896 | Protecting a network against malware | **COVERED** | Lesson 8 (Section 8.3), Defender Lab |
| K0900 | Web filtering technologies | **COVERED** | Lesson 8 (Section 8.5), VPN/Web Filtering Lab (Exercise 2) |
| K1125 | Cloud-based knowledge management technologies | **COVERED** | Lesson 13 (Section 13.1), Cloud Lab |
| K3143 | Basic system, network, and OS hardening techniques | **COVERED** | Lesson 9, Hardening Lab |
| K6210 | Cloud service models and possible limitations for incident response | **COVERED** | Lesson 13 (Section 13.5) |
| S6670 | System, network, and OS hardening techniques | **COVERED** | Lesson 9, Hardening Lab |
| A6918 | Ability to apply cybersecurity strategy to cloud computing | **COVERED** | Lesson 13, Cloud Lab |
| A6919 | Ability to determine best cloud deployment model | **COVERED** | Lesson 13 (Section 13.3), Cloud Lab (Exercise 1) |
| S6942 | Designing or implementing cloud computing deployment models | **PARTIALLY COVERED** | Lesson 13 (Section 13.4), Cloud Lab -- no live cloud environment |
| S6945 | Migrating workloads to/from/among cloud service models | **PARTIALLY COVERED** | Lesson 13 (Section 13.4) -- covered as planning exercise only |
| K1074A | Knowledge of transmission records (Bluetooth, RFID, IR, Wi-Fi, paging, cellular, satellite, VoIP) and jamming techniques | **MINIMALLY COVERED** | Lesson 3 (Section 3.4) covers Wi-Fi, Bluetooth, RFID only |

### 1.4 KSAT Gap Summary

| Gap | Severity | Notes |
|-----|----------|-------|
| K1074A -- Transmission technologies | **Low** | Additional KSAT. Wi-Fi, Bluetooth, and RFID are covered. Satellite, VoIP, paging, cellular, IR, and jamming techniques are not addressed. |
| S6942/S6945 -- Cloud implementation/migration skills | **Low** | Additional KSATs. Covered conceptually but no live cloud lab exists. This is acknowledged as a constraint of the DoD training environment. |

---

## 2. Cross-Lesson Redundancy

These are cases where substantive content is duplicated across multiple lessons, inflating total student hours and increasing maintenance cost.

### 2.1 High-Impact Redundancies (recommend consolidation)

| Topic | Where It Appears | Recommendation |
|-------|-----------------|----------------|
| **Zero Trust Architecture** | Lesson 1 (Section 1.1.5, ~50 lines) AND Lesson 4 (Section 4.3, ~450 lines) | Trim Lesson 1 to 2-3 sentences with a forward reference to Lesson 4. |
| **Defense-in-Depth** | Lesson 1 (Section 1.1.4, ~70 lines including DoD boundary model) AND Lesson 4 (Section 4.2, ~500 lines) | Trim Lesson 1 to a brief introduction; defer the DoD boundary model and sensing matrix to Lesson 4. |
| **IDS vs. IPS fundamentals** | Lesson 6 (Section 6.2.5) AND Lesson 8 (Section 8.1) | Remove from Lesson 6 (Access Control). The full treatment belongs in Lesson 8 (Cyber Defense Tools). |
| **NIST publications and RMF concepts** | Lesson 11 (RMF, throughout) AND Lesson 12 (Policies, Sections 12.1.3 and 12.3) | Remove the NIST publication tables and POA&M management from Lesson 12; reference Lesson 11. |
| **Performance impact assessment** | Lesson 17 (Section 17.4.4) AND Lesson 18 (Section 18.3.3) | Consolidate into Lesson 18 (deployment context); reference from Lesson 17. |
| **MRT-C identification process** | Lesson 2 (DoD Framework, Section 2.5) AND Lesson 18 (Section 18.4) | Mark Lesson 2 as the primary source; Lesson 18 should reference back rather than re-explain. |

### 2.2 Medium-Impact Redundancies (acceptable but worth noting)

| Topic | Where It Appears | Notes |
|-------|-----------------|-------|
| CWP 3-2.1 Sensing Capabilities matrix | Lesson 4 (Section 4.2.4) and Lesson 7 (Sensing) | Different framing (architecture vs. operations) makes both presentations useful, but the matrix itself appears twice. |
| Filebeat module configuration | Zeek Lab, Suricata Lab, VPN Lab (optional), Defender Lab, Wazuh Lab | Structurally identical steps repeated. Consider a reusable reference procedure. |
| Kibana visualization creation | Zeek Lab, Suricata Lab, Arkime Lab, Defender Lab, Sysmon Lab | Same procedural pattern (create Lens, configure, save, build dashboard) repeated across labs. Provides practice but may cause fatigue. |
| Evidence collection commands | Lab 11A (Exercise 2) and Lab 12A (Exercise 4) | Some of the same Linux commands appear in both labs. Lab 12A acknowledges this. |

---

## 3. Bloat Assessment

### 3.1 Lesson Conclusion Sections

**Every lesson** includes a "Key Takeaways" conclusion that restates the entire lesson body in paragraph or bullet form. Across all lessons, this accounts for approximately **1,300-1,500 lines** of purely duplicated content.

**Recommendation:** Replace with a brief (10-15 line) summary per lesson that highlights only the most critical points and forward references to the next lesson. The KSAT application table and "Bridge to the Next Lesson" sections are valuable and should be retained.

**Estimated savings:** ~1,000 lines across the course.

### 3.2 Prerequisite Content Re-Teaching

The following content re-teaches material explicitly listed as a prerequisite (Network+ equivalent):

| Content | Location | Issue |
|---------|----------|-------|
| OSI model 7-layer deep dive | Lesson 3, Section 3.1.1 | Full layer-by-layer walkthrough is Network+ material |
| TCP/IP 4-layer model | Lesson 3, Section 3.1.1 | Same |
| Subnetting and CIDR calculation | Lesson 3, Section 3.1.3 | Pure Network+ content |
| IPv4 address classes | Lesson 3, Section 3.1.3 | Explicitly noted as "largely historical" yet given a full table |

**Recommendation:** Condense Section 3.1 into a focused "security implications" review (~30% of current length). Retain the security-oriented analysis of each layer but remove the "how it works" fundamentals.

**Estimated savings:** ~300-400 lines from Lesson 3.

### 3.3 Content Exceeding Role Scope

These sections cover material at a depth that exceeds what a Cyber Defense Infrastructure Support Specialist needs:

| Content | Location | Issue | Recommendation |
|---------|----------|-------|----------------|
| Formal access control models (Bell-LaPadula, Biba) | Lesson 6, Section 6.1.2 | Mathematical models are academic, not operational. A CDISS implements MAC via SELinux or Windows MIC, not formal proofs. | Reduce to 1-2 paragraphs of awareness-level coverage. |
| Encryption algorithm comparison tables | Lesson 8, Section 8.4.4 | Detailed key-size/status comparisons for every algorithm is Security+ study material. | Retain only the DoD recommendation summary. |
| Malware type taxonomy (10 categories) | Lesson 8, Section 8.3.1 | Standard security awareness content. A CDISS deploys/manages AV tools, not classifies malware families. | Trim to a brief reference table; keep the behavioral indicators subsection. |
| Cloud model selection and migration (6 R's) | Lesson 13, Sections 13.3-13.4 | Architect/program-manager-level decisions. A CDISS operates within an already-selected environment. | Reduce to awareness level; focus on what a CDISS needs to operate in cloud environments. |
| National-level authorities catalog | Lesson 12, Section 12.1 | Listing all USC titles, Executive Orders, and PPDs is reference material, not applied knowledge. | Convert to a reference table in an appendix rather than lesson body. |
| CMMI maturity levels | Lesson 17, Section 17.1.4 | Process improvement framework for program management, not infrastructure support. | Remove or reduce to a brief mention. |
| Generic communication principles | Lesson 18, Section 18.1.5 | "Use clear language" and "communicate early and often" are not CDISS-specific. | Remove or drastically condense. |
| Generic requirements gathering | Lesson 18, Section 18.1.6 | Standard systems engineering content. | Condense to a single paragraph. |
| Crisis/contingency C2 relationships | Lesson 2, Section 2.4.4 | Operational-level concepts a CDISS would rarely apply directly. | Reduce to high-level awareness. |
| OCO details | Lesson 2, Section 2.3.4 | Lesson itself acknowledges this is not the CDISS focus. | Trim further. |

### 3.4 Knowledge Check Question Efficiency

Lesson knowledge checks (as opposed to lab knowledge checks) follow a rigid pattern: three obviously wrong answers and one correct answer that lists every item from the preceding section. This tests rote recall, not comprehension or application.

By contrast, the lab knowledge checks present realistic decision-making scenarios (e.g., "You discover a route to production -- what do you do?") that test judgment.

**Recommendation:** Revise lesson knowledge checks to use scenario-based questions similar to the lab style. Reduce total count by ~30% by consolidating questions that test the same concept.

---

## 4. Quality Issues

### 4.1 Incomplete Content

| Issue | Location | Severity |
|-------|----------|----------|
| **Module 1 Assessment is empty** | `LAB-XX4 Module 1 Assessment` -- contains only a title, no content | **High** -- no summative assessment for the largest module |
| **Module 2 Assessment not present** | Referenced in course outline as "LAB: Module 2 Assessment" but no file exists | **High** -- no summative assessment |
| **Module 3 Assessment not present** | Referenced in course outline as "LAB: Module 3 Assessment" but no file exists | **High** -- no summative assessment |
| **Capstone not present** | Referenced in course outline as "CAPSTONE" but no file exists | **High** -- course culminating exercise missing |

### 4.2 Errors and Placeholders

| Issue | Location | Severity |
|-------|----------|----------|
| **Copy-paste error** | LAB-183, Task 1 -- references Jupyter Lab and `process_parquet.ipynb` for a CIA Triad analysis exercise | **Medium** -- confusing for self-paced learners |
| **TODO comments remain** | LAB-XX2 -- multiple TODO comments (e.g., "TODO accomplish with firewall role variable linux_firewall_rules", "Step 1.2: Configure the Windows Domain Controller (VM2) TODO") | **Medium** -- indicates incomplete lab automation |
| **Development GitHub URL** | LAB-XX3 -- references `https://github.com/uki-code/ukilrn-courses/blob/arbitr/dev-cameron/modules/labs/LAB-185/lab.json` | **Low** -- development reference should be removed for production |
| **Missing duration estimates** | Lessons 2, 3, 4 (DoD Framework, Network Infrastructure, Network Security Architecture) have no duration specified | **Low** -- needed for course scheduling |

### 4.3 Proctor Guide Duplication

The LAB-183 Proctor Guide (~1,058 lines) duplicates the entire Lab Manual (~245 lines) verbatim and adds answer keys. The proctor-specific content (answer keys) could be maintained as a supplement rather than a full duplication, reducing maintenance burden.

---

## 5. Estimated Course Duration

| Module | Lessons (reading) | Labs (hands-on) | Assessment | Total |
|--------|-------------------|------------------|------------|-------|
| Module 1 - Foundations | ~11-14 hours | ~17.5-19.5 hours | Not developed | ~28-34 hours |
| Module 2 - Technical Implementation | ~12-16 hours | ~26-35 hours | Not developed | ~38-51 hours |
| Module 3 - Governance and Compliance | ~8-10 hours | ~9-11 hours | Not developed | ~17-21 hours |
| Module 4 - Operations | ~6-8 hours | ~6-7 hours | N/A | ~12-15 hours |
| **Total** | **~37-48 hours** | **~58.5-72.5 hours** | **TBD** | **~95-121 hours** |

Module 2 is by far the largest module, accounting for roughly 40% of total course hours. This is appropriate given that it covers the core technical implementation skills of the work role.

---

## 6. Recommendations Summary

### Priority 1 -- Must Fix (quality issues affecting usability)

1. Fix the LAB-183 copy-paste error (Jupyter Lab / process_parquet.ipynb reference in Task 1)
2. Resolve TODO placeholders in LAB-XX2
3. Remove the development GitHub URL from LAB-XX3
4. Decide on Module Assessments (1, 2, 3) and Capstone -- develop or remove from outline

### Priority 2 -- Cost-Saving Consolidation (reduce development/maintenance burden)

5. Trim lesson conclusion "Key Takeaways" sections to brief summaries (~1,000 lines saved)
6. Consolidate the six high-impact redundancies identified in Section 2.1
7. Condense Lesson 3, Section 3.1 prerequisite re-teaching (~300-400 lines saved)
8. Reduce Lesson 12, Section 12.1 national-level authorities to a reference appendix

### Priority 3 -- Content Trimming (remove content exceeding role scope)

9. Trim items listed in Section 3.3 (formal models, encryption tables, malware taxonomy, cloud selection/migration depth, CMMI, generic communication/requirements content)
10. Reduce Lesson 13 cloud content to focus on operating within cloud environments rather than selecting/designing them

### Priority 4 -- Quality Improvements (improve learning efficiency)

11. Revise lesson knowledge checks to scenario-based format
12. Add duration estimates to lessons missing them
13. Restructure Proctor Guide to supplement (not duplicate) the Lab Manual

---

*End of Analysis*
