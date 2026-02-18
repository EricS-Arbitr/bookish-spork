# LAB-183: Cybersecurity Scenarios - Proctor Guide

Owner: Pete Hay
Last edited by: Wendy Schey

| **Lab ID (UUID)** | 7c557b39-656e-4cf8-9e5f-b0ebb544615c |
| --- | --- |
| **Lab Name** | Cybersecurity Scenarios |
| **Lab Directory (LAB-XXX)** | LAB-183 |
| **Duration (x.x)** | 3.5h |
| **JCT&CS KSATS** | K0063, K1159, K0150, K6900, K1157, T0960 |
| **Competencies (teaches)** |  |
| **Competencies (assesses)** |  |
| **Dependency (Tools, DB, etc.)** |  |
| **Web References** |  |
| **Terminal Learning Objectives (TLOs)** |  |
| **Enabling Learning Objectives (ELOs)** | CDISS 1.5, CDISS 1.6, CDISS 1.7, CDISS 1.8, CDISS 1.9 |
| **Lab Author** | Arbitr |

**This confluence page contains Controlled Unclassified Information (CUI) and must be handled within the protections of that data.**

---

# Cybersecurity Foundations

**Estimated Completion Time:** 3-4 hours

**Prerequisites:** Completion of Module 1 reading sections (1.1-1.4)

**Lab Type:** Scenario-based analysis and documentation exercises

---

## Lab Overview

This lab reinforces the foundational cybersecurity concepts covered in Module 1 through practical, scenario-based exercises. The learner will apply the CIA Triad, analyze threat actors, assess mission impacts, and work through ethical dilemmas relevant to DoD cyber defense operations.

### Lab Objectives

Upon completion of this lab, the learner will be able to:

1. Apply CIA Triad principles to analyze DoD system security requirements
2. Profile threat actors and assess their likely targets and methods
3. Conduct mission impact analysis for cyber incidents
4. Navigate ethical dilemmas in cybersecurity operations
5. Prioritize security efforts based on mission criticality

### KSAT Alignment

| KSAT ID | Description | Lab Exercise |
| --- | --- | --- |
| K0063 | Cybersecurity principles (CIA, authentication) | Exercise 1 |
| K1159 | Cyber threats and vulnerabilities | Exercise 2 |
| K0150 | Network attacks and threat/vulnerability relationship | Exercise 2 |
| K6900 | Operational impacts of cybersecurity lapses | Exercise 3 |
| K1157 | Laws, regulations, policies, ethics | Exercise 4 |
| T0960 | Assist in identifying, prioritizing critical infrastructure | Exercise 3, 5 |

### Required Materials

- Module 1 reading content
- Notepad or word processor for documentation
- Access to MITRE ATT&CK website (https://attack.mitre.org) - optional reference

---

## Task 1: CIA Triad Analysis

**Estimated Time:** 30-40 minutes

### Objective

Apply CIA Triad principles to analyze three DoD scenarios, determining which security properties are most critical and what controls should be implemented.

### Background

The CIA Triad—Confidentiality, Integrity, and Availability—provides the foundation for analyzing security requirements. Different mission contexts prioritize these properties differently. Understanding these trade-offs is essential for Cyber Defense Infrastructure Support Specialists.

### Instructions

For each scenario below, the learner should complete the analysis worksheet. The learner should consider the mission context, potential threats, and operational requirements.

---

### Task 1A: Intelligence Database

**Description:**

An intelligence database contains information about enemy force positions, capabilities, and intentions. The database is accessed by analysts at multiple locations worldwide via classified networks. Analysts use this information to brief commanders and develop operational recommendations.

**Analysis Questions:**

1. **Primary CIA Property:** Which property (Confidentiality, Integrity, or Availability) is MOST critical for this system? Explain the reasoning.
    
    ```
    Answer:
    
    ```
    
2. **Top Three Threats:** Identify the three most significant threats to this system.
    
    
    | Threat | CIA Property Affected | Likelihood (H/M/L) |
    | --- | --- | --- |
    | 1. |  |  |
    | 2. |  |  |
    | 3. |  |  |
3. **Recommended Controls:** List three controls the CDISS would implement, specifying which CIA property each protects.
    
    
    | Control | CIA Property Protected | Implementation Priority |
    | --- | --- | --- |
    | 1. |  |  |
    | 2. |  |  |
    | 3. |  |  |
4. **Trade-offs:** What trade-offs exist between CIA properties for this system? For example, how might maximizing confidentiality affect availability?
    
    ```
    Answer:
    
    ```
    

---

### Scenario 1B: Logistics System During Combat Operations

**Description:**

A logistics tracking system manages ammunition, fuel, food, and medical supplies for forward-deployed forces during active combat operations. The system tracks inventory levels, shipment status, and delivery schedules. Supply requests and allocations are processed through this system.

**Analysis Questions:**

1. **Primary CIA Property:** Which property is MOST critical during active combat? Explain why.
    
    ```
    Answer:
    
    ```
    
2. **Context Change:** How would the prioritization change if this were a peacetime training scenario instead of combat operations?
    
    
    | Property | Combat Priority (1-3) | Peacetime Priority (1-3) | Explanation |
    | --- | --- | --- | --- |
    | Confidentiality |  |  |  |
    | Integrity |  |  |  |
    | Availability |  |  |  |
3. **Critical Failure Scenario:** What happens if an adversary successfully compromises the INTEGRITY of this system during combat operations? Describe potential consequences.
    
    ```
    Answer:
    
    ```
    

---

### Scenario 1C: Command and Control Network

**Description:**

A command and control (C2) network enables real-time communication between a headquarters and subordinate units executing combat operations. The network carries operational orders, situation reports, requests for fire support, and coordination messages.

**Analysis Questions:**

1. **Rank CIA Properties:** Rank the three CIA properties in order of importance for this scenario (1 = most important).
    
    
    | Rank | Property | Justification |
    | --- | --- | --- |
    | 1 |  |  |
    | 2 |  |  |
    | 3 |  |  |
2. **Availability Compromise:** What operational consequences occur if availability is compromised during active operations?
    
    ```
    Answer:
    
    ```
    
3. **Multi-Property Controls:** Identify two controls that address ALL THREE CIA properties simultaneously.
    
    
    | Control | How it Protects Confidentiality | How it Protects Integrity | How it Protects Availability |
    | --- | --- | --- | --- |
    | 1. |  |  |  |
    | 2. |  |  |  |

---

### Exercise 1 Self-Assessment

- **Click to reveal Exercise 1 Solution Guide**
    
    **Scenario 1A - Intelligence Database:**
    - **Primary Property:** Confidentiality is most critical. Intelligence databases contain classified information that, if disclosed, could compromise operations, endanger personnel, and provide adversaries with strategic advantage.
    - **Key Threats:** Nation-state espionage (APT), insider threats, unauthorized access via compromised credentials
    - **Key Controls:** Strong encryption (at rest and in transit), multi-factor authentication, strict access controls based on need-to-know, comprehensive audit logging
    - **Trade-off Example:** Maximizing confidentiality through strict access controls may reduce availability for analysts who need rapid access to time-sensitive intelligence
    
    **Scenario 1B - Logistics System:**
    - **Combat Priority:** Availability is typically most critical during combat—forces need supplies regardless of whether the enemy knows what’s being shipped. However, Integrity is also critical to prevent misdirection of supplies.
    - **Peacetime Shift:** Confidentiality may become more important (protecting procurement data, costs), while availability requirements are less urgent.
    - **Integrity Compromise:** Could result in supplies being sent to wrong locations, false shortages causing unnecessary emergency resupply, or excess supplies wasting resources. Could endanger forces if ammunition or medical supplies are misdirected.
    
    **Scenario 1C - C2 Network:**
    - **Typical Ranking:** 1) Availability (can’t command without communications), 2) Integrity (orders must be accurate), 3) Confidentiality (important but secondary to ability to communicate)
    - **Availability Loss:** Units operate without orders, can’t coordinate, can’t request support, potential fratricide, mission failure
    - **Multi-Property Controls:** Redundant encrypted communications (all three), authenticated and signed messages with multiple delivery paths (all three)
    

---

## Task 2: Threat Actor Analysis

**Estimated Time:** 45-60 minutes

### Objective

Analyze threat actor capabilities, motivations, and likely attack methods against DoD systems.

### Instructions

The learner will analyze two different threat actors and assess how each would approach attacking a specified DoD system.

---

### Part A: Threat Actor Profiling

**Select ONE threat actor from each category and complete the profile:**

### Category 1: Nation-State APT Group

Choose one: **APT28 (Fancy Bear/Russia)** OR **APT41 (China)**

**Threat Actor Profile:**

| Attribute | Analysis |
| --- | --- |
| **Name/Alias** |  |
| **Sponsoring Nation** |  |
| **Primary Motivation** |  |
| **Typical Targets** |  |
| **Known Capabilities** |  |
| **Common TTPs (Tactics, Techniques, Procedures)** |  |
| **Notable Historical Operations** |  |

*Note: The learner may reference the MITRE ATT&CK website or open-source intelligence for this exercise.*

### Category 2: Criminal Organization

Choose one: **Ransomware Group (e.g., LockBit, BlackCat)** OR **Financially-Motivated Cybercrime Syndicate**

**Threat Actor Profile:**

| Attribute | Analysis |
| --- | --- |
| **Type of Organization** |  |
| **Primary Motivation** |  |
| **Typical Targets** |  |
| **Known Capabilities** |  |
| **Common Attack Methods** |  |
| **Typical Attack Lifecycle** |  |

---

### Part B: Target Analysis

**Target System:** DoD Personnel Management System

**Description:** This system contains service records, performance evaluations, security clearance status, assignment history, and contact information for all military personnel. It is accessible from multiple DoD installations.

**For EACH threat actor profiled above, analyze:**

### Nation-State Actor Analysis:

1. **Attractiveness:** Why would this system attract this threat actor?
    
    ```
    Answer:
    
    ```
    
2. **Attack Vectors:** What attack vectors would they likely use?
    
    ```
    Answer:
    
    ```
    
3. **Targeted Vulnerabilities:** What types of vulnerabilities would they target?
    
    
    | Vulnerability Type | Specific Example | Exploitation Method |
    | --- | --- | --- |
    | Technical |  |  |
    | Human |  |  |
    | Process |  |  |
4. **Cyber Kill Chain Mapping:** Map a likely attack to the Cyber Kill Chain.
    
    
    | Kill Chain Phase | Likely Activity for This Target |
    | --- | --- |
    | Reconnaissance |  |
    | Weaponization |  |
    | Delivery |  |
    | Exploitation |  |
    | Installation |  |
    | Command & Control |  |
    | Actions on Objectives |  |

### Criminal Organization Analysis:

1. **Attractiveness:** Why would this system attract this threat actor?
    
    ```
    Answer:
    
    ```
    
2. **Attack Approach:** How would their approach differ from the nation-state actor?
    
    ```
    Answer:
    
    ```
    

---

### Part C: Defense Recommendations

Based on the analysis, provide prioritized defensive recommendations:

**Top 5 Defensive Priorities:**

| Priority | Recommendation | Threat(s) Addressed | CIA Property Protected |
| --- | --- | --- | --- |
| 1 |  |  |  |
| 2 |  |  |  |
| 3 |  |  |  |
| 4 |  |  |  |
| 5 |  |  |  |

**Detection Capabilities:** What detection capabilities would help identify attacks from each threat actor type?

| Threat Actor Type | Detection Capability | Indicator Type |
| --- | --- | --- |
| Nation-State APT |  |  |
| Criminal Organization |  |  |

---

### Exercise 2 Self-Assessment

- **Click to reveal Exercise 2 Solution Guide**
    
    **Nation-State APT Analysis (Example: APT28):**
    - **Attractiveness:** Personnel database enables identification of intelligence personnel, creates blackmail opportunities, supports counterintelligence operations, enables targeting of personnel for recruitment
    - **Attack Vectors:** Spear-phishing targeting system administrators, watering hole attacks on HR-related sites, supply chain compromise of connected systems
    - **Key Vulnerabilities:** Unpatched systems, weak authentication, overly broad access permissions, insufficient monitoring
    - **Kill Chain:** Long-term reconnaissance (OSINT on administrators), custom malware development, targeted phishing to administrators, credential theft for initial access, establish persistence, slow exfiltration over months
    
    **Criminal Organization Analysis:**
    - **Different Motivation:** Personnel data has value for identity theft, fraud, but ransomware against this system would be high-profile target
    - **Different Approach:** More opportunistic, faster timeline, noisier (less concerned about attribution), may use commodity malware, seeking quick monetization
    - **Less Sophisticated:** May rely on phishing with common payloads, exploit known vulnerabilities, less patience for long-term operations
    
    **Defense Priorities:**
    1. Multi-factor authentication (addresses both threat types)
    2. Network segmentation (limits lateral movement)
    3. Endpoint detection and response (detects malware, anomalous behavior)
    4. User awareness training (reduces phishing success)
    5. Privileged access management (limits credential theft impact)
    

---

## Task 3: Mission Impact Analysis

**Estimated Time:** 45-60 minutes

### Objective

Analyze how cyber incidents impact military operations by mapping system dependencies and assessing consequences of compromise.

### Scenario

**Operation IRON SHIELD**

The CDISS is supporting a Joint Task Force (JTF) headquarters conducting a multinational peacekeeping operation. The operation involves:

- **Forces:** 5,000 personnel from three nations
- **Duration:** 12-month deployment
- **Location:** Deployed to a forward operating base in a partner nation
- **Mission:** Protect civilian population, support local government, deter hostile actors
- **Threat Environment:** Regional adversary with known cyber capabilities, local criminal elements, potential insider threats

---

### Part A: System Identification

Identify the critical information systems supporting this mission. For each system, rate its criticality (Critical/High/Medium/Low).

| System Category | Specific Systems | Criticality | Primary Function |
| --- | --- | --- | --- |
| **Command & Control** |  |  |  |
| **Intelligence** |  |  |  |
| **Communications** |  |  |  |
| **Logistics** |  |  |  |
| **Personnel** |  |  |  |
| **Weapons/Platforms** |  |  |  |

---

### Part B: Dependency Mapping

Select the THREE most critical systems from the list above and map their dependencies.

**System 1:** ________________________

```
Dependencies (what this system needs to function):
- Network connectivity:
- Power:
- Other systems:
- Personnel:
- External services:

Dependents (what relies on this system):
-
-
-
```

**System 2:** ________________________

```
Dependencies:
- Network connectivity:
- Power:
- Other systems:
- Personnel:
- External services:

Dependents:
-
-
-
```

**System 3:** ________________________

```
Dependencies:
- Network connectivity:
- Power:
- Other systems:
- Personnel:
- External services:

Dependents:
-
-
-
```

---

### Part C: Impact Analysis Matrix

For each of the three critical systems, analyze the impact of CIA property compromise:

**System 1: ________________________**

| Impact Type | Confidentiality Loss | Integrity Loss | Availability Loss |
| --- | --- | --- | --- |
| **Immediate Effect** |  |  |  |
| **Operational Impact** |  |  |  |
| **Mission Impact** |  |  |  |
| **Time to Mission Failure** |  |  |  |
| **Recovery Time Estimate** |  |  |  |

**System 2: ________________________**

| Impact Type | Confidentiality Loss | Integrity Loss | Availability Loss |
| --- | --- | --- | --- |
| **Immediate Effect** |  |  |  |
| **Operational Impact** |  |  |  |
| **Mission Impact** |  |  |  |
| **Time to Mission Failure** |  |  |  |
| **Recovery Time Estimate** |  |  |  |

**System 3: ________________________**

| Impact Type | Confidentiality Loss | Integrity Loss | Availability Loss |
| --- | --- | --- | --- |
| **Immediate Effect** |  |  |  |
| **Operational Impact** |  |  |  |
| **Mission Impact** |  |  |  |
| **Time to Mission Failure** |  |  |  |
| **Recovery Time Estimate** |  |  |  |

---

### Part D: Cascading Effects Analysis

Select one of the critical systems and analyze a cascading failure scenario:

**Scenario:** The [________________] system experiences a complete availability loss due to a ransomware attack.

**Cascading Effects Analysis:**

| Time | Direct Effects | Cascading Effects | Mission Impact |
| --- | --- | --- | --- |
| **0-1 hours** |  |  |  |
| **1-4 hours** |  |  |  |
| **4-12 hours** |  |  |  |
| **12-24 hours** |  |  |  |
| **24+ hours** |  |  |  |

---

### Part E: Protection Prioritization

Based on the analysis, prioritize the systems for protection:

| Priority | System | Justification | Recommended Protection Measures |
| --- | --- | --- | --- |
| 1 |  |  |  |
| 2 |  |  |  |
| 3 |  |  |  |

**Resource Allocation:** If the CDISS could only fully protect ONE system, which should be chosen and why?

```
Answer:

```

---

### Exercise 3 Self-Assessment

- **Click to reveal Exercise 3 Solution Guide**
    
    **Critical Systems Identification:**
    - **C2 Systems:** Mission command applications, battle tracking, common operational picture - CRITICAL
    - **Communications:** SATCOM, tactical radios, classified networks - CRITICAL
    - **Intelligence:** Intelligence databases, ISR feeds, threat reporting - HIGH
    - **Logistics:** Supply tracking, maintenance management, transportation - HIGH
    - **Personnel:** Accountability systems, personnel actions - MEDIUM
    
    **Dependency Insights:**
    - Most systems depend on network connectivity and power
    - C2 systems typically depend on communications and intelligence feeds
    - Logistics depends on communications to coordinate with supply sources
    - Single points of failure in network or power affect multiple systems
    
    **Impact Analysis Key Points:**
    - C2 availability loss: Immediate loss of coordination capability, mission failure within hours
    - Communications integrity loss: Wrong orders executed, potential fratricide, strategic failure
    - Intelligence confidentiality loss: Compromise of sources/methods, long-term strategic damage
    
    **Cascading Example (C2 System Loss):**
    - 0-1 hours: Headquarters loses situational awareness, subordinate units continue last orders
    - 1-4 hours: Unable to coordinate, units operating independently, no response to changing situation
    - 4-12 hours: Mission degrades significantly, potential for friendly fire, adversary exploitation
    - 12-24 hours: Mission pause required, emergency procedures invoked
    - 24+ hours: Potential mission failure, strategic consequences
    
    **Prioritization Logic:**
    1. C2/Communications (without these, can’t command or coordinate)
    2. Intelligence (needed for informed decisions)
    3. Logistics (can operate short-term without, but degrades over time)
    

---

## Task 4: Ethical Scenarios

**Estimated Time:** 30-40 minutes

### Objective

Apply legal and ethical principles to realistic cybersecurity dilemmas in DoD contexts.

### Instructions

Read each scenario carefully. For each, identify the ethical considerations, applicable policies, and recommend a course of action. Document the reasoning.

---

### Task 4A: The Urgent Request

**Situation:**

A battalion commander in a deployed location emails the CDISS directly, requesting immediate administrator access to a classified system. They state it's mission-critical and there's no time for the proper authorization process. The security manager is on leave and unreachable. The commander outranks the CDISS significantly and is known for a short temper.

**Analysis:**

1. **Ethical Considerations:** What ethical principles are in conflict?
    
    ```
    Answer:
    
    ```
    
2. **Policy Considerations:** What policies or regulations apply to this situation?
    
    ```
    Answer:
    
    ```
    
3. **Risks of Compliance:** What could go wrong if the CDISS grants the access?
    
    ```
    Answer:
    
    ```
    
4. **Risks of Non-Compliance:** What could go wrong if the CDISS refuses?
    
    ```
    Answer:
    
    ```
    
5. **Recommended Action:** What should the CDISS do? Be specific about the steps.
    
    ```
    Answer:
    
    ```
    

---

### Task 4B: Security vs. Mission

**Situation:**

A critical security update requires rebooting servers supporting an ongoing operation. The operation commander says the reboot cannot happen during their current phase, which will last another 72 hours. The vulnerability being patched is being actively exploited in the wild, and threat intelligence indicates adversaries are targeting similar systems.

**Analysis:**

1. **Competing Priorities:** What are the competing interests?
    
    
    | Security Perspective | Operational Perspective |
    | --- | --- |
    |  |  |
    |  |  |
    |  |  |
2. **Risk Assessment:** Complete this risk comparison:
    
    
    | Option | Risk | Likelihood | Impact | Risk Level |
    | --- | --- | --- | --- | --- |
    | Delay patching 72 hours |  |  |  |  |
    | Patch immediately (disrupt operations) |  |  |  |  |
    | Implement temporary mitigations |  |  |  |  |
3. **Decision Authority:** Who has the authority to make this decision?
    
    ```
    Answer:
    
    ```
    
4. **Recommendation:** What should the CDISS recommend and how should it be presented?
    
    ```
    Answer:
    
    ```
    

---

### Task 4C: The Discovered Activity

**Situation:**

While investigating a security alert, the CDISS discovers a senior officer appears to be using government systems to run a personal business during duty hours. This activity is completely unrelated to the security investigation. The officer is well-liked and has a reputation for taking care of their people.

**Analysis:**

1. **What Was Discovered:** Is this a security issue, policy violation, or both?
    
    ```
    Answer:
    
    ```
    
2. **Responsibility:** What is the CDISS's obligation regarding this discovery?
    
    ```
    Answer:
    
    ```
    
3. **Proper Channels:** Who should the CDISS report this to, if anyone?
    
    ```
    Answer:
    
    ```
    
4. **Documentation:** What should the CDISS document and what should NOT be documented?
    
    ```
    Answer:
    
    ```
    

---

### Task 4D: The Helpful Contractor

**Situation:**

A contractor working in the facility offers to help the CDISS solve a persistent system problem that's been frustrating for weeks. They suggest a solution that requires them to access a system they're not authorized for. The contractor says, "It's fine, everyone does it, and it will only take a minute. No one will ever know."

**Analysis:**

1. **Red Flags:** What warning signs are present in this situation?
    
    ```
    Answer:
    
    ```
    
2. **Potential Violations:** What policies or laws could be violated?
    
    ```
    Answer:
    
    ```
    
3. **Response:** How should the CDISS respond to the contractor?
    
    ```
    Answer:
    
    ```
    
4. **Reporting:** Should the CDISS report this interaction? To whom?
    
    ```
    Answer:
    
    ```
    

---

### Exercise 4 Self-Assessment

- **Click to reveal Exercise 4 Solution Guide**
    
    **Scenario 4A - Urgent Request:**
    - **Ethical Conflict:** Duty to follow chain of command vs. responsibility to maintain security; military authority vs. security authority
    - **Applicable Policies:** Access control policies require proper authorization regardless of rank; ISSO authority over system access
    - **Key Point:** Rank does not convey system access rights. Proper authorization is required regardless of urgency.
    - **Recommended Action:** Respectfully explain authorization requirements, offer to expedite through alternate security personnel, contact backup security authority, document the request and the response. Do NOT grant unauthorized access regardless of pressure.
    
    **Scenario 4B - Security vs. Mission:**
    - **Decision Authority:** Typically the mission commander makes risk decisions, but with security input. This may need to escalate to higher authority.
    - **Recommended Approach:** Present risk clearly with options (patch now, delay with mitigations, accept risk). Document commander’s decision. Consider temporary mitigations (network isolation, enhanced monitoring, IPS signatures) if delay is chosen.
    - **Key Point:** Security professionals advise and document; commanders decide and accept risk.
    
    **Scenario 4C - Discovered Activity:**
    - **Nature of Issue:** Policy violation (misuse of government resources), not necessarily a security threat
    - **Responsibility:** Report through appropriate channels (supervisor, IG, chain of command)—not the CDISS's decision to ignore
    - **Key Point:** The CDISS is not the investigator for this issue. Report it and return to security duties. Don't conduct further investigation into non-security matters.
    
    **Scenario 4D - Helpful Contractor:**
    - **Red Flags:** "Everyone does it," "no one will know," unauthorized access, circumventing controls
    - **Potential Violations:** Computer fraud laws, access control policies, contractor oversight requirements
    - **Response:** Politely decline, explain the CDISS can't authorize their access to systems, document the interaction
    - **Reporting:** Yes—this should be reported to the security manager and contracting officer. It could indicate insider threat indicators.
    

---

## Task 5: Comprehensive Scenario Assessment

**Estimated Time:** 45-60 minutes

### Objective

Integrate all Module 1 concepts to analyze a complex scenario involving multiple cybersecurity principles, threats, and operational considerations.

### Scenario: Forward Operating Base Network Compromise

**Background:**

The CDISS is at Forward Operating Base (FOB) PHOENIX, supporting a brigade combat team. The FOB relies on the following systems:

- **Tactical Operations Center (TOC) Network:** Classified C2 systems, intelligence feeds, common operational picture
- **Administrative Network:** Email, personnel systems, logistics applications
- **Base Life Support Systems:** Physical security cameras, access control, environmental controls
- **SATCOM Links:** Primary communications to higher headquarters
- **Tactical Radio Network:** Communications with subordinate units in the field

**Incident:**

At 0300 hours, multiple anomalies are detected:
- Unusual outbound traffic from the administrative network to an unknown external IP
- Several failed login attempts on the TOC network from an administrative network workstation
- A phishing email was reported 48 hours ago—the user clicked the link before reporting
- The base physical security system shows intermittent camera failures
- SATCOM performance is degraded by 40%

---

### Task 5A: Initial Assessment

1. **Threat Identification:** Based on the indicators, what type of threat actor is most likely involved?
    
    ```
    Answer:
    
    ```
    
2. **Attack Phase:** Where in the Cyber Kill Chain is this attack likely positioned?
    
    
    | Kill Chain Phase | Evidence Present | Confidence (H/M/L) |
    | --- | --- | --- |
    | Reconnaissance |  |  |
    | Weaponization |  |  |
    | Delivery |  |  |
    | Exploitation |  |  |
    | Installation |  |  |
    | Command & Control |  |  |
    | Actions on Objectives |  |  |
3. **CIA Impact Assessment:** Which CIA properties are potentially compromised for each system?
    
    
    | System | Confidentiality | Integrity | Availability |
    | --- | --- | --- | --- |
    | TOC Network | ☐ Confirmed ☐ Suspected ☐ Unknown | ☐ Confirmed ☐ Suspected ☐ Unknown | ☐ Confirmed ☐ Suspected ☐ Unknown |
    | Admin Network | ☐ Confirmed ☐ Suspected ☐ Unknown | ☐ Confirmed ☐ Suspected ☐ Unknown | ☐ Confirmed ☐ Suspected ☐ Unknown |
    | Base Life Support | ☐ Confirmed ☐ Suspected ☐ Unknown | ☐ Confirmed ☐ Suspected ☐ Unknown | ☐ Confirmed ☐ Suspected ☐ Unknown |
    | SATCOM | ☐ Confirmed ☐ Suspected ☐ Unknown | ☐ Confirmed ☐ Suspected ☐ Unknown | ☐ Confirmed ☐ Suspected ☐ Unknown |
    | Tactical Radios | ☐ Confirmed ☐ Suspected ☐ Unknown | ☐ Confirmed ☐ Suspected ☐ Unknown | ☐ Confirmed ☐ Suspected ☐ Unknown |

---

### Task 5B: Mission Impact Analysis

1. **Current Operations:** The brigade has units conducting a patrol 50km from the FOB. How does this incident affect their safety and mission?
    
    ```
    Answer:
    
    ```
    
2. **Critical Dependencies:** What systems must remain operational to support the patrol?
    
    
    | System | Must Have | Nice to Have | Can Operate Without |
    | --- | --- | --- | --- |
    | TOC Network | ☐ | ☐ | ☐ |
    | Admin Network | ☐ | ☐ | ☐ |
    | Base Life Support | ☐ | ☐ | ☐ |
    | SATCOM | ☐ | ☐ | ☐ |
    | Tactical Radios | ☐ | ☐ | ☐ |
3. **Time Sensitivity:** How long can operations continue at each degradation level?
    
    
    | Degradation Level | Sustainable Duration | Actions Required |
    | --- | --- | --- |
    | Current State |  |  |
    | Loss of SATCOM |  |  |
    | Loss of TOC Network |  |  |
    | Total Network Loss |  |  |

---

### Task 5C: Response Prioritization

1. **Immediate Actions (0-1 hours):** List the top 5 immediate actions in priority order.
    
    
    | Priority | Action | Justification |
    | --- | --- | --- |
    | 1 |  |  |
    | 2 |  |  |
    | 3 |  |  |
    | 4 |  |  |
    | 5 |  |  |
2. **Containment Decisions:** For each system, recommend containment action:
    
    
    | System | Isolate Immediately | Monitor Closely | No Action Needed | Justification |
    | --- | --- | --- | --- | --- |
    | Admin Network | ☐ | ☐ | ☐ |  |
    | TOC Network | ☐ | ☐ | ☐ |  |
    | Base Life Support | ☐ | ☐ | ☐ |  |
    | SATCOM | ☐ | ☐ | ☐ |  |
3. **Commander Notification:** What should the CDISS tell the brigade commander right now?
    
    ```
    The briefing (keep it concise—commanders are busy):
    
    ```
    

---

### Task 5D: Ethical and Legal Considerations

1. **Authorization:** What actions can the CDISS take immediately without additional authorization?
    
    ```
    Answer:
    
    ```
    
2. **Escalation:** What actions require commander approval or higher authority?
    
    ```
    Answer:
    
    ```
    
3. **Documentation:** What must the CDISS document during this incident?
    
    ```
    Answer:
    
    ```
    

---

### Part E: Lessons Learned (Post-Incident)

Assuming the incident is contained, answer these forward-looking questions:

1. **Root Cause:** What likely enabled this attack to succeed?
    
    ```
    Answer:
    
    ```
    
2. **Prevention Measures:** What three measures would most effectively prevent similar incidents?
    
    
    | Measure | Implementation Difficulty | Effectiveness |
    | --- | --- | --- |
    | 1. |  |  |
    | 2. |  |  |
    | 3. |  |  |
3. **Detection Improvements:** How could this attack have been detected earlier?
    
    ```
    Answer:
    
    ```
    

---

### Exercise 5 Self-Assessment

- **Click to reveal Exercise 5 Solution Guide**
    
    **Threat Assessment:**
    - **Likely Threat Actor:** Nation-state or sophisticated adversary (targeting military base, patient approach, multiple vectors)
    - **Kill Chain Position:** Likely in Installation/C2 phase (persistence established, lateral movement attempted)
    - **The phishing email 48 hours ago was likely the initial access vector**
    
    **Key Observations:**
    - Admin network is compromised (C2 traffic, source of lateral movement attempts)
    - TOC network is being targeted but may not be compromised (failed logins)
    - Base life support and SATCOM issues may be related or coincidental
    
    **Mission Impact:**
    - Units in field depend on SATCOM and tactical radios for communication
    - TOC must remain operational for C2
    - Admin network is lower priority during active operations
    - SATCOM degradation directly affects command’s ability to support patrol
    
    **Response Priorities:**
    1. Isolate administrative network from TOC (prevent lateral movement)
    2. Preserve evidence on compromised workstation
    3. Verify tactical radio functionality (backup comms for patrol)
    4. Notify higher headquarters of potential compromise
    5. Increase monitoring on TOC network
    
    **Commander Brief Example:**
    “Sir, we have a suspected network intrusion. The admin network appears compromised—we’re isolating it now. TOC network shows attempted access but appears secure. SATCOM degradation is being investigated. Our patrol has working radio comms. I recommend we shift to backup procedures for the next 4 hours while we assess. No classified data breach confirmed at this time.”
    
    **Ethical/Legal Considerations:**
    - Can isolate networks, preserve evidence, notify chain of command immediately
    - May need commander approval for significant operational impacts
    - Must document all actions, times, and decisions
    
    **Prevention:**
    1. User awareness training (prevent phishing clicks)
    2. Network segmentation (prevent lateral movement)
    3. Enhanced monitoring/alerting (detect faster)
    

---

## Lab Completion Checklist

Before submitting this lab, verify you have completed:

- [ ]  **Exercise 1:** CIA Triad Analysis (3 scenarios)
- [ ]  **Exercise 2:** Threat Actor Analysis (profiling, target analysis, defense recommendations)
- [ ]  **Exercise 3:** Mission Impact Analysis (system identification, dependencies, impact matrix, cascading effects, prioritization)
- [ ]  **Exercise 4:** Ethical Scenarios (4 scenarios with analysis and recommendations)
- [ ]  **Exercise 5:** Comprehensive Scenario Assessment (all parts A-E)

### Self-Grading Rubric

| Criterion | Excellent (90-100%) | Satisfactory (70-89%) | Needs Improvement (<70%) |
| --- | --- | --- | --- |
| **Technical Accuracy** | Correctly applies CIA Triad, Kill Chain, and threat concepts | Minor errors in application | Significant misunderstanding of concepts |
| **Critical Thinking** | Thorough analysis with well-reasoned conclusions | Adequate analysis with some gaps | Superficial analysis |
| **DoD Context** | Appropriately applies military/DoD considerations | Some DoD context applied | Minimal DoD context |
| **Practical Application** | Recommendations are specific and actionable | Recommendations are general but reasonable | Recommendations are vague or impractical |
| **Documentation Quality** | Clear, complete, well-organized responses | Mostly clear with minor gaps | Incomplete or unclear responses |

---

## Summary

This lab provided hands-on practice applying Module 1’s foundational cybersecurity concepts:

- **CIA Triad Analysis:** Understanding how mission context affects security priorities
- **Threat Actor Analysis:** Profiling adversaries and predicting their behavior
- **Mission Impact Analysis:** Connecting cybersecurity to operational outcomes
- **Ethical Decision-Making:** Navigating complex situations with competing priorities
- **Integrated Scenario Analysis:** Combining all concepts in realistic situations

These skills form the foundation for the technical modules that follow, where the learner will learn to implement the protective measures discussed in these scenarios.

---

**Proceed to Module 2: DoD Cyberspace Operations Framework**

---

*Document Version: 1.0*

*Last Updated: December 2024*

*Classification: UNCLASSIFIED // FOR TRAINING USE ONLY*