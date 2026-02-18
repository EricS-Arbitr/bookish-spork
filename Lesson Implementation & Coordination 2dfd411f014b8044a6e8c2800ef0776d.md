# Lesson: Implementation & Coordination

Owner: Eric Starace
Last edited by: Eric Starace

| **Lesson Reference** |  |
| --- | --- |
| **Lesson Author** | Arbitr |
| **Lesson ID (LES-XXX)** | LES-XXX |
| **Lesson Name** | Implementation and Coordination |
| **Duration (x.x)** |  |
| **Terminal Learning Objectives (TLOs)** | **Given** instruction on stakeholder coordination, infrastructure deployment, impact assessment, and critical infrastructure protection, **the learner** implements and deploys cyber defense infrastructure, **demonstrating** the ability to coordinate with stakeholders, plan and execute deployments, assess operational and mission impacts, and identify and prioritize protection of critical infrastructure **in accordance with** CWP 3-33.4, CWP 3-0.1, DODD 3020.40, and applicable DoD guidance. |
| **Enabling Learning Objectives (ELOs)** | - Coordinate with stakeholders for cyber defense implementation |
|  | - Plan and execute infrastructure deployments |
|  | - Assess operational and mission impacts of implementations |
|  | - Identify and prioritize protection of critical infrastructure |
|  | - Manage cyber defense system transitions |
| **DCWF KSATs** | T0393B - Coordinate with system administrators to create tools, test beds, and establish requirements |
|  | T2772 - Build, install, configure, and test cyber defense hardware |
|  | T5090 - Assess the impact of implementing and sustaining a dedicated cyber defense infrastructure |
|  | T0960 - Assist in identifying, prioritizing, and coordinating the protection of critical cyber defense infrastructure and key resources |
| **JQR Line Items** |  |
| **Dependency (Tools, DB, Etc.)** |  |

**This confluence page contains Controlled Unclassified Information (CUI) and must be handled within the protections of that data.**

---

## How to Use This Lesson

This lesson focuses on implementing and deploying cyber defense infrastructure in coordination with stakeholders. The content covers coordination with system administrators, CSSPs, and CPTs; deployment of cyber defense tools; assessment of implementation impacts; and protection of critical infrastructure.

**Recommended Approach:**

1. Read each section thoroughly before attempting exercises
2. Complete all “Check Your Understanding” questions and compare to answer keys
3. Perform hands-on exercises in the lab environment
4. Use the self-assessment checklists to verify progress
5. Review any areas scoring below 80% before proceeding

**Icons Used in This Lesson:**
- 📖 **Reading** - Content to study
- ✅ **Check Your Understanding** - Self-assessment questions
- 💡 **Key Concept** - Important information to remember
- ⚠️ **Important** - Critical information requiring attention
- 🎯 **Learning Objective** - Expected capability after this section
- 📋 **Doctrinal Reference** - Source from DoD/USCYBERCOM publications

**Prerequisites:**
Before starting this lesson, learners must have completed:
- Lesson 5: Mission Relevant Terrain in Cyberspace (MRT-C)
- Lesson 15: CPT Operations Support
- Lesson 17: Testing and Evaluation

---

## Overview

Implementation and coordination are critical phases in deploying cyber defense infrastructure. Effective implementation requires coordination with multiple stakeholders, careful planning, impact assessment, and protection of critical infrastructure. As a Cyber Defense Infrastructure Support Specialist, successful deployment must be ensured while minimizing operational impacts.

### Terminal Learning Objective (TLO)

**Given** instruction on stakeholder coordination, infrastructure deployment, impact assessment, and critical infrastructure protection, **the learner** implements and deploys cyber defense infrastructure, **demonstrating** the ability to coordinate with stakeholders, plan and execute deployments, assess operational and mission impacts, and identify and prioritize protection of critical infrastructure **in accordance with** CWP 3-33.4, CWP 3-0.1, DODD 3020.40, and applicable DoD guidance.

### Enabling Learning Objectives (ELOs)

Upon completion of this lesson, learners are able to:

🎯 **Objective 1:** Coordinate with stakeholders for cyber defense implementation

🎯 **Objective 2:** Plan and execute infrastructure deployments

🎯 **Objective 3:** Assess operational and mission impacts of implementations

🎯 **Objective 4:** Identify and prioritize protection of critical infrastructure

🎯 **Objective 5:** Manage cyber defense system transitions

### KSAT Coverage

This lesson addresses the following Knowledge, Skills, Abilities, and Tasks:

| KSAT ID | Type | Description |
| --- | --- | --- |
| T0393B | Task (Core) | Coordinate with system administrators to create tools, test beds, and establish requirements |
| T2772 | Task (Core) | Build, install, configure, and test cyber defense hardware |
| T5090 | Task (Core) | Assess the impact of implementing and sustaining a dedicated cyber defense infrastructure |
| T0960 | Task (Core) | Assist in identifying, prioritizing, and coordinating the protection of critical cyber defense infrastructure and key resources |

### Doctrinal Foundation

This lesson draws from:
- **CWP 3-33.4:** Cyber Protection Team Organization, Functions, and Employment
- **CWP 3-0.1:** Identification of Mission Relevant Terrain in Cyberspace (MRT-C)
- **DODD 3020.40:** Mission Assurance
- **DODI 3020.45:** Mission Assurance Construct

---

## Section 18.1: Stakeholder Coordination

**🎯 Learning Objective:** Coordinate effectively with stakeholders for cyber defense implementation

---

### 📖 18.1.1 Stakeholder Identification

Successful implementation requires coordination with multiple stakeholders.

```
┌─────────────────────────────────────────────────────────────────┐
│                  KEY STAKEHOLDERS                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   INTERNAL STAKEHOLDERS                                         │
│   ├── System Administrators                                     │
│   │   └── Manage systems where tools will be deployed           │
│   ├── Network Administrators                                    │
│   │   └── Manage network infrastructure                         │
│   ├── Security Management (ISSM/ISSO)                           │
│   │   └── Approve security implementations                      │
│   ├── Operations Staff                                          │
│   │   └── Use systems affected by changes                       │
│   ├── Help Desk/User Support                                    │
│   │   └── Support users during transitions                      │
│   └── Leadership/Command                                        │
│       └── Approve implementations, provide resources            │
│                                                                  │
│   EXTERNAL STAKEHOLDERS                                         │
│   ├── Cybersecurity Service Providers (CSSPs)                   │
│   │   └── Provide cybersecurity services to the enclave         │
│   ├── Cyber Protection Teams (CPTs)                             │
│   │   └── Conduct defensive operations                          │
│   ├── JFHQ-DODIN                                                │
│   │   └── Synchronize DODIN defense                             │
│   ├── Higher Headquarters                                       │
│   │   └── Provide guidance, approve changes                     │
│   └── Vendors/Contractors                                       │
│       └── Support products, provide expertise                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### 📖 18.1.2 Working with System Administrators

System administrators are key partners in cyber defense implementation.

**Coordination Areas:**

| Area | What to Coordinate |
| --- | --- |
| **Requirements** | Resources needed (CPU, memory, disk, network) |
| **Access** | Administrative access for installation |
| **Scheduling** | Maintenance windows for deployment |
| **Dependencies** | Prerequisite software, configurations |
| **Testing** | Test bed creation and validation |
| **Support** | Ongoing maintenance responsibilities |

**Coordination Process:**

```
┌─────────────────────────────────────────────────────────────────┐
│          SYSTEM ADMINISTRATOR COORDINATION                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   1. INITIAL ENGAGEMENT                                         │
│      • Introduce the project                                    │
│      • Explain cyber defense tool requirements                  │
│      • Identify system administrator points of contact          │
│      • Establish communication channels                         │
│                                                                  │
│   2. REQUIREMENTS GATHERING                                     │
│      • Document system configurations                           │
│      • Identify resource availability                           │
│      • Determine constraints and limitations                    │
│      • Agree on success criteria                                │
│                                                                  │
│   3. PLANNING                                                   │
│      • Develop deployment plan together                         │
│      • Schedule maintenance windows                             │
│      • Plan test bed creation                                   │
│      • Define rollback procedures                               │
│                                                                  │
│   4. EXECUTION                                                  │
│      • Coordinate during deployment                             │
│      • Communicate status updates                               │
│      • Address issues together                                  │
│      • Validate successful deployment                           │
│                                                                  │
│   5. TRANSITION                                                 │
│      • Transfer knowledge                                       │
│      • Define ongoing responsibilities                          │
│      • Establish support procedures                             │
│      • Document lessons learned                                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### 📖 18.1.3 Coordinating with CSSPs

📋 **Doctrinal Reference - CWP 3-0.1:**
“Static Cyberspace Operations Forces (e.g., local defenders, CSSP). Provide expertise and assistance in MRT-C identification, assessment, prioritization, risk management and monitoring.”

**CSSP Coordination Areas:**

| Area | Purpose |
| --- | --- |
| **Service Boundaries** | Understand CSSP vs. local responsibilities |
| **Sensor Placement** | Coordinate sensor locations at boundaries |
| **Log Integration** | Ensure logs flow to CSSP monitoring |
| **Alert Handling** | Define escalation procedures |
| **Change Notification** | Inform CSSP of infrastructure changes |
| **Incident Coordination** | Align incident response procedures |

```
┌─────────────────────────────────────────────────────────────────┐
│                 CSSP COORDINATION                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   BEFORE IMPLEMENTATION:                                        │
│   • Notify CSSP of planned changes                              │
│   • Verify changes don't conflict with CSSP services            │
│   • Coordinate sensor/log integration requirements              │
│   • Align implementation with CSSP maintenance windows          │
│                                                                  │
│   DURING IMPLEMENTATION:                                        │
│   • Provide status updates to CSSP                              │
│   • Coordinate any service interruptions                        │
│   • Address integration issues                                  │
│   • Validate connectivity to CSSP services                      │
│                                                                  │
│   AFTER IMPLEMENTATION:                                         │
│   • Confirm log flow to CSSP                                    │
│   • Verify alert forwarding                                     │
│   • Update CSSP on new capabilities                             │
│   • Document integration points                                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### 📖 18.1.4 Coordination with CPTs and JFHQ-DODIN

📋 **Doctrinal Reference - CWP 3-33.4:**
“CPT leaders are responsible for accounting and coordinating for mission requirements with the appropriate controlling commander, including considerations arising from command relationship support responsibilities.”

**CPT Coordination Considerations:**

| Consideration | Description |
| --- | --- |
| **Pre-mission Planning** | Coordinate access and requirements before CPT arrives |
| **Network Documentation** | Provide current network diagrams and configurations |
| **Tool Compatibility** | Ensure local tools don’t conflict with CPT DMSS |
| **Access Coordination** | Coordinate system and physical access |
| **Integration Support** | Support CPT integration with local infrastructure |

📋 **Doctrinal Reference - CWP 3-33.4:**
“Pre-mission planning and coordination considerations include: Special Authority to Operate (or Connect); Account or system accesses; Physical access; Travel and lodging funding; On-site transportation; Theater-specific pre-deployment training requirements; Special equipment; and Personal protective equipment and weapons.”

**JFHQ-DODIN Coordination:**

```
┌─────────────────────────────────────────────────────────────────┐
│              JFHQ-DODIN COORDINATION                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   JFHQ-DODIN ROLE:                                              │
│   • Synchronizes DOD Components' MRT-C efforts                  │
│   • Tracks MRT-C mapping status and progress                    │
│   • Coordinates CPT assignments                                 │
│   • Issues operational guidance                                 │
│                                                                  │
│   COORDINATION POINTS:                                          │
│   • Report MRT-C mapping progress                               │
│   • Coordinate CPT support requests                             │
│   • Report significant infrastructure changes                   │
│   • Align with DODIN-wide initiatives                           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### 📖 18.1.5 Communication Strategies

Effective communication is essential for successful coordination.

**Communication Principles:**

| Principle | Application |
| --- | --- |
| **Clarity** | Use clear, unambiguous language |
| **Timeliness** | Communicate early and often |
| **Completeness** | Include all relevant information |
| **Accuracy** | Verify information before sharing |
| **Appropriateness** | Use proper channels and classification |

**Communication Plan Elements:**

```
┌─────────────────────────────────────────────────────────────────┐
│              COMMUNICATION PLAN                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   1. STAKEHOLDER MATRIX                                         │
│      • Who needs to be informed?                                │
│      • What information do they need?                           │
│      • How often do they need updates?                          │
│      • What is their preferred communication method?            │
│                                                                  │
│   2. COMMUNICATION CHANNELS                                     │
│      • Email (routine updates)                                  │
│      • Meetings (planning, decision-making)                     │
│      • Phone/VTC (urgent issues)                                │
│      • Ticketing system (technical issues)                      │
│      • Secure channels (classified information)                 │
│                                                                  │
│   3. COMMUNICATION SCHEDULE                                     │
│      • Daily status updates during implementation               │
│      • Weekly progress reports                                  │
│      • Milestone notifications                                  │
│      • Immediate notification of issues                         │
│                                                                  │
│   4. ESCALATION PROCEDURES                                      │
│      • When to escalate issues                                  │
│      • Who to escalate to                                       │
│      • How to escalate                                          │
│      • Expected response times                                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### 📖 18.1.6 Requirements Gathering

Thorough requirements gathering prevents implementation problems.

**Requirements Categories:**

| Category | Examples |
| --- | --- |
| **Functional** | What the tool must do |
| **Technical** | Hardware, software, network requirements |
| **Security** | Access controls, encryption, compliance |
| **Operational** | Availability, performance, support |
| **Integration** | Connectivity to other systems |
| **Documentation** | Required documentation |

**Requirements Gathering Process:**

```
┌─────────────────────────────────────────────────────────────────┐
│          REQUIREMENTS GATHERING PROCESS                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   1. IDENTIFY STAKEHOLDERS                                      │
│      • Who uses the capability?                                 │
│      • Who manages the systems?                                 │
│      • Who approves the implementation?                         │
│                                                                  │
│   2. GATHER REQUIREMENTS                                        │
│      • Interview stakeholders                                   │
│      • Review existing documentation                            │
│      • Analyze current capabilities                             │
│      • Identify gaps                                            │
│                                                                  │
│   3. DOCUMENT REQUIREMENTS                                      │
│      • Write clear requirement statements                       │
│      • Prioritize requirements (must-have vs. nice-to-have)     │
│      • Identify constraints                                     │
│      • Document assumptions                                     │
│                                                                  │
│   4. VALIDATE REQUIREMENTS                                      │
│      • Review with stakeholders                                 │
│      • Confirm understanding                                    │
│      • Obtain approval                                          │
│      • Baseline requirements                                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### ✅ Check Your Understanding - Section 18.1

### Knowledge Check: Key Stakeholders

Who are the key stakeholders for cyber defense implementation?

1. Only system administrators and leadership
2. Only CSSPs and CPTs
3. **Internal (System Admins, Network Admins, Security Management, Operations, Help Desk, Leadership) and External (CSSPs, CPTs, JFHQ-DODIN, Higher HQ, Vendors)**
4. Only vendors and contractors

💡
Key stakeholders include Internal: System Administrators (manage systems where tools deploy), Network Administrators (manage network infrastructure), Security Management (approve implementations), Operations Staff (use affected systems), Help Desk (support users), Leadership (approve and provide resources); and External: CSSPs (provide cybersecurity services), CPTs (conduct defensive operations), JFHQ-DODIN (synchronize DODIN defense), Higher HQ (provide guidance), Vendors (support products).

### Knowledge Check: System Administrator Coordination

What areas require coordination with system administrators?

1. Only access and scheduling
2. Only requirements and testing
3. **Requirements (resources needed), Access (administrative access), Scheduling (maintenance windows), Dependencies (prerequisites), Testing (test bed creation), and Support (ongoing maintenance)**
4. Only support and dependencies

💡
System administrator coordination areas include: Requirements (resources needed - CPU, memory, disk, network), Access (administrative access for installation), Scheduling (maintenance windows for deployment), Dependencies (prerequisite software, configurations), Testing (test bed creation and validation), and Support (ongoing maintenance responsibilities).

### Knowledge Check: CSSP Role

What role do CSSPs play in cyber defense implementation?

1. Only provide vendor support
2. Only conduct penetration testing
3. **Provide expertise and assistance in MRT-C identification, assessment, prioritization, risk management, and monitoring; provide cybersecurity services to the enclave**
4. Only approve implementations

💡
Per CWP 3-0.1, CSSPs (Static Cyberspace Operations Forces) provide expertise and assistance in MRT-C identification, assessment, prioritization, risk management, and monitoring. They provide cybersecurity services to the enclave. Coordination areas include service boundaries, sensor placement, log integration, alert handling, change notification, and incident coordination.

### Knowledge Check: CPT Coordination

What are CPT pre-mission planning coordination considerations?

1. Only network documentation
2. Only system access
3. **Special Authority to Operate, Account/system accesses, Physical access, Travel/lodging funding, On-site transportation, Theater-specific training requirements, Special equipment, and Personal protective equipment/weapons**
4. Only tool compatibility

💡
Per CWP 3-33.4, CPT pre-mission planning considerations include: Special Authority to Operate (or Connect), Account or system accesses, Physical access, Travel and lodging funding, On-site transportation, Theater-specific pre-deployment training requirements, Special equipment, and Personal protective equipment and weapons.

### Knowledge Check: Communication Plan

What are the key elements of a communication plan?

1. Only stakeholder matrix
2. Only escalation procedures
3. **Stakeholder matrix (who, what, how often, method), Communication channels (email, meetings, phone, tickets), Communication schedule (daily, weekly, milestones), and Escalation procedures (when, who, how)**
4. Only communication channels

💡
Communication plan elements include: Stakeholder matrix (who needs to be informed, what information they need, how often, preferred method), Communication channels (email, meetings, phone/VTC, ticketing system, secure channels), Communication schedule (daily status, weekly progress, milestone notifications, immediate issue notification), and Escalation procedures (when to escalate, who to escalate to, how to escalate, expected response times).

---

### 📋 Progress Checkpoint - Section 18.1

Before proceeding to Section 18.2, verify the ability to accomplish the following:

- [ ]  Identify key stakeholders for implementation
- [ ]  Describe coordination with system administrators
- [ ]  Explain CSSP coordination requirements
- [ ]  Understand CPT coordination considerations
- [ ]  Develop a communication plan
- [ ]  Gather and document requirements

**If all items are checked, proceed to Section 18.2.**

**If any items remain unchecked, review the relevant subsections before continuing.**

---

## Section 18.2: Infrastructure Deployment

**🎯 Learning Objective:** Plan and execute cyber defense infrastructure deployments

---

### 📖 18.2.1 Deployment Planning

Successful deployment requires thorough planning.

```
┌─────────────────────────────────────────────────────────────────┐
│                DEPLOYMENT PLANNING                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   PLANNING PHASES:                                              │
│                                                                  │
│   1. PREPARATION                                                │
│      • Define deployment scope                                  │
│      • Identify resources needed                                │
│      • Establish timeline                                       │
│      • Identify risks                                           │
│                                                                  │
│   2. DESIGN                                                     │
│      • Architecture decisions                                   │
│      • Integration points                                       │
│      • Configuration specifications                             │
│      • Security requirements                                    │
│                                                                  │
│   3. TESTING                                                    │
│      • Test environment validation                              │
│      • Functional testing                                       │
│      • Integration testing                                      │
│      • Performance testing                                      │
│                                                                  │
│   4. DEPLOYMENT                                                 │
│      • Pre-deployment checklist                                 │
│      • Execution steps                                          │
│      • Validation procedures                                    │
│      • Rollback triggers                                        │
│                                                                  │
│   5. TRANSITION                                                 │
│      • Knowledge transfer                                       │
│      • Documentation completion                                 │
│      • Support handoff                                          │
│      • Lessons learned                                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Deployment Plan Components:**

| Component | Description |
| --- | --- |
| **Scope** | What is being deployed, where, and to whom |
| **Schedule** | Timeline with milestones |
| **Resources** | Personnel, equipment, budget |
| **Dependencies** | Prerequisites and constraints |
| **Risks** | Potential issues and mitigations |
| **Procedures** | Step-by-step instructions |
| **Validation** | How success will be verified |
| **Rollback** | How to reverse if needed |

---

### 📖 18.2.2 Implementation Procedures

Structured procedures ensure consistent, successful deployments.

**Implementation Workflow:**

```
┌─────────────────────────────────────────────────────────────────┐
│            IMPLEMENTATION WORKFLOW                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   PRE-DEPLOYMENT (Day -7 to -1)                                 │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │ [ ] Verify all prerequisites met                         │  │
│   │ [ ] Confirm maintenance window approved                  │  │
│   │ [ ] Notify stakeholders of deployment                    │  │
│   │ [ ] Stage deployment media/packages                      │  │
│   │ [ ] Verify backup of affected systems                    │  │
│   │ [ ] Confirm rollback procedure ready                     │  │
│   │ [ ] Verify test environment validated                    │  │
│   │ [ ] Conduct deployment readiness review                  │  │
│   └─────────────────────────────────────────────────────────┘  │
│                                                                  │
│   DEPLOYMENT (Day 0)                                            │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │ [ ] Announce start of maintenance window                 │  │
│   │ [ ] Execute pre-deployment backups                       │  │
│   │ [ ] Install/configure according to procedure             │  │
│   │ [ ] Verify installation success                          │  │
│   │ [ ] Execute functional tests                             │  │
│   │ [ ] Execute integration tests                            │  │
│   │ [ ] Validate security configurations                     │  │
│   │ [ ] Confirm monitoring operational                       │  │
│   └─────────────────────────────────────────────────────────┘  │
│                                                                  │
│   POST-DEPLOYMENT (Day +1 to +7)                                │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │ [ ] Monitor for issues                                   │  │
│   │ [ ] Address any problems                                 │  │
│   │ [ ] Collect user feedback                                │  │
│   │ [ ] Complete documentation                               │  │
│   │ [ ] Conduct lessons learned                              │  │
│   │ [ ] Close deployment activities                          │  │
│   └─────────────────────────────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### 📖 18.2.3 Cutover Strategies

Different strategies for transitioning from old to new systems.

| Strategy | Description | When to Use |
| --- | --- | --- |
| **Big Bang** | All at once | Simple changes, limited scope |
| **Phased** | Gradual rollout | Large deployments, risk reduction |
| **Parallel** | Run old and new together | Critical systems, validation needed |
| **Pilot** | Test with small group first | New technology, uncertain impact |

**Cutover Strategy Comparison:**

```
┌─────────────────────────────────────────────────────────────────┐
│              CUTOVER STRATEGIES                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   BIG BANG                                                      │
│   ├── Advantages: Fast, clean transition                        │
│   ├── Disadvantages: High risk, no fallback during cutover      │
│   └── Best for: Non-critical systems, simple changes            │
│                                                                  │
│   PHASED                                                        │
│   ├── Advantages: Reduced risk, lessons learned between phases  │
│   ├── Disadvantages: Longer duration, complexity                │
│   └── Best for: Large environments, critical systems            │
│                                                                  │
│   PARALLEL                                                      │
│   ├── Advantages: Validation, easy rollback                     │
│   ├── Disadvantages: Resource intensive, complexity             │
│   └── Best for: Mission-critical systems                        │
│                                                                  │
│   PILOT                                                         │
│   ├── Advantages: Real-world validation, user feedback          │
│   ├── Disadvantages: Limited scope, extended timeline           │
│   └── Best for: New technology, uncertain requirements          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### 📖 18.2.4 Rollback Planning

⚠️ **Important:** Every deployment must have a rollback plan.

**Rollback Plan Components:**

```
┌─────────────────────────────────────────────────────────────────┐
│                  ROLLBACK PLAN                                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   1. ROLLBACK TRIGGERS                                          │
│      • What conditions trigger rollback?                        │
│      • Who has authority to initiate rollback?                  │
│      • What is the decision timeline?                           │
│                                                                  │
│   2. ROLLBACK PROCEDURES                                        │
│      • Step-by-step reversal instructions                       │
│      • Order of operations                                      │
│      • Data preservation requirements                           │
│      • Configuration restoration steps                          │
│                                                                  │
│   3. VALIDATION                                                 │
│      • How to verify rollback success                           │
│      • Testing procedures post-rollback                         │
│      • User notification requirements                           │
│                                                                  │
│   4. POST-ROLLBACK                                              │
│      • Root cause analysis                                      │
│      • Remediation planning                                     │
│      • Re-deployment criteria                                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Common Rollback Triggers:**
- Critical functionality failure
- Unacceptable performance degradation
- Security vulnerability discovered
- Integration failures
- Data corruption
- Exceeding maintenance window

---

### 📖 18.2.5 Change Management

Deployments must follow change management processes.

**Change Management Steps:**

| Step | Description |
| --- | --- |
| **Request** | Submit change request with justification |
| **Review** | Technical review of change |
| **Approve** | CAB or authority approval |
| **Schedule** | Assign maintenance window |
| **Implement** | Execute the change |
| **Verify** | Confirm successful implementation |
| **Close** | Document and close change record |

**Change Documentation:**

```
┌─────────────────────────────────────────────────────────────────┐
│              CHANGE REQUEST TEMPLATE                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   CHANGE REQUEST                                                │
│                                                                  │
│   Change ID: _____________                                      │
│   Requestor: _____________                                      │
│   Date: _____________                                           │
│                                                                  │
│   Description of Change:                                        │
│   [What is being changed]                                       │
│                                                                  │
│   Justification:                                                │
│   [Why change is needed]                                        │
│                                                                  │
│   Affected Systems:                                             │
│   [Systems impacted by change]                                  │
│                                                                  │
│   Risk Assessment:                                              │
│   [ ] Low [ ] Medium [ ] High                                   │
│   [Risk details]                                                │
│                                                                  │
│   Implementation Plan:                                          │
│   [How change will be implemented]                              │
│                                                                  │
│   Rollback Plan:                                                │
│   [How to reverse if needed]                                    │
│                                                                  │
│   Testing Plan:                                                 │
│   [How change will be validated]                                │
│                                                                  │
│   Approvals:                                                    │
│   Technical: _____________ Date: _______                        │
│   Security: _____________ Date: _______                         │
│   CAB: _____________ Date: _______                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### ✅ Check Your Understanding - Section 18.2

### Knowledge Check: Deployment Phases

What are the phases of deployment planning?

1. Only preparation and deployment
2. Only design and testing
3. **Preparation (scope, resources, timeline, risks), Design (architecture, integration, configuration, security), Testing (validation, functional, integration, performance), Deployment (checklist, execution, validation, rollback), Transition (knowledge transfer, documentation, handoff, lessons learned)**
4. Only transition and testing

💡
Deployment planning phases: (1) Preparation - define scope, identify resources, establish timeline, identify risks, (2) Design - architecture decisions, integration points, configuration specifications, security requirements, (3) Testing - test environment validation, functional testing, integration testing, performance testing, (4) Deployment - pre-deployment checklist, execution steps, validation procedures, rollback triggers, (5) Transition - knowledge transfer, documentation completion, support handoff, lessons learned.

### Knowledge Check: Pre-Deployment Activities

What should be done during pre-deployment activities?

1. Only notify stakeholders
2. Only verify backups
3. **Verify prerequisites met, Confirm maintenance window approved, Notify stakeholders, Stage deployment media, Verify backups, Confirm rollback procedure ready, Verify test environment validated, Conduct deployment readiness review**
4. Only stage deployment media

💡
Pre-deployment activities include: Verify all prerequisites met, Confirm maintenance window approved, Notify stakeholders of deployment, Stage deployment media/packages, Verify backup of affected systems, Confirm rollback procedure ready, Verify test environment validated, and Conduct deployment readiness review.

### Knowledge Check: Cutover Strategies

What are the four main cutover strategies?

1. Fast, Slow, Medium, Custom
2. **Big Bang (all at once - simple, non-critical), Phased (gradual rollout - large environments), Parallel (run old and new together - critical systems), Pilot (test with small group first - new technology)**
3. Manual, Automatic, Hybrid, Scripted
4. Planned, Emergency, Routine, Urgent

💡
Four cutover strategies: Big Bang (all at once, best for simple changes and non-critical systems), Phased (gradual rollout, best for large deployments and risk reduction), Parallel (run old and new together, best for critical systems needing validation), Pilot (test with small group first, best for new technology with uncertain impact).

### Knowledge Check: Rollback Plan

What should a rollback plan include?

1. Only rollback procedures
2. Only rollback triggers
3. **Rollback triggers (conditions, authority, timeline), Rollback procedures (steps, order, data preservation, configuration restoration), Validation (verify success, testing, user notification), Post-rollback activities (root cause, remediation, re-deployment criteria)**
4. Only post-rollback activities

💡
Rollback plan components: Rollback triggers (what conditions trigger rollback, who has authority, decision timeline), Rollback procedures (step-by-step reversal, order of operations, data preservation, configuration restoration), Validation (how to verify success, testing procedures, user notification), Post-rollback (root cause analysis, remediation planning, re-deployment criteria).

### Knowledge Check: Change Management

What are the steps in change management?

1. Only request and approve
2. Only implement and verify
3. **Request (submit with justification), Review (technical review), Approve (CAB approval), Schedule (assign maintenance window), Implement (execute change), Verify (confirm success), Close (document and close record)**
4. Only schedule and close

💡
Change management steps: Request (submit change request with justification), Review (technical review of change), Approve (CAB or authority approval), Schedule (assign maintenance window), Implement (execute the change), Verify (confirm successful implementation), Close (document and close change record).

---

### 📋 Progress Checkpoint - Section 18.2

Before proceeding to Section 18.3, verify the ability to accomplish the following:

- [ ]  Explain deployment planning phases
- [ ]  Develop implementation procedures
- [ ]  Select appropriate cutover strategies
- [ ]  Create rollback plans
- [ ]  Apply change management processes

**If all items are checked, proceed to Section 18.3.**

**If any items remain unchecked, review the relevant subsections before continuing.**

---

## Section 18.3: Impact Assessment

**🎯 Learning Objective:** Assess operational and mission impacts of implementations

---

### 📖 18.3.1 Types of Impact Assessment

Impact assessment evaluates effects of cyber defense implementations.

```
┌─────────────────────────────────────────────────────────────────┐
│              TYPES OF IMPACT ASSESSMENT                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   OPERATIONAL IMPACT                                            │
│   ├── Effect on day-to-day operations                          │
│   ├── User experience changes                                   │
│   ├── Process modifications required                            │
│   └── Support requirements                                      │
│                                                                  │
│   PERFORMANCE IMPACT                                            │
│   ├── System resource usage                                     │
│   ├── Network bandwidth consumption                             │
│   ├── Application response times                                │
│   └── Processing throughput                                     │
│                                                                  │
│   MISSION IMPACT                                                │
│   ├── Effect on mission essential functions                     │
│   ├── Critical capability availability                          │
│   ├── Mission readiness                                         │
│   └── Operational effectiveness                                 │
│                                                                  │
│   SECURITY IMPACT                                               │
│   ├── Security posture changes                                  │
│   ├── Risk reduction achieved                                   │
│   ├── New vulnerabilities introduced                            │
│   └── Compliance implications                                   │
│                                                                  │
│   RESOURCE IMPACT                                               │
│   ├── Personnel requirements                                    │
│   ├── Budget implications                                       │
│   ├── Equipment needs                                           │
│   └── Ongoing maintenance costs                                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### 📖 18.3.2 Operational Impact Analysis

Assess how implementation affects operations.

**Operational Impact Factors:**

| Factor | Assessment Questions |
| --- | --- |
| **Availability** | Will systems be unavailable? For how long? |
| **Functionality** | Will any capabilities be affected? |
| **Processes** | Will procedures need to change? |
| **Users** | How will users be affected? |
| **Support** | Will support requirements change? |

**Operational Impact Assessment Template:**

```
┌─────────────────────────────────────────────────────────────────┐
│         OPERATIONAL IMPACT ASSESSMENT                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   IMPLEMENTATION: _____________                                 │
│   DATE: _____________                                           │
│   ASSESSOR: _____________                                       │
│                                                                  │
│   1. AVAILABILITY IMPACT                                        │
│      Expected downtime: _____________                           │
│      Systems affected: _____________                            │
│      Mitigation: _____________                                  │
│                                                                  │
│   2. FUNCTIONALITY IMPACT                                       │
│      Features affected: _____________                           │
│      Workarounds available: [ ] Yes [ ] No                      │
│      Duration of impact: _____________                          │
│                                                                  │
│   3. USER IMPACT                                                │
│      Users affected: _____________                              │
│      Training required: [ ] Yes [ ] No                          │
│      Communication needed: _____________                        │
│                                                                  │
│   4. PROCESS IMPACT                                             │
│      Procedures to update: _____________                        │
│      Documentation changes: _____________                       │
│                                                                  │
│   5. OVERALL OPERATIONAL IMPACT                                 │
│      [ ] Minimal [ ] Moderate [ ] Significant [ ] Severe        │
│                                                                  │
│   RECOMMENDATIONS:                                              │
│   _____________                                                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### 📖 18.3.3 Performance Impact Considerations

Measure performance effects before and after implementation.

**Performance Metrics to Assess:**

| Category | Metrics |
| --- | --- |
| **System** | CPU utilization, memory usage, disk I/O |
| **Network** | Bandwidth, latency, packet loss |
| **Application** | Response time, transaction rate, error rate |
| **User** | Page load time, login time, search response |

**Performance Assessment Process:**

```
┌─────────────────────────────────────────────────────────────────┐
│          PERFORMANCE ASSESSMENT PROCESS                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   1. BASELINE MEASUREMENT                                       │
│      • Measure current performance                              │
│      • Document metrics under normal load                       │
│      • Capture peak load performance                            │
│      • Record user experience metrics                           │
│                                                                  │
│   2. PREDICTED IMPACT                                           │
│      • Estimate resource requirements                           │
│      • Calculate expected performance change                    │
│      • Identify potential bottlenecks                           │
│      • Define acceptable thresholds                             │
│                                                                  │
│   3. POST-IMPLEMENTATION MEASUREMENT                            │
│      • Measure performance after deployment                     │
│      • Compare to baseline                                      │
│      • Identify any degradation                                 │
│      • Verify acceptable thresholds met                         │
│                                                                  │
│   4. OPTIMIZATION                                               │
│      • Tune configuration if needed                             │
│      • Address bottlenecks                                      │
│      • Re-measure after optimization                            │
│      • Document final performance                               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### 📖 18.3.4 Mission Impact Considerations

📋 **Doctrinal Reference - CWP 3-0.1:**
“Update MRT-C data annually, or as the environment changes, to provide and maintain a strategic view of system and asset dependencies relevant to DOD strategic missions, and enable decision-makers to determine the mission impact resulting from MRT-C loss or degradation.”

**Mission Impact Assessment:**

```
┌─────────────────────────────────────────────────────────────────┐
│              MISSION IMPACT ASSESSMENT                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ASSESS IMPACT ON:                                             │
│                                                                  │
│   MISSION ESSENTIAL FUNCTIONS (MEFs)                            │
│   ├── Will implementation affect any MEFs?                      │
│   ├── During implementation (temporary)?                        │
│   ├── After implementation (permanent)?                         │
│   └── Risk to mission accomplishment?                           │
│                                                                  │
│   TASK CRITICAL ASSETS (TCAs)                                   │
│   ├── Will any TCAs be affected?                                │
│   ├── Impact on TCA availability?                               │
│   ├── Impact on TCA functionality?                              │
│   └── Risk to dependent missions?                               │
│                                                                  │
│   MISSION RELEVANT TERRAIN IN CYBERSPACE (MRT-C)                │
│   ├── Will MRT-C be modified?                                   │
│   ├── New MRT-C being added?                                    │
│   ├── MRT-C mapping updates required?                           │
│   └── Impact on mission threads?                                │
│                                                                  │
│   OPERATIONAL READINESS                                         │
│   ├── Impact on readiness posture?                              │
│   ├── Degradation during implementation?                        │
│   ├── Improvement after implementation?                         │
│   └── Net effect on capability?                                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### 📖 18.3.5 Resource Requirements

Assess resources needed to implement and sustain.

| Resource Category | Considerations |
| --- | --- |
| **Personnel** | Installation, configuration, ongoing support |
| **Training** | User training, administrator training |
| **Equipment** | Hardware, licenses, infrastructure |
| **Budget** | Initial cost, ongoing costs, maintenance |
| **Time** | Implementation duration, ongoing effort |

---

### 📖 18.3.6 Sustainability Planning

Plan for long-term sustainability of implementations.

```
┌─────────────────────────────────────────────────────────────────┐
│              SUSTAINABILITY PLANNING                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ONGOING REQUIREMENTS:                                         │
│                                                                  │
│   MAINTENANCE                                                   │
│   ├── Patch management                                          │
│   ├── Signature updates                                         │
│   ├── Configuration management                                  │
│   └── Performance monitoring                                    │
│                                                                  │
│   SUPPORT                                                       │
│   ├── Help desk training                                        │
│   ├── Escalation procedures                                     │
│   ├── Vendor support contracts                                  │
│   └── Documentation maintenance                                 │
│                                                                  │
│   RESOURCES                                                     │
│   ├── Personnel assignments                                     │
│   ├── Budget allocations                                        │
│   ├── Equipment refresh cycles                                  │
│   └── License renewals                                          │
│                                                                  │
│   IMPROVEMENT                                                   │
│   ├── Performance optimization                                  │
│   ├── Capability enhancement                                    │
│   ├── Integration expansion                                     │
│   └── Continuous improvement                                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### ✅ Check Your Understanding - Section 18.3

### Knowledge Check: Impact Types

What are the main types of impact assessment?

1. Only operational and performance
2. Only mission and security
3. **Operational impact (day-to-day operations), Performance impact (resource usage, response times), Mission impact (MEFs, TCAs, MRT-C), Security impact (posture, risk, compliance), Resource impact (personnel, budget, equipment)**
4. Only resource impact

💡
Types of impact assessment: Operational impact (effect on day-to-day operations, user experience, process modifications), Performance impact (system resource usage, network bandwidth, application response times), Mission impact (effect on MEFs, TCA availability, mission readiness), Security impact (security posture changes, risk reduction, vulnerabilities), Resource impact (personnel requirements, budget implications, equipment needs).

### Knowledge Check: Operational Factors

What factors should be assessed for operational impact?

1. Only availability
2. Only user impact
3. **Availability (system downtime), Functionality (capabilities affected), Processes (procedure changes), Users (how affected), Support (requirement changes)**
4. Only support requirements

💡
Operational impact factors: Availability (Will systems be unavailable? For how long?), Functionality (Will any capabilities be affected?), Processes (Will procedures need to change?), Users (How will users be affected?), Support (Will support requirements change?). Overall operational impact is rated as minimal, moderate, significant, or severe.

### Knowledge Check: Performance Metrics

What metrics should be measured for performance impact?

1. Only CPU and memory
2. Only network bandwidth
3. **System (CPU, memory, disk I/O), Network (bandwidth, latency, packet loss), Application (response time, transaction rate, error rate), User (page load time, login time, search response)**
4. Only application response time

💡
Performance metrics to assess: System (CPU utilization, memory usage, disk I/O), Network (bandwidth, latency, packet loss), Application (response time, transaction rate, error rate), User (page load time, login time, search response). The assessment process includes baseline measurement, predicted impact, post-implementation measurement, and optimization.

### Knowledge Check: Mission Impact

What should be assessed for mission impact?

1. Only MEFs
2. Only TCAs
3. **Mission Essential Functions (MEFs) - effect on functions, temporary/permanent impact; Task Critical Assets (TCAs) - availability, functionality impact; MRT-C - modifications, mapping updates; Operational readiness - readiness posture, degradation, improvement**
4. Only operational readiness

💡
Mission impact assessment areas: Mission Essential Functions (MEFs) - will implementation affect MEFs, during or after implementation, risk to mission accomplishment; Task Critical Assets (TCAs) - will TCAs be affected, impact on availability and functionality; MRT-C - modifications, new MRT-C added, mapping updates required; Operational readiness - impact on readiness posture, degradation during implementation, improvement after.

### Knowledge Check: Sustainability Planning

What does sustainability planning address?

1. Only maintenance
2. Only support
3. **Maintenance (patches, updates, configuration, monitoring), Support (help desk, escalation, vendor contracts, documentation), Resources (personnel, budget, equipment refresh, licenses), Improvement (optimization, enhancement, integration, continuous improvement)**
4. Only resources

💡
Sustainability planning addresses: Maintenance (patch management, signature updates, configuration management, performance monitoring), Support (help desk training, escalation procedures, vendor support contracts, documentation maintenance), Resources (personnel assignments, budget allocations, equipment refresh cycles, license renewals), Improvement (performance optimization, capability enhancement, integration expansion, continuous improvement).

---

### 📋 Progress Checkpoint - Section 18.3

Before proceeding to Section 18.4, verify the ability to accomplish the following:

- [ ]  Identify types of impact assessment
- [ ]  Conduct operational impact analysis
- [ ]  Assess performance impact
- [ ]  Evaluate mission impact
- [ ]  Plan for sustainability

**If all items are checked, proceed to Section 18.4.**

**If any items remain unchecked, review the relevant subsections before continuing.**

---

## Section 18.4: Critical Infrastructure Protection

**🎯 Learning Objective:** Identify and prioritize protection of critical infrastructure

---

### 📖 18.4.1 Critical Infrastructure Concepts

Understanding critical infrastructure is essential for prioritizing protection.

📋 **Doctrinal Reference - DODD 3020.40:**
Mission Assurance establishes requirements for protecting critical assets and key resources.

```
┌─────────────────────────────────────────────────────────────────┐
│              CRITICAL ASSET HIERARCHY                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │                DEFENSE CRITICAL ASSETS (DCA)             │  │
│   │   Most critical - incapacitation has very serious,       │  │
│   │   debilitating effect on DOD mission fulfillment         │  │
│   │   • Nominated by CJCS from TCAs                          │  │
│   │   • Highest priority for protection                      │  │
│   └─────────────────────────────────────────────────────────┘  │
│                           │                                      │
│                           ▼                                      │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │              TASK CRITICAL ASSETS (TCA)                  │  │
│   │   • Tier 1: Mission failure at DOD Component level       │  │
│   │   • Tier 2: Significant degradation of mission           │  │
│   │   • Tier 3: Moderate impact on mission                   │  │
│   └─────────────────────────────────────────────────────────┘  │
│                           │                                      │
│                           ▼                                      │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │                    TASK ASSETS                           │  │
│   │   Supporting assets that enable mission functions        │  │
│   │   but are not individually critical                      │  │
│   └─────────────────────────────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### 📖 18.4.2 Identifying Critical Assets

📋 **Doctrinal Reference - CWP 3-33.4:**
“USCYBERCOM and subordinate commanders use the criticality, threat, and vulnerability methodology to assess risk and identify priority for CPT task management.”

**CPT Prioritization Based on Criticality:**
- Defense Critical Infrastructure Program DCAs
- Tier 1 TCAs
- Tier 2 TCAs
- Tier 3 TCAs
- Task Assets

**Critical Asset Identification Process:**

```
┌─────────────────────────────────────────────────────────────────┐
│         CRITICAL ASSET IDENTIFICATION                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   1. MISSION DECOMPOSITION                                      │
│      • Identify Mission Essential Functions (MEFs)              │
│      • Identify Mission Essential Tasks (METs)                  │
│      • Map capabilities to missions                             │
│                                                                  │
│   2. ASSET MAPPING                                              │
│      • Identify assets supporting each capability               │
│      • Determine dependencies                                   │
│      • Document mission threads                                 │
│                                                                  │
│   3. CRITICALITY ASSESSMENT                                     │
│      • Assess impact of asset loss                              │
│      • Determine mission failure potential                      │
│      • Assign criticality tier                                  │
│                                                                  │
│   4. MRT-C IDENTIFICATION                                       │
│      • Identify cyberspace terrain supporting assets            │
│      • Map physical and logical components                      │
│      • Document in designated system                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### 📖 18.4.3 Prioritizing Protection Efforts

Protection efforts must be prioritized based on criticality, threat, and vulnerability.

**Prioritization Methodology:**

| Factor | Assessment |
| --- | --- |
| **Criticality** | How important is the asset to the mission? |
| **Threat** | What threats target this asset? |
| **Vulnerability** | How vulnerable is the asset? |
| **Risk** | Combination of threat, vulnerability, impact |

```
┌─────────────────────────────────────────────────────────────────┐
│            PROTECTION PRIORITIZATION                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│                    HIGH CRITICALITY                              │
│                          │                                       │
│              ┌───────────┼───────────┐                          │
│              │           │           │                          │
│         HIGH THREAT  MED THREAT  LOW THREAT                     │
│              │           │           │                          │
│         ┌────┴────┐  ┌───┴───┐   ┌───┴───┐                     │
│         │HIGH│MED │  │MED│LOW│   │LOW│   │                     │
│         │VULN│VULN│  │VUL│VUL│   │VUL│   │                     │
│         └────┴────┘  └───┴───┘   └───┴───┘                     │
│           │   │        │   │       │                            │
│           ▼   ▼        ▼   ▼       ▼                            │
│          P1  P1       P2  P2      P3                            │
│                                                                  │
│   PRIORITY LEVELS:                                              │
│   P1 - Immediate attention required                             │
│   P2 - High priority protection                                 │
│   P3 - Standard protection measures                             │
│   P4 - Routine protection                                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### 📖 18.4.4 Key Resource Protection

Protecting key resources that support critical assets.

**Key Resources Include:**
- Network infrastructure (routers, switches, firewalls)
- Server infrastructure (domain controllers, file servers)
- Security infrastructure (IDS/IPS, SIEM, AV management)
- Supporting services (DNS, DHCP, authentication)
- Data repositories (databases, file shares)
- Communications systems (email, VoIP)

**Protection Measures:**

```
┌─────────────────────────────────────────────────────────────────┐
│              KEY RESOURCE PROTECTION                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   PHYSICAL PROTECTION                                           │
│   ├── Secure facilities                                         │
│   ├── Access controls                                           │
│   ├── Environmental controls                                    │
│   └── Redundancy                                                │
│                                                                  │
│   LOGICAL PROTECTION                                            │
│   ├── Access controls                                           │
│   ├── Encryption                                                │
│   ├── Monitoring                                                │
│   └── Hardening                                                 │
│                                                                  │
│   OPERATIONAL PROTECTION                                        │
│   ├── Backup and recovery                                       │
│   ├── Incident response                                         │
│   ├── Change management                                         │
│   └── Configuration management                                  │
│                                                                  │
│   PERSONNEL PROTECTION                                          │
│   ├── Security awareness                                        │
│   ├── Access management                                         │
│   ├── Insider threat mitigation                                 │
│   └── Training                                                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### 📖 18.4.5 Coordination Requirements

Protecting critical infrastructure requires coordination.

📋 **Doctrinal Reference - CWP 3-0.1:**
“In coordination with capability providers, identifies CSSPs for TCA MRT-C and enters CSSP information into the designated system.”

**Coordination for Critical Infrastructure:**

| Stakeholder | Coordination Purpose |
| --- | --- |
| **Mission Owner** | Validate criticality, provide mission context |
| **Asset Owner** | Physical maintenance, protection implementation |
| **Capability Provider** | Ensure functionality, maintain capability |
| **CSSP** | Cybersecurity services, monitoring |
| **CPT** | Advanced defensive operations |
| **Intelligence** | Threat information, warnings |

---

### 📖 18.4.6 Alignment with MRT-C Mapping

📋 **Doctrinal Reference - CWP 3-0.1:**
“Mapped MRT-C enables power projection and freedom of action across all operational domains. Identified MRT-C is critical to warfighting capability resilience, understanding mapped MRT-C informs prioritizations to support planning, execution, and assessment.”

**MRT-C Alignment:**

```
┌─────────────────────────────────────────────────────────────────┐
│              MRT-C ALIGNMENT                                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ENSURE IMPLEMENTATIONS:                                       │
│                                                                  │
│   1. SUPPORT MRT-C                                              │
│      • Don't degrade MRT-C functionality                        │
│      • Enhance protection of MRT-C                              │
│      • Maintain visibility into MRT-C                           │
│                                                                  │
│   2. UPDATE MRT-C MAPPING                                       │
│      • Document new cyber defense infrastructure                │
│      • Update dependencies                                      │
│      • Reflect changes in designated system                     │
│                                                                  │
│   3. INFORM RISK MANAGEMENT                                     │
│      • Input to Risk Response Plans (RRP)                       │
│      • Input to Mission Mitigation Plans (MMP)                  │
│      • Input to Operational Risk Assessments (ORA)              │
│                                                                  │
│   4. SUPPORT MISSION ASSURANCE                                  │
│      • Enhance resilience                                       │
│      • Reduce vulnerability                                     │
│      • Improve detection capability                             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### ✅ Check Your Understanding - Section 18.4

### Knowledge Check: TCA vs DCA

What is the difference between a TCA and a DCA?

1. TCAs are for networks; DCAs are for systems
2. TCAs are local; DCAs are enterprise-wide
3. **TCA: Asset whose incapacitation has serious, debilitating effect on mission capability; DCA: Asset of extraordinary importance where incapacitation has very serious, debilitating effect on DOD’s ability to fulfill missions (nominated from TCAs by CJCS)**
4. TCAs are temporary; DCAs are permanent

💡
TCA (Task Critical Asset): Asset whose incapacitation would have a serious, debilitating effect on mission capability. TCAs are tiered: Tier 1 (mission failure at DOD Component level), Tier 2 (significant degradation), Tier 3 (moderate impact). DCA (Defense Critical Asset): Asset of extraordinary importance where incapacitation would have a very serious, debilitating effect on DOD’s ability to fulfill missions. DCAs are nominated by CJCS from TCAs and receive highest priority for protection.

### Knowledge Check: TCA Tiers

What are the TCA tiers?

1. Critical, High, Medium, Low
2. **Tier 1 (Mission failure at DOD Component level), Tier 2 (Significant degradation of mission), Tier 3 (Moderate impact on mission)**
3. Priority 1, Priority 2, Priority 3
4. Essential, Important, Standard

💡
TCA tiers: Tier 1 - Mission failure at DOD Component level, Tier 2 - Significant degradation of mission, Tier 3 - Moderate impact on mission. CPT prioritization follows: Defense Critical Infrastructure Program DCAs, then Tier 1 TCAs, Tier 2 TCAs, Tier 3 TCAs, and Task Assets.

### Knowledge Check: Prioritization Methodology

What methodology is used to prioritize protection?

1. Only criticality assessment
2. Only threat assessment
3. **Criticality (how important to mission), Threat (what threats target asset), and Vulnerability (how vulnerable is asset) methodology to assess risk and identify priority**
4. Only vulnerability assessment

💡
Per CWP 3-33.4, USCYBERCOM and subordinate commanders use the criticality, threat, and vulnerability methodology to assess risk and identify priority for CPT task management. Criticality assesses importance to mission, Threat assesses what threats target the asset, Vulnerability assesses how vulnerable the asset is, and Risk combines these factors.

### Knowledge Check: Protection Measures

What types of protection measures should be applied to key resources?

1. Only physical and logical
2. Only operational and personnel
3. **Physical (secure facilities, access controls, environmental, redundancy), Logical (access controls, encryption, monitoring, hardening), Operational (backup/recovery, incident response, change/config management), Personnel (security awareness, access management, insider threat, training)**
4. Only logical protection

💡
Protection measures include: Physical (secure facilities, access controls, environmental controls, redundancy), Logical (access controls, encryption, monitoring, hardening), Operational (backup and recovery, incident response, change management, configuration management), Personnel (security awareness, access management, insider threat mitigation, training).

### Knowledge Check: MRT-C Alignment

How should implementations align with MRT-C?

1. Only update MRT-C mapping
2. Only support mission assurance
3. **Support MRT-C (don’t degrade, enhance protection, maintain visibility), Update MRT-C mapping (document new infrastructure, update dependencies), Inform risk management (RRP, MMP, ORA input), Support mission assurance (enhance resilience, reduce vulnerability, improve detection)**
4. Only inform risk management

💡
Implementations should align with MRT-C by: Supporting MRT-C (don’t degrade functionality, enhance protection, maintain visibility), Updating MRT-C mapping (document new cyber defense infrastructure, update dependencies, reflect changes in designated system), Informing risk management (input to Risk Response Plans, Mission Mitigation Plans, Operational Risk Assessments), Supporting mission assurance (enhance resilience, reduce vulnerability, improve detection capability).

---

### 📋 Progress Checkpoint - Section 18.4

Before proceeding to the Conclusion, verify the ability to accomplish the following:

- [ ]  Understand TCA and DCA concepts
- [ ]  Identify critical assets
- [ ]  Apply prioritization methodology
- [ ]  Implement key resource protection
- [ ]  Coordinate for critical infrastructure
- [ ]  Align implementations with MRT-C

**If all items are checked, proceed to the Conclusion.**

**If any items remain unchecked, review the relevant subsections before continuing.**

---

## Conclusion

This lesson established comprehensive understanding of implementation and coordination for cyber defense infrastructure. These skills ensure successful deployment of security tools while minimizing operational impacts and protecting critical infrastructure. Implementation and coordination capabilities are essential for Cyber Defense Infrastructure Support Specialists responsible for deploying and maintaining cyber defense capabilities.

### Key Takeaways

**Stakeholder Identification**
Internal stakeholders include System Administrators (manage systems), Network Administrators (manage infrastructure), Security Management (approve implementations), Operations Staff (use systems), Help Desk (support users), and Leadership (approve and provide resources). External stakeholders include CSSPs (provide cybersecurity services), CPTs (conduct defensive operations), JFHQ-DODIN (synchronize defense), Higher HQ (provide guidance), and Vendors (support products).

**System Administrator Coordination**
Coordination areas include Requirements (resources needed), Access (administrative access for installation), Scheduling (maintenance windows), Dependencies (prerequisite software/configurations), Testing (test bed creation and validation), and Support (ongoing maintenance). The coordination process flows through Initial engagement, Requirements gathering, Planning, Execution, and Transition.

**CSSP and CPT Coordination**
CSSPs provide expertise and assistance in MRT-C identification, assessment, prioritization, risk management, and monitoring. Coordinate with CSSPs before (notify, verify, coordinate integration), during (status updates, address issues), and after (confirm log flow, verify alerts) implementation. CPT pre-mission planning considerations include Special Authority to Operate, account/system accesses, physical access, travel/lodging, transportation, training requirements, special equipment, and PPE/weapons.

**Deployment Planning Phases**
Five phases: Preparation (define scope, identify resources, establish timeline, identify risks), Design (architecture, integration points, configurations, security), Testing (environment validation, functional, integration, performance), Deployment (pre-deployment checklist, execution, validation, rollback triggers), and Transition (knowledge transfer, documentation, support handoff, lessons learned).

**Cutover Strategies**
Four strategies: Big Bang (all at once, best for simple/non-critical), Phased (gradual rollout, best for large environments), Parallel (run old and new together, best for critical systems), and Pilot (test with small group, best for new technology). Every deployment must have a rollback plan with triggers, procedures, validation, and post-rollback activities.

**Change Management**
Seven steps: Request (submit with justification), Review (technical review), Approve (CAB approval), Schedule (assign maintenance window), Implement (execute change), Verify (confirm success), Close (document and close record). Change documentation includes description, justification, affected systems, risk assessment, implementation plan, rollback plan, testing plan, and approvals.

**Impact Assessment Types**
Five types: Operational impact (day-to-day operations, user experience, process changes), Performance impact (resource usage, bandwidth, response times), Mission impact (MEFs, TCAs, MRT-C, operational readiness), Security impact (posture changes, risk reduction, new vulnerabilities), and Resource impact (personnel, budget, equipment needs).

**Mission Impact Considerations**
Assess impact on MEFs (effect on functions, temporary/permanent, risk to mission), TCAs (availability, functionality, dependent missions), MRT-C (modifications, new MRT-C, mapping updates, mission threads), and Operational readiness (readiness posture, degradation during implementation, improvement after). Update MRT-C data annually or as the environment changes.

**Critical Asset Hierarchy**
DCAs (Defense Critical Assets) are most critical, nominated by CJCS from TCAs, highest priority for protection. TCAs (Task Critical Assets) are tiered: Tier 1 (mission failure), Tier 2 (significant degradation), Tier 3 (moderate impact). Task Assets support mission functions but are not individually critical.

**Prioritization Methodology**
Use criticality (importance to mission), threat (what targets the asset), and vulnerability (how vulnerable) to assess risk and identify priority. Priority levels: P1 (immediate attention), P2 (high priority), P3 (standard protection), P4 (routine protection). Protection measures include physical, logical, operational, and personnel categories.

### KSAT Application

| KSAT ID | Application in This Lesson |
| --- | --- |
| T0393B | Coordinating with system administrators for deployment planning, requirements gathering, test bed creation, scheduling maintenance windows, and establishing ongoing support responsibilities |
| T2772 | Building and installing cyber defense hardware following deployment procedures, configuring systems per specifications, testing functionality, and validating integration |
| T5090 | Assessing operational, performance, mission, security, and resource impacts; planning for sustainability including maintenance, support, resources, and continuous improvement |
| T0960 | Identifying critical assets using TCA/DCA hierarchy, prioritizing protection using criticality/threat/vulnerability methodology, coordinating with stakeholders, aligning with MRT-C mapping |

### Preparation for the Lab

The Lesson 18 Lab provides hands-on application of implementation and coordination concepts through a SIEM deployment scenario. Prior to beginning the lab, ensure mastery of the following:

- Stakeholder coordination plan development including stakeholder matrix and communication plan
- Deployment plan creation with scope, schedule, cutover strategy, and rollback procedures
- Impact assessment across operational, performance, mission, security, and resource dimensions
- Critical infrastructure analysis including asset criticality, protection prioritization, and MRT-C considerations
- Deployment execution and validation procedures

The lab environment presents a multi-source SIEM deployment requiring complete stakeholder coordination, deployment planning, impact assessment, and execution.

### Bridge to Lesson 19

Lesson 19: Capstone Project integrates all course knowledge and skills into a comprehensive cyber defense infrastructure project. The capstone applies everything learned from Lessons 1-18 and demonstrates readiness for the Cyber Defense Infrastructure Support Specialist role. The implementation and coordination skills from this lesson form a critical foundation for the capstone project.

---

## Appendix A: Implementation Quick Reference

### Stakeholder Coordination

- System Administrators
- Network Administrators
- Security Management
- CSSPs
- CPTs
- JFHQ-DODIN

### Deployment Phases

1. Preparation
2. Design
3. Testing
4. Deployment
5. Transition

### Cutover Strategies

- Big Bang
- Phased
- Parallel
- Pilot

### Impact Types

- Operational
- Performance
- Mission
- Security
- Resource

---

## Appendix B: Glossary

| Term | Definition |
| --- | --- |
| **CAB** | Change Advisory Board |
| **CSSP** | Cybersecurity Service Provider |
| **DCA** | Defense Critical Asset |
| **JFHQ-DODIN** | Joint Force Headquarters - DODIN |
| **MEF** | Mission Essential Function |
| **MET** | Mission Essential Task |
| **MRT-C** | Mission Relevant Terrain in Cyberspace |
| **TCA** | Task Critical Asset |

---

## Appendix C: Additional Resources

### Doctrinal References

- CWP 3-33.4, CPT Organization, Functions, and Employment
- CWP 3-0.1, Identification of Mission Relevant Terrain in Cyberspace
- DODD 3020.40, Mission Assurance
- DODI 3020.45, Mission Assurance Construct

### Related Lessons

- Lesson 5: Mission Relevant Terrain in Cyberspace
- Lesson 15: CPT Operations Support
- Lesson 17: Testing and Evaluation
- Lesson 19: Capstone Project

---

*End of Lesson*