# LAB-183: Cybersecurity Scenarios - Lab Manual

Owner: Eric Starace
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

## Lab Resources

### VMs

- Elastic IP: `http://10.10.10.100:5601`
- Username: `analyst`
- Password: `S3cureP@ssw0rd1!`

### Reference Material

- Module 1 reading content
- MITRE ATT&CK website (https://attack.mitre.org) - optional reference

---

## Task 1: CIA Triad Analysis

**Estimated Time:** 30-40 minutes

### Objective

Apply CIA Triad principles to analyze three DoD scenarios, determining which security properties are most critical and what controls should be implemented.

### Background

The CIA Triad—Confidentiality, Integrity, and Availability—provides the foundation for analyzing security requirements. Different mission contexts prioritize these properties differently. Understanding these trade-offs is essential for Cyber Defense Infrastructure Support Specialists.

### Instructions

For each scenario below, the learner should complete the analysis worksheet. The learner should consider the mission context, potential threats, and operational requirements.

1. Open a terminal window
2. Navigate to the lab files directory 
    
    ```python
    cd Desktop/lab_files/
    ```
    
3. Run Jupyter Lab
    1. This will block the terminal. Open another terminal tab or window for running other commands.
    
    ```python
    jupyter lab
    ```
    
4. In the web browser that opens, select **process_parquet.ipynb** in the left pane.
5. Follow along with the explanations below. 
    1. Press the play button in the menu bar to run each cell to observe its functionality.

---

---

## Task 2: Threat Actor Analysis

**Estimated Time:** 45-60 minutes

### Objective

Analyze threat actor capabilities, motivations, and likely attack methods against DoD systems.

### Instructions

The learner will analyze two different threat actors and assess how each would approach attacking a specified DoD system.

---

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

---

## Task 4: Ethical Scenarios

**Estimated Time:** 30-40 minutes

### Objective

Apply legal and ethical principles to realistic cybersecurity dilemmas in DoD contexts.

### Instructions

Read each scenario carefully. For each, identify the ethical considerations, applicable policies, and recommend a course of action. Document the reasoning.

---

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