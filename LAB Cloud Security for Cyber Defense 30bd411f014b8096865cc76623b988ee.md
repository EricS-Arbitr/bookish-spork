# LAB: Cloud Security for Cyber Defense

Owner: Eric Starace
Last edited by: Eric Starace

# LAB: Cloud Security for Cyber Defense

## Cyber Defense Infrastructure Support Specialist Course

| **Estimated Completion Time** | 2.5–3 hours |
| --- | --- |
| **Prerequisites** | Lesson 13 (Cloud Security for Cyber Defense); Lesson 11 (RMF) recommended |
| **Lab Type** | Planning, architecture design, and documentation |
| **Classification** | UNCLASSIFIED // FOR TRAINING USE ONLY |

---

## Terminal Learning Objective

Apply cybersecurity strategy to a cloud computing scenario by evaluating cloud service and deployment models against mission requirements, designing a secure cloud architecture with shared responsibility documentation, and developing cloud-specific incident response and migration procedures for a DoD cyber defense application.

## Enabling Learning Objectives

| ELO | Objective |
| --- | --- |
| 13A.1 | Evaluate cloud service models (IaaS, PaaS, SaaS) and deployment models (public, private, community, hybrid) against operational requirements and select the best option with justification |
| 13A.2 | Design a secure cloud architecture including VPC layout, subnet tiers, security groups, and logging configuration, and document the shared responsibility matrix for the selected service model |
| 13A.3 | Develop cloud-specific incident response procedures addressing evidence preservation, CSP coordination, and IR limitations, and create a migration plan using an appropriate migration strategy |

## KSAT Alignment

| KSAT ID | Type | Description |
| --- | --- | --- |
| K6935 | Knowledge (Core) | Knowledge of cloud service models |
| K6938 | Knowledge (Core) | Knowledge of cloud deployment models |
| K1125 | Knowledge (Additional) | Knowledge of cloud-based knowledge management |
| K6210 | Knowledge (Additional) | Knowledge of cloud service models and incident response limitations |
| A6918 | Ability (Additional) | Ability to apply cybersecurity strategy to cloud computing |
| A6919 | Ability (Additional) | Ability to determine the best cloud deployment model |
| S6942 | Skill (Additional) | Skill in designing and implementing cloud deployments |
| S6945 | Skill (Additional) | Skill in migrating workloads between cloud models |

---

## Lab Scenario

> **Note:** Due to the nature of government cloud access restrictions, this lab focuses on planning, architecture design, and documentation — the critical skills a CDISS performs before any cloud deployment occurs. These are the same deliverables required for real-world DoD cloud authorization.
> 

**Scenario:** Forward Operating Base (FOB) Kilo needs to deploy a web-based **Equipment Maintenance Tracking** application. This application is currently hosted on-premises on a single Windows Server at the FOB. Command has directed evaluation of cloud hosting to improve availability and reduce local infrastructure burden.

**Application Requirements:**

| Requirement | Detail |
| --- | --- |
| **Users** | ~200 personnel across the FOB |
| **Data Classification** | CUI (Controlled Unclassified Information) — maintenance records, equipment serial numbers, readiness data |
| **Availability** | 99.9% uptime required (mission-impacting if unavailable) |
| **Integration** | Must authenticate against on-premises Active Directory |
| **Connectivity** | FOB has SIPR and NIPR connectivity; application runs on NIPR |
| **Current Stack** | Windows Server 2019, IIS web server, SQL Server database, ~500GB data |
| **Budget** | Limited — cost efficiency is a factor |
| **Compliance** | Must meet DoD CC SRG, FedRAMP authorization required |

You will use this single scenario across all three exercises, building a complete cloud deployment package.

---

## Exercise 1: Cloud Deployment Evaluation

**Estimated Time:** 45 minutes
**ELO Mapping:** 13A.1
**KSAT Coverage:** K6935, K6938, A6919, K1125

### Background

Before any DoD workload moves to the cloud, a formal evaluation must determine the appropriate service model, deployment model, and Impact Level. This evaluation drives the authorization requirements, provider selection, and security architecture. Getting this wrong means either deploying to an environment that cannot protect the data, or over-engineering a solution that wastes resources.

### Step 1.1: Requirements Analysis

Using the scenario requirements, complete the analysis:

| Factor | Assessment |
| --- | --- |
| **Data Classification** | (What classification level? What does this mean for Impact Level?) |
| **Required Impact Level** | (IL2, IL4, IL5, or IL6? Justify based on data type and mission criticality) |
| **Availability Requirement** | (What does 99.9% mean in terms of acceptable downtime per year?) |
| **Integration Constraints** | (What does AD integration require from the cloud architecture?) |
| **Compliance Requirements** | (What authorization framework applies?) |

### Step 1.2: Service Model Evaluation

Evaluate each service model against the FOB Kilo requirements. For each model, assess whether it is suitable and explain the trade-offs.

**IaaS Evaluation:**

| Factor | Assessment |
| --- | --- |
| **Suitability for this workload** | (Suitable / Not Suitable) |
| **What you would manage** |  |
| **What the provider would manage** |  |
| **Pros for this scenario** |  |
| **Cons for this scenario** |  |

**PaaS Evaluation:**

| Factor | Assessment |
| --- | --- |
| **Suitability for this workload** | (Suitable / Not Suitable) |
| **What you would manage** |  |
| **What the provider would manage** |  |
| **Pros for this scenario** |  |
| **Cons for this scenario** |  |

**SaaS Evaluation:**

| Factor | Assessment |
| --- | --- |
| **Suitability for this workload** | (Suitable / Not Suitable) |
| **What you would manage** |  |
| **What the provider would manage** |  |
| **Pros for this scenario** |  |
| **Cons for this scenario** |  |

**Recommended Service Model:** ___________
**Justification:** (Why is this model the best fit? What trade-offs are you accepting?)

### Step 1.3: Deployment Model Evaluation

Evaluate each deployment model:

| Deployment Model | Suitable? | Reason |
| --- | --- | --- |
| **Public Cloud** | Yes / No |  |
| **Private Cloud** | Yes / No |  |
| **Community Cloud** | Yes / No |  |
| **Hybrid Cloud** | Yes / No |  |

**Recommended Deployment Model:** ___________
**Justification:**

### Step 1.4: Provider Recommendation

Based on the required Impact Level and deployment model, recommend a specific provider:

| Field | Recommendation |
| --- | --- |
| **Provider** | (Select from DoD-authorized cloud offerings covered in the lesson) |
| **Impact Level** |  |
| **FedRAMP Baseline** | (Low / Moderate / High) |
| **Rationale** | (Why this provider over alternatives?) |

### Step 1.5: Cloud-Based Knowledge Management Consideration

The FOB also uses Microsoft 365 (DEOS) for email and collaboration. Answer:

1. What service model is DEOS? What are the customer’s security responsibilities?
2. Could the maintenance tracker data be shared via DEOS collaboration tools (SharePoint, Teams)? What data handling considerations apply given the CUI classification?

### Knowledge Check: Cloud Model Selection

1. A colleague recommends deploying the CUI-containing application to a public cloud at IL2 because “it’s cheaper.” What is the correct response?
    1. Agree — cost savings justify the lower Impact Level
    2. Recommend IL6 to be safe
    3. **CUI requires IL4 minimum per the DoD CC SRG; deploying CUI to an IL2 environment violates policy regardless of cost savings — the data classification determines the minimum Impact Level, not the budget**
    4. Request a waiver from the CSP to handle CUI at IL2
    
    💡
    The DoD Cloud Computing Security Requirements Guide is clear: CUI requires IL4 minimum, and CUI supporting critical missions or national security requires IL5. Impact Level requirements are driven by data classification and mission criticality, not by budget. Deploying CUI to a lower IL than required is a policy violation that could result in loss of authorization. Cost optimization should be pursued within the correct IL tier, not by lowering the tier.
    

---

## Exercise 2: Security Architecture and Shared Responsibility

**Estimated Time:** 60 minutes
**ELO Mapping:** 13A.2
**KSAT Coverage:** A6918, S6942

### Background

With the service model, deployment model, and provider selected in Exercise 1, this exercise designs the security architecture and documents the shared responsibility division. These deliverables are required inputs to the RMF authorization process (Lesson 11) — the architecture feeds the SSP system description, and the responsibility matrix defines who is accountable for each security domain.

### Step 2.1: Network Architecture Design

Design the cloud network architecture for the Equipment Maintenance Tracker. Complete the architecture template below.

**VPC/Network Configuration:**

| Field | Value |
| --- | --- |
| **VPC Name** |  |
| **VPC CIDR Block** | (e.g., 10.200.0.0/16) |
| **Region** | (Select a GovCloud region) |

**Subnet Design:**

| Subnet Name | CIDR Block | Public/Private | Purpose | Availability Zone |
| --- | --- | --- | --- | --- |
|  |  | Public | (What goes here? Load balancer? Bastion host?) |  |
|  |  | Private | (Application tier) |  |
|  |  | Private | (Database tier) |  |

**Connectivity:**

| Component | Configuration |
| --- | --- |
| **Internet Gateway** | Yes / No — Justify |
| **NAT Gateway** | Yes / No — Justify |
| **VPN Connection** | Yes / No — Type and destination |

> **Tip:** The application must integrate with on-premises Active Directory. How does traffic get from the cloud VPC to the FOB’s on-premises AD? This drives the VPN requirement and affects subnet routing.
> 

### Step 2.2: Security Group Design

Define security groups for each tier. Apply least privilege — only allow the traffic that is required.

**Web/Load Balancer Tier Security Group:**

| Rule # | Direction | Protocol | Port | Source/Destination | Purpose |
| --- | --- | --- | --- | --- | --- |
| 1 | Inbound |  |  |  |  |
| 2 | Inbound |  |  |  |  |
| 3 | Outbound |  |  |  |  |

**Application Tier Security Group:**

| Rule # | Direction | Protocol | Port | Source/Destination | Purpose |
| --- | --- | --- | --- | --- | --- |
| 1 | Inbound |  |  |  |  |
| 2 | Outbound |  |  |  |  |
| 3 | Outbound |  |  |  |  |

**Database Tier Security Group:**

| Rule # | Direction | Protocol | Port | Source/Destination | Purpose |
| --- | --- | --- | --- | --- | --- |
| 1 | Inbound |  |  |  |  |
| 2 | Outbound |  |  |  |  |

### Step 2.3: Logging and Monitoring Configuration

| Log Type | Enabled? | Destination | Retention | Purpose |
| --- | --- | --- | --- | --- |
| API Audit Logs (CloudTrail/Activity Log) |  |  |  |  |
| VPC Flow Logs |  |  |  |  |
| Application Logs (IIS/Web) |  |  |  |  |
| Database Audit Logs |  |  |  |  |
| Authentication Logs |  |  |  |  |

**SIEM Integration:** Describe how cloud logs will be forwarded to the centralized SIEM (if applicable).

### Step 2.4: Shared Responsibility Matrix

Based on the service model selected in Exercise 1, document who is responsible for each security domain. Mark each cell as **Customer**, **Provider**, or **Shared**, and add a note explaining what the responsible party must do.

| Security Domain | Responsible Party | Notes |
| --- | --- | --- |
| Physical Security |  |  |
| Hypervisor/Virtualization |  |  |
| Operating System |  |  |
| Network Infrastructure |  |  |
| Network Controls (Security Groups) |  |  |
| Application Security |  |  |
| Data Encryption (at rest) |  |  |
| Data Encryption (in transit) |  |  |
| Identity and Access Management |  |  |
| Patch Management |  |  |
| Logging and Monitoring |  |  |
| Backup and Recovery |  |  |
| Incident Response |  |  |
| Compliance Verification |  |  |

### Step 2.5: Encryption Configuration

| Data State | Method | Key Management | Notes |
| --- | --- | --- | --- |
| **Data at Rest** (storage volumes) |  | (CSP-managed keys or customer-managed?) |  |
| **Data at Rest** (database) |  |  |  |
| **Data in Transit** (user to app) |  |  |  |
| **Data in Transit** (app to DB) |  |  |  |
| **Data in Transit** (VPN to on-prem) |  |  |  |

### Knowledge Check: Security Architecture

1. A team member designs the architecture with the database in a public subnet “for easier management access.” What is the problem and how should it be corrected?
    1. No problem — public subnets are fine for databases if security groups are configured
    2. Move the database to a different region instead
    3. **The database must be in a private subnet with no direct internet access; management access should be through a bastion host or VPN connection — placing a CUI database in a public subnet exposes it to the internet and violates least privilege and defense-in-depth principles**
    4. Add a second firewall in front of the database
    
    💡
    Defense-in-depth requires that sensitive resources (especially databases containing CUI) are placed in private subnets with no direct internet route. Management access uses a bastion host in the public subnet or the VPN connection to on-premises. Security groups alone are not sufficient — subnet-level isolation provides an additional layer of protection. This aligns with NIST SP 800-53 SC-7 (Boundary Protection) and AC-4 (Information Flow Enforcement).
    

---

## Exercise 3: Cloud Incident Response and Migration Planning

**Estimated Time:** 45 minutes
**ELO Mapping:** 13A.3
**KSAT Coverage:** K6210, S6945

### Background

Cloud environments introduce incident response challenges that do not exist on-premises — limited physical access, data volatility, CSP dependency, and shared infrastructure. Additionally, migrating the application from on-premises to the cloud design from Exercise 2 requires a structured plan. This exercise addresses both.

### Step 3.1: Cloud IR Procedure Development

Develop incident response procedures for the cloud-hosted Equipment Maintenance Tracker. Use the architecture from Exercise 2.

**IR Preparation:**

| Preparation Item | Configuration |
| --- | --- |
| **Logging enabled** | (List the log types from Step 2.3 that support IR) |
| **Log retention period** |  |
| **Log forwarding destination** |  |
| **CSP support contact procedure** | (How does your organization contact the CSP during an incident?) |
| **Snapshot automation** | (Are volume snapshots configured for evidence preservation?) |

**Detection and Analysis:**

| Detection Source | What It Detects | Alert Configured? |
| --- | --- | --- |
| API Audit Logs |  |  |
| VPC Flow Logs |  |  |
| Application Logs |  |  |
| SIEM Correlation |  |  |

**Containment — Compromised Instance:**

Document the correct sequence of actions when a cloud instance is suspected compromised. Number these steps in the correct order:

| Step # | Action |
| --- | --- |
|  | Notify ISSO and begin incident documentation |
|  | Create snapshots of all attached volumes |
|  | Export and preserve current logs |
|  | Modify the instance’s security group to isolate it (deny all inbound/outbound except management) |
|  | Collect instance metadata (instance ID, IP, launch time, attached volumes, security group history) |
|  | **Do NOT terminate the instance** |

**CSP Coordination:**

| Situation | Contact CSP? | What to Request |
| --- | --- | --- |
| Application-layer compromise (attacker exploited web vulnerability) |  |  |
| Suspected hypervisor or infrastructure compromise |  |  |
| Unauthorized API calls from unknown source |  |  |
| Need forensic data beyond your log access |  |  |

### Step 3.2: Cloud IR Limitations Analysis

For each IR limitation, explain how it applies to the FOB Kilo scenario and what mitigation you have implemented in your architecture (Exercise 2):

| Limitation | Impact on This Scenario | Mitigation in Your Design |
| --- | --- | --- |
| **No physical access to hardware** |  |  |
| **Limited network capture** |  |  |
| **Ephemeral resources** |  |  |
| **CSP dependency for infrastructure-level data** |  |  |
| **Multi-tenancy** |  |  |

### Step 3.3: Migration Plan

Plan the migration of the Equipment Maintenance Tracker from on-premises to the cloud architecture designed in Exercise 2.

**Migration Strategy Selection:**

| Strategy | Applicable? | Rationale |
| --- | --- | --- |
| **Rehost** (lift and shift) |  |  |
| **Replatform** (minor optimization) |  |  |
| **Repurchase** (replace with SaaS) |  |  |
| **Refactor** (re-architect) |  |  |

**Selected Strategy:** ___________
**Justification:**

**Migration Plan:**

| Phase | Activities | Responsible | Duration |
| --- | --- | --- | --- |
| **1. Assess** | (What inventory, dependencies, and readiness checks?) |  |  |
| **2. Plan** | (Architecture design from Ex 2, security requirements, rollback plan) |  |  |
| **3. Migrate** | (Environment setup, data migration method, application deployment) |  |  |
| **4. Validate** | (What testing before cutover?) |  |  |
| **5. Optimize** | (Post-migration tuning) |  |  |

**Validation Checklist:**

- [ ]  Application functional (users can log in, create/view records)
- [ ]  AD authentication working through VPN
- [ ]  Security groups enforced (test blocked traffic)
- [ ]  Encryption verified (at rest and in transit)
- [ ]  Logging confirmed (events appearing in SIEM)
- [ ]  Performance acceptable (page load times, database queries)
- [ ]  Backup and recovery tested

**Rollback Triggers** (conditions that cause reversion to on-premises):

1. 
2. 
3. 

### Knowledge Check: Cloud Incident Response

1. During an incident, the CDISS discovers that VPC Flow Logs were not enabled on the database subnet. The team needs network connection data to determine if data was exfiltrated. What are the options?
    1. Enable flow logs now — they will retroactively capture past traffic
    2. Image the physical hard drive to recover network artifacts
    3. **Flow logs cannot capture past traffic retroactively; request available logs from the CSP (API audit logs, database connection logs), check application-level logs for data access patterns, and enable flow logs immediately for ongoing monitoring — then document this logging gap as a finding for the after-action review**
    4. Terminate the database instance to stop any ongoing exfiltration
    
    💡
    This scenario illustrates why the IR preparation step is critical. Flow logs, once enabled, only capture traffic going forward. There is no retroactive capability, and there is no physical drive to image in a cloud environment. The available options are limited to whatever logging was already configured plus what the CSP can provide. The correct response uses every available data source, enables the missing capability immediately, and documents the gap so it is corrected for the future. This directly demonstrates the K6210 KSAT — understanding cloud service model limitations for incident response.
    

---

## Lab Completion Checklist

**Exercise 1 — Cloud Deployment Evaluation:**
- [ ] Requirements analysis completed with Impact Level justification
- [ ] All three service models evaluated with pros/cons
- [ ] Service model recommendation with justification
- [ ] All four deployment models evaluated
- [ ] Deployment model recommendation with justification
- [ ] Provider recommendation with rationale
- [ ] DEOS/knowledge management questions answered
- [ ] Knowledge check answered

**Exercise 2 — Security Architecture and Shared Responsibility:**
- [ ] VPC and subnet design completed
- [ ] Connectivity requirements documented (VPN, gateways)
- [ ] Security groups defined for all three tiers with least-privilege rules
- [ ] Logging and monitoring configuration documented
- [ ] SIEM integration described
- [ ] Shared responsibility matrix completed for all 14 security domains
- [ ] Encryption configuration documented for all data states
- [ ] Knowledge check answered

**Exercise 3 — Cloud IR and Migration:**
- [ ] IR preparation documented (logging, contacts, snapshots)
- [ ] Detection sources and alerting identified
- [ ] Containment steps sequenced correctly
- [ ] CSP coordination scenarios completed
- [ ] IR limitations analyzed with mitigations from Exercise 2
- [ ] Migration strategy selected with justification
- [ ] Five-phase migration plan completed
- [ ] Validation checklist reviewed
- [ ] Rollback triggers identified
- [ ] Knowledge check answered

---

## Summary

In this lab you applied cybersecurity strategy to a cloud computing scenario by:

1. **Evaluating cloud service and deployment models** against mission requirements including data classification, availability, integration, and compliance, selecting the appropriate Impact Level, service model, deployment model, and provider with documented justification
2. **Designing a secure cloud architecture** with VPC layout, tiered subnets, least-privilege security groups, encryption configuration, and comprehensive logging, and documenting the shared responsibility matrix between customer and CSP for the selected service model
3. **Developing cloud-specific incident response procedures** addressing evidence preservation, containment sequencing, CSP coordination, and IR limitations, and creating a structured migration plan with strategy selection, phased activities, validation testing, and rollback triggers

These activities address KSATs K6935 and K6938 (cloud service and deployment models) through the evaluation framework, A6918 and A6919 (applying cybersecurity strategy and determining best deployment model) through the recommendation and architecture design, S6942 (designing cloud deployments) through the architecture and security group design, K6210 (cloud IR limitations) through the incident response procedures and limitations analysis, S6945 (migrating workloads) through the migration plan, and K1125 (cloud-based knowledge management) through the DEOS analysis.

---

*Document Version: 1.0Classification: UNCLASSIFIED // FOR TRAINING USE ONLY*