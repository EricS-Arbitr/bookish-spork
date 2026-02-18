# LAB-XX2: Layer and Organizational Role Analysis

Owner: Eric Starace, Andy Kidd
Last edited by: Andy Kidd

# Lab: DoD Cyberspace Operations Framework

## Cyber Defense Infrastructure Support Specialist (CDISS) Course

---

| **Lab Information** |  |
| --- | --- |
| **Associated Lesson** | Lesson 2: DoD Cyberspace Operations Framework |
| **Estimated Duration** | 6-8 hours |
| **Lab Environment** | Virtual Machine Environment |
| **Prerequisites** | Completion of Lesson 2 content |

---

## Terminal Learning Objective (TLO)

Apply DoD cyberspace operations concepts through practical network analysis, mission dependency identification, and defensive infrastructure configuration.

## Enabling Learning Objectives (ELOs)

Upon completion of this lab, you will be able to:

1. Analyze realistic DoD cyberspace scenarios to identify organizational responsibilities and command relationships
2. Apply MRT-C identification processes to determine mission-critical cyberspace assets
3. Configure a multi-segment network environment representing DoD operational infrastructure
4. Document cyberspace terrain using the three-layer model (physical, logical, cyber-persona)
5. Classify cyberspace actions according to mission type (DODIN Operations, DCO-IDM, DCO-RA)
6. Implement baseline defensive measures on network infrastructure

## DCWF KSAT Alignment

| **KSAT ID** | **Description** | **Lab Coverage** |
| --- | --- | --- |
| K0001 | Knowledge of computer networking concepts and protocols | Tasks 1, 2, 5 |
| K0004 | Knowledge of cybersecurity and privacy principles | Tasks 4, 5 |
| K0179 | Knowledge of network security architecture concepts | Tasks 1, 2, 5 |
| K0332 | Knowledge of network protocols such as TCP/IP, DHCP, DNS | Tasks 1, 5 |
| K1069 | Knowledge of general kill chain (e.g., footprinting and scanning, enumeration, gaining access, escalation of privileges, maintaining access, network exploitation, covering tracks) | Exercise 2.2 |
| K1072 | Knowledge of network security architecture concepts including topology, protocols, components, and principles | Tasks 1, 2 |
| K1086 | Knowledge of DoD cyber defense policies, procedures, and regulations | All Exercises and Tasks |
| T0960 | Identify Task Critical Assets (TCA) and Mission Relevant Terrain in Cyberspace (MRT-C) | Exercise 2.4, Task 3 |

---

## Lab Environment Requirements

### Required Virtual Machines

| **VM** | **Operating System** | **Role** | **Minimum Resources** |
| --- | --- | --- | --- |
| VM1 | Ubuntu Server 22.04 LTS | Firewall/Router (using UFW/iptables) | 2 GB RAM, 20 GB disk |
| VM2 | Windows Server 2019/2022 | Domain Controller / File Server | 4 GB RAM, 40 GB disk |
| VM3 | Ubuntu Server 22.04 LTS | Application Server (Web App) | 2 GB RAM, 20 GB disk |
| VM4 | Windows 10/11 or Ubuntu Desktop | Workstation | 4 GB RAM, 40 GB disk |

### Network Configuration

Configure your virtualization platform with three virtual network segments:

| **Network Segment** | **Subnet** | **Purpose** |
| --- | --- | --- |
| WAN | 10.0.0.0/24 | Simulated external/higher HQ connection |
| UNCLASS LAN | 192.168.10.0/24 | Unclassified network segment |
| RESTRICTED LAN | 192.168.20.0/24 | Restricted/sensitive network segment |

### Software Requirements

- Virtualization platform: VirtualBox, VMware Workstation/Player, or Hyper-V
- SSH client for remote management
- Web browser for testing web application access
- Text editor for documentation

---

## Pre-Lab Preparation

Before beginning the hands-on tasks, complete the following exercises to reinforce your understanding of DoD cyberspace operations concepts.

---

## Exercise 2.2: Organizational Role Analysis

**Objective:** Apply understanding of DoD cyberspace organization to realistic scenarios.

**Estimated Time:** 45-60 minutes

### Scenario

A combatant command (CCMD) intelligence analyst discovers indicators that an advanced persistent threat (APT) actor may have compromised credentials for a critical mission system. The system supports time-sensitive targeting operations. Initial analysis suggests the compromise may extend beyond the CCMD’s network into enterprise services.

### Task 1: Organization Identification

For each action below, identify which organization would be primarily responsible. Record your answers in the table, then check your work against the solution guide.

| **Action** | **Your Answer** |
| --- | --- |
| 1. Coordinating the overall defensive response across DODIN |  |
| 2. Deploying a team to hunt for additional compromise indicators on CCMD networks |  |
| 3. Analyzing malware samples recovered from compromised systems |  |
| 4. Providing threat intelligence on the APT actor’s tactics, techniques, and procedures |  |
| 5. Implementing emergency patches on enterprise email servers |  |
| 6. Conducting counterattack operations against the APT’s infrastructure (if authorized) |  |
| 7. Notifying other CCMDs of the threat indicators |  |

### Task 2: Command Relationship Analysis

Draw or describe the command relationships that would be in effect during this incident. Address the following questions:

1. Who would JFHQ-DODIN coordinate with during this incident?
    
    ---
    
    ---
    
2. What authority would JFHQ-DODIN exercise?
    
    ---
    
    ---
    
3. How would a deployed CPT relate to the CCMD?
    
    ---
    
    ---
    

### Task 3: CPT Employment Decision

The CCMD requests CPT support. Identify which CPT type (DODIN, CCMD, Service, or National) would likely be employed for each scenario:

| **Scenario** | **CPT Type** | **Rationale** |
| --- | --- | --- |
| Hunting on CCMD J6 enterprise servers |  |  |
| Investigating compromise of Air Force-specific tactical system |  |  |
| Threat extends to national-level critical infrastructure |  |  |
| Clearing malware from SIPRNET backbone routers |  |  |
- 💡 Click to reveal Solution Guide 2.2
    
    ### Task 1: Organization Identification - Answers
    
    | **Action** | **Responsible Organization** |
    | --- | --- |
    | 1. Coordinating the overall defensive response across DODIN | **JFHQ-DODIN** (has DACO for global DODIN operations and DCO-IDM) |
    | 2. Deploying a team to hunt for additional compromise indicators on CCMD networks | **CCMD CPT** (aligned to specific CCMD, hunts on CCMD terrain) |
    | 3. Analyzing malware samples recovered from compromised systems | **DC3** (Department of Defense Cyber Crime Center - forensics/malware analysis) |
    | 4. Providing threat intelligence on the APT actor’s TTPs | **CNMF-HQ/National Mission Teams** or **Intelligence Community** (threat-focused intelligence on nation-state actors) |
    | 5. Implementing emergency patches on enterprise email servers | **DISA** (operates enterprise services) in coordination with **CSSPs** |
    | 6. Conducting counterattack operations against the APT’s infrastructure (if authorized) | **Combat Mission Teams (CMTs)** under **JFHQ-C** (OCO missions in support of CCDRs) |
    | 7. Notifying other CCMDs of the threat indicators | **JFHQ-DODIN** (coordinates threat information across the enterprise) and **USCYBERCOM** (notifies CCMDs of developing threats) |
    
    ### Task 2: Command Relationship Analysis - Answers
    
    **JFHQ-DODIN Coordination:**
    - Would coordinate with USCYBERCOM headquarters (reports to)
    - Would coordinate with the affected CCMD (supported/supporting relationship)
    - Would coordinate with all other CCMDs (to share threat indicators)
    - Would coordinate with Service Cyberspace Components (if Service-specific systems involved)
    - Would coordinate with DISA (for enterprise services)
    
    **Authority:**
    - JFHQ-DODIN exercises DACO (delegated from CDRUSCYBERCOM) over all DOD components for DODIN operations and DCO-IDM
    - This means JFHQ-DODIN can direct actions to protect the DODIN across organizational boundaries
    
    **CPT Relationship to CCMD:**
    - CCMD CPTs are under OPCON of the CCMD
    - The CCMD would task the CPT through normal command channels
    - For actions with broader DODIN impact, the CPT would coordinate through JFHQ-DODIN
    - If additional CPTs are needed, USCYBERCOM would coordinate their deployment (TACON to receiving commander)
    
    ### Task 3: CPT Employment Decision - Answers
    
    | **Scenario** | **CPT Type** | **Rationale** |
    | --- | --- | --- |
    | Hunting on CCMD J6 enterprise servers | **CCMD CPT** | Aligned to the specific CCMD; familiar with CCMD network architecture |
    | Investigating compromise of Air Force-specific tactical system | **Service CPT (Air Force)** | Service-specific system under Air Force/16th AF DODIN responsibility |
    | Threat extends to national-level critical infrastructure | **National CPT** | National CPTs under CNMF-HQ protect non-DODIN critical infrastructure when ordered |
    | Clearing malware from SIPRNET backbone routers | **DODIN CPT** | Enterprise-level DODIN infrastructure under JFHQ-DODIN |

---

## Exercise 2.4: MRT-C Analysis

**Objective:** Apply MRT-C concepts to identify and prioritize mission-critical cyberspace assets.

**Estimated Time:** 60-75 minutes

### Scenario

You are supporting a medical logistics unit responsible for managing pharmaceutical supplies for a regional military treatment facility (MTF). The unit’s Mission Essential Task is: **“Manage pharmaceutical inventory to ensure 95% availability of critical medications within 24 hours of demand.”**

The unit uses the following systems:

| **System** | **Description** |
| --- | --- |
| PharmTrack | Pharmaceutical inventory management application (commercial software on local server) |
| DMLSS | Defense Medical Logistics Standard Support system (enterprise system) |
| SIPRNET Email | For classified communications with theater medical command |
| NIPRNET Email | For unclassified communications with suppliers |
| Video Teleconference (VTC) | For coordination meetings |
| Local file server | For standard office documents |

### Task 1: Mission Decomposition

Identify at least three capabilities required to accomplish the MET, and for each capability, identify the supporting systems:

| **Capability** | **Supporting Systems** |
| --- | --- |
| 1. |  |
| 2. |  |
| 3. |  |

### Task 2: TCA Identification

Based on your decomposition, identify which system(s) would be Task Critical Assets and explain why:

| **System** | **TCA? (Y/N)** | **Tier (if Y)** | **Rationale** |
| --- | --- | --- | --- |
| PharmTrack |  |  |  |
| DMLSS |  |  |  |
| SIPRNET Email |  |  |  |
| NIPRNET Email |  |  |  |
| VTC |  |  |  |
| Local file server |  |  |  |

### Task 3: MRT-C Identification

For the highest-priority TCA identified, list the MRT-C components (be specific):

| **MRT-C Category** | **Specific Components** |
| --- | --- |
| Hardware |  |
| Network |  |
| Software/OS |  |
| Services |  |
| External Dependencies |  |

### Task 4: Impact Statement

Write a mission impact statement for your highest-priority TCA:

---

---

---

---

- 💡 Click to reveal Solution Guide 2.4
    
    ### Task 1: Mission Decomposition - Answers
    
    | **Capability** | **Supporting Systems** |
    | --- | --- |
    | 1. Track current inventory levels and expiration dates | PharmTrack, DMLSS |
    | 2. Order/request resupply from higher echelons | DMLSS, NIPRNET Email |
    | 3. Coordinate priority requirements with theater medical command | SIPRNET Email, VTC |
    | 4. Receive and process incoming shipments | PharmTrack, DMLSS |
    | 5. Generate reports for leadership | PharmTrack, DMLSS, Local file server |
    
    ### Task 2: TCA Identification - Answers
    
    | **System** | **TCA?** | **Tier** | **Rationale** |
    | --- | --- | --- | --- |
    | PharmTrack | **Yes** | **Tier 1** | Primary system for real-time inventory tracking; loss prevents knowing current stock levels and would directly cause inability to ensure 95% availability |
    | DMLSS | **Yes** | **Tier 1** | Enterprise logistics system for ordering and tracking resupply; loss prevents ordering replacements and tracking shipments |
    | SIPRNET Email | Yes | Tier 2 | Important for classified coordination but alternate methods exist (phone, in-person); not immediately mission-failing |
    | NIPRNET Email | Yes | Tier 2 | Important for supplier communication but alternate methods available; supports but doesn’t directly execute MET |
    | VTC | No | N/A | Useful coordination tool but loss doesn’t directly impact pharmaceutical management |
    | Local file server | No | N/A | Administrative convenience; data can be recreated or accessed elsewhere |
    
    ### Task 3: MRT-C Identification (for PharmTrack) - Answers
    
    | **MRT-C Category** | **Specific Components** |
    | --- | --- |
    | Hardware | Dell PowerEdge server (model/serial); UPS battery backup; network switch in server room; workstations (3) in pharmacy |
    | Network | NIPRNET connection to installation backbone; Cat6 cabling to server; VLAN 42 configuration; firewall rules allowing port 443 and 8443 |
    | Software/OS | Windows Server 2019; SQL Server 2019 database; PharmTrack v4.2 application; .NET Framework 4.8 |
    | Services | SQL Server service; IIS web service; Windows Active Directory authentication; DNS for name resolution |
    | External Dependencies | Active Directory domain controllers; DHCP server; DNS server; network time protocol (NTP) for timestamp accuracy; backup system for database |
    
    ### Task 4: Impact Statement - Answer
    
    “Loss or compromise of the PharmTrack inventory management system would immediately eliminate the unit’s ability to track current pharmaceutical stock levels, monitor medication expiration dates, and identify critical shortages. Without real-time inventory visibility, the unit cannot ensure 95% medication availability within 24 hours of demand, directly failing the Mission Essential Task. During high-demand operations such as mass casualty events, this could result in medication stockouts, delayed patient treatment, and potentially increased mortality. Recovery time is estimated at 24-48 hours minimum if backups are current, during which manual tracking would provide significantly degraded capability.”
    

---

## Hands-On Lab Tasks

Complete the following tasks to build and analyze a network environment from a DoD cyberspace operations perspective.

---

## Task 1: Build the Lab Network

**Estimated Time:** 90 minutes

### Objective

Configure a multi-segment network representing a deployed operations center environment.

### Network Architecture

```
[SIMULATED HIGHER HQ / INTERNET]
              |
        [Ubuntu Router]
          (VM1 - UFW/iptables)
              |
    ----------------------
    |                    |
[UNCLASS VLAN]     [RESTRICTED VLAN]
192.168.10.0/24    192.168.20.0/24
    |                    |
[Workstation]      [Windows DC]
  (VM4)               (VM2)
                         |
                  [Linux App Server]
                      (VM3)
```

### Step 1.1: Configure the Ubuntu Router/Firewall (VM1)

1. Install Ubuntu Server 22.04 LTS with the following network interfaces:
    - **eth0**: WAN interface (DHCP or static 10.0.0.1/24)
    - **eth1**: UNCLASS LAN (192.168.10.1/24)
    - **eth2**: RESTRICTED LAN (192.168.20.1/24)
2. Enable IP forwarding: (done with linuxRouter role on ubuntu box)
    
    ```bash
    sudo nano /etc/sysctl.conf
    # Uncomment or add:
    net.ipv4.ip_forward=1
    
    # Apply changes:
    sudo sysctl -p
    ```
    
3. Configure netplan for network interfaces:
    
    ```bash
    sudo nano /etc/netplan/00-installer-config.yaml
    ```
    
    Example configuration: (this should be completed by setting up interfaces in lab.json - need to confirm eth0..1 etc stuff)
    
    ```yaml
    network:
    version:2
    ethernets:
    eth0:
    dhcp4:true
    eth1:
    addresses:
    - 192.168.10.1/24
    eth2:
    addresses:
    - 192.168.20.1/24
    ```
    
    Apply configuration:
    
    ```bash
    sudo netplan apply
    ```
    
4. Configure iptables rules for routing and filtering (TODO accomplish with firewall role variable linux_firewall_rules :
    
    ```bash
    # Enable NAT for outbound traffic
    sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    
    # Allow established connections
    sudo iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow UNCLASS to access WAN
    sudo iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
    
    # Allow specific traffic from RESTRICTED to UNCLASS
    sudo iptables -A FORWARD -i eth2 -o eth1 -p tcp --dport 53 -j ACCEPT
    sudo iptables -A FORWARD -i eth2 -o eth1 -p udp --dport 53 -j ACCEPT
    sudo iptables -A FORWARD -i eth2 -o eth1 -p tcp --dport 80 -j ACCEPT
    sudo iptables -A FORWARD -i eth2 -o eth1 -p tcp --dport 443 -j ACCEPT
    
    # Block RESTRICTED direct to WAN
    sudo iptables -A FORWARD -i eth2 -o eth0 -j DROP
    
    # Enable logging for dropped packets
    sudo iptables -A FORWARD -j LOG --log-prefix "IPTables-Dropped: "
    
    # Save rules
    sudo apt install iptables-persistent -y
    sudo netfilter-persistent save
    ```
    

### Step 1.2: Configure the Windows Domain Controller (VM2) TODO

1. Install Windows Server 2019/2022 with the following configuration:
    - IP Address: 192.168.20.10/24
    - Default Gateway: 192.168.20.1
    - DNS: 127.0.0.1 (self, after AD DS installation)
2. Install Active Directory Domain Services:
    - Open Server Manager → Add Roles and Features
    - Select “Active Directory Domain Services”
    - Complete installation and promote to Domain Controller
    - Create new forest: **YOURLAB.MIL**
3. Configure DNS services:
    - DNS will be installed automatically with AD DS
    - Verify forward lookup zone for YOURLAB.MIL exists
4. Create a file share:
    - Create folder: `C:\Shares\OPORDERS`
    - Right-click → Properties → Sharing → Advanced Sharing
    - Share name: **OPORDERS**
    - Configure permissions as appropriate
5. Create test user accounts:
    - Open Active Directory Users and Computers
    - Create Organizational Unit: **LabUsers**
    - Create test users: `labuser1`, `labuser2`, `admin.ops`

### Step 1.3: Configure the Linux Application Server (VM3)

1. Install Ubuntu Server 22.04 LTS with the following configuration:
    - IP Address: 192.168.20.20/24
    - Default Gateway: 192.168.20.1
    - DNS: 192.168.20.10 (Windows DC)
2. Install Apache and PHP:
    
    ```bash
    sudo apt update
    sudo apt install apache2 php libapache2-mod-php -y
    ```
    
3. Create the Operations Tracking System application:
    
    ```bash
    sudo nano /var/www/html/index.php
    ```
    
    Add the following content:
    
    ```php
    <?php
    session_start();
    
    // Simple authentication
    $valid_users = array(
        'operator' => 'SecurePass123!',
        'admin' => 'AdminPass456!'
    );
    
    if (isset($_POST['logout'])) {
        session_destroy();
        header('Location: index.php');
        exit;
    }
    
    if (isset($_POST['username']) && isset($_POST['password'])) {
        $username = $_POST['username'];
        $password = $_POST['password'];
    
        if (isset($valid_users[$username]) && $valid_users[$username] === $password) {
            $_SESSION['authenticated'] = true;
            $_SESSION['username'] = $username;
        } else {
            $error = "Invalid credentials";
        }
    }
    
    if (!isset($_SESSION['authenticated'])) {
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>Operations Tracking System - Login</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 50px; background: #1a1a2e; color: #eee; }
            .login-box { max-width: 400px; margin: auto; padding: 30px; background: #16213e; border-radius: 10px; }
            input { width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }
            button { width: 100%; padding: 10px; background: #0f3460; color: white; border: none; cursor: pointer; }
            .error { color: #e94560; }
            h2 { color: #e94560; }
        </style>
    </head>
    <body>
        <div class="login-box">
            <h2>Operations Tracking System</h2>
            <p>UNCLASSIFIED // FOR TRAINING USE ONLY</p>
            <?php if (isset($error)) echo "<p class='error'>$error</p>"; ?>
            <form method="POST">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
        </div>
    </body>
    </html>
    <?php
    } else {
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>Operations Tracking System</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }
            .header { background: #16213e; padding: 20px; margin-bottom: 20px; }
            .content { background: #16213e; padding: 20px; }
            table { width: 100%; border-collapse: collapse; }
            th, td { border: 1px solid #0f3460; padding: 10px; text-align: left; }
            th { background: #0f3460; }
            button { padding: 10px 20px; background: #e94560; color: white; border: none; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Operations Tracking System</h1>
            <p>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?> |
            <form method="POST" style="display:inline;">
                <button type="submit" name="logout">Logout</button>
            </form>
            </p>
            <p>UNCLASSIFIED // FOR TRAINING USE ONLY</p>
        </div>
        <div class="content">
            <h2>Current Operations Status</h2>
            <table>
                <tr>
                    <th>Operation ID</th>
                    <th>Status</th>
                    <th>Last Updated</th>
                    <th>Priority</th>
                </tr>
                <tr>
                    <td>OP-2024-001</td>
                    <td>Active</td>
                    <td><?php echo date('Y-m-d H:i:s'); ?></td>
                    <td>HIGH</td>
                </tr>
                <tr>
                    <td>OP-2024-002</td>
                    <td>Planning</td>
                    <td><?php echo date('Y-m-d H:i:s', strtotime('-2 hours')); ?></td>
                    <td>MEDIUM</td>
                </tr>
                <tr>
                    <td>OP-2024-003</td>
                    <td>Complete</td>
                    <td><?php echo date('Y-m-d H:i:s', strtotime('-1 day')); ?></td>
                    <td>LOW</td>
                </tr>
            </table>
            <p><em>Server Time: <?php echo date('Y-m-d H:i:s T'); ?></em></p>
            <p><em>Server IP: <?php echo $_SERVER['SERVER_ADDR']; ?></em></p>
        </div>
    </body>
    </html>
    <?php
    }
    ?>
    ```
    
4. Set proper permissions:
    
    ```bash
    sudo chown -R www-data:www-data /var/www/html/
    sudo chmod 644 /var/www/html/index.php
    ```
    
5. Restart Apache:
    
    ```bash
    sudo systemctl restart apache2
    sudo systemctl enable apache2
    ```
    

### Step 1.4: Configure the Workstation (VM4)

**Option A: Windows Workstation**

1. Install Windows 10/11 with the following configuration:
    - IP Address: 192.168.10.50/24
    - Default Gateway: 192.168.10.1
    - DNS: 192.168.20.10
2. Join to the YOURLAB.MIL domain:
    - System Properties → Computer Name → Change
    - Select “Domain” and enter: YOURLAB.MIL
    - Authenticate with domain admin credentials
    - Restart

**Option B: Ubuntu Desktop Workstation**

1. Install Ubuntu Desktop 22.04 LTS with the following configuration:
    - IP Address: 192.168.10.50/24
    - Default Gateway: 192.168.10.1
    - DNS: 192.168.20.10
2. Install required packages:
    
    ```bash
    sudo apt update
    sudo apt install firefox cifs-utils smbclient -y
    ```
    

### Step 1.5: Validate Network Connectivity

From each system, verify connectivity to other systems:

| **From** | **To** | **Test Command** | **Expected Result** |
| --- | --- | --- | --- |
| Workstation | Router | `ping 192.168.10.1` | Success |
| Workstation | Windows DC | `ping 192.168.20.10` | Success |
| Workstation | Linux App Server | `ping 192.168.20.20` | Success |
| Windows DC | Router | `ping 192.168.20.1` | Success |
| Linux App Server | Windows DC | `ping 192.168.20.10` | Success |

Test application access:
- From Workstation, open browser to: `http://192.168.20.20`
- Verify login page appears
- Test login with credentials: `operator` / `SecurePass123!`

### Deliverable 1: Network Configuration Documentation

Complete the following table with your actual configuration:

| **Component** | **IP Address** | **Hostname** | **Services Running** |
| --- | --- | --- | --- |
| Ubuntu Router |  |  |  |
| Windows DC |  |  |  |
| Linux App Server |  |  |  |
| Workstation |  |  |  |

Document your firewall rules:

```
Rule 1: _______________________________________________
Rule 2: _______________________________________________
Rule 3: _______________________________________________
Rule 4: _______________________________________________
Rule 5: _______________________________________________
```

---

## Task 2: Cyberspace Layer Analysis

**Estimated Time:** 45 minutes

### Objective

Document your lab network using the three-layer cyberspace model from JP 3-12.

### Step 2.1: Document the Physical Network Layer

List all hardware components (VMs representing physical systems):

| **Component** | **Physical Description** | **Geographic Location (Simulated)** |
| --- | --- | --- |
|  |  |  |
|  |  |  |
|  |  |  |
|  |  |  |

Identify physical interconnections:

| **Connection** | **Media Type** | **Speed** |
| --- | --- | --- |
|  |  |  |
|  |  |  |
|  |  |  |

### Step 2.2: Document the Logical Network Layer

List all IP addresses and their assignments:

| **IP Address** | **Hostname** | **Network Segment** | **Purpose** |
| --- | --- | --- | --- |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |

Document running services and ports:

| **System** | **Service** | **Port** | **Protocol** |
| --- | --- | --- | --- |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |

Map application dependencies:

```
Operations Tracking System depends on:
→ _______________________________________________
→ _______________________________________________
→ _______________________________________________

File Share access depends on:
→ _______________________________________________
→ _______________________________________________
```

### Step 2.3: Document the Cyber-Persona Layer

List all user accounts created:

| **Account Name** | **System** | **Account Type** | **Permissions** |
| --- | --- | --- | --- |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |

Identify service accounts:

| **Service Account** | **System** | **Purpose** |
| --- | --- | --- |
|  |  |  |
|  |  |  |

Document authentication mechanisms:

```
Domain authentication: _______________________________________________
Web application authentication: _______________________________________________
Local system authentication: _______________________________________________
```

### Deliverable 2: Three-Layer Analysis Table

Complete the comprehensive three-layer analysis:

| **Component** | **Physical Layer** | **Logical Layer** | **Cyber-Persona Layer** |
| --- | --- | --- | --- |
| Web Application |  |  |  |
| Domain Controller |  |  |  |
| File Share |  |  |  |
| Firewall/Router |  |  |  |
- 💡 Click to reveal Example Analysis
    
    
    | **Component** | **Physical Layer** | **Logical Layer** | **Cyber-Persona Layer** |
    | --- | --- | --- | --- |
    | Web Application | Ubuntu Server VM; 2GB RAM; virtual NIC on RESTRICTED VLAN; virtual disk storage | IP: 192.168.20.20; Apache on port 80; PHP application; depends on DNS for name resolution | operator account; admin account; session-based authentication; no domain integration |
    | Domain Controller | Windows Server VM; 4GB RAM; virtual NIC on RESTRICTED VLAN; virtual disk storage | IP: 192.168.20.10; AD DS on 389/636; DNS on 53; Kerberos on 88; LDAP authentication | Domain Admin; labuser1; labuser2; admin.ops; service accounts for AD services |
    | File Share | Hosted on DC (same physical); shared folder storage | SMB/CIFS on ports 445/139; UNC path \DC; NTFS permissions | Access controlled by AD groups; authenticated via Kerberos |
    | Firewall/Router | Ubuntu Server VM; 2GB RAM; 3 virtual NICs; iptables rules | IPs: 10.0.0.x, 192.168.10.1, 192.168.20.1; NAT; packet filtering; routing between segments | Local admin account; no external authentication |

---

## Task 3: MRT-C Identification

**Estimated Time:** 60 minutes

### Objective

Apply MRT-C identification methodology to your lab environment.

### Mission Scenario

Your network supports a deployed operations center with the following Mission Essential Task:

**“Coordinate daily operations through secure information sharing and tracking.”**

### Step 3.1: Conduct Mission Decomposition

Identify 3-4 capabilities required for this MET:

| **#** | **Required Capability** | **Supporting Systems in Lab** |
| --- | --- | --- |
| 1 |  |  |
| 2 |  |  |
| 3 |  |  |
| 4 |  |  |

### Step 3.2: Identify Task Critical Assets

Determine which systems are TCAs:

| **System** | **TCA? (Y/N)** | **Tier** | **Rationale** |
| --- | --- | --- | --- |
| Ubuntu Router |  |  |  |
| Windows DC |  |  |  |
| Linux App Server |  |  |  |
| Workstation |  |  |  |

### Step 3.3: Document MRT-C

For your highest-priority TCA, document all MRT-C components:

**Selected TCA:** _______________________________

| **MRT-C Category** | **Specific Components** |
| --- | --- |
| Hardware |  |
| Network Infrastructure |  |
| Operating System |  |
| Applications/Services |  |
| External Dependencies |  |

### Step 3.4: Write Impact Statements

Write a mission impact statement for each TCA identified:

**TCA 1:** _______________________________

Impact Statement:
_____________________________________________________________________________
_____________________________________________________________________________
_____________________________________________________________________________

**TCA 2:** _______________________________

Impact Statement:
_____________________________________________________________________________
_____________________________________________________________________________
_____________________________________________________________________________

### Deliverable 3: MRT-C Documentation Package

Compile your complete MRT-C package including:
- [ ] Mission decomposition table
- [ ] TCA identification with rationale
- [ ] Detailed MRT-C documentation for highest-priority TCA
- [ ] Impact statements for all TCAs

---

## Task 4: Mission Classification Scenarios

**Estimated Time:** 45 minutes

### Objective

Classify cyberspace actions according to mission type based on your lab environment.

### Instructions

For each scenario below, identify:
1. **Mission Type**: DODIN Operations, DCO-IDM, DCO-RA, or OCO
2. **Cyberspace Action**: Security, Defense, Exploitation, or Attack
3. **Rationale**: Explain your classification

### Scenario A

You notice the firewall logs show a high volume of failed login attempts from an unknown IP address. You add a rule to block that IP address.

| **Classification Element** | **Your Answer** |
| --- | --- |
| Mission Type |  |
| Cyberspace Action |  |
| Rationale |  |

### Scenario B

Your security tools detect suspicious files on the Linux application server. You begin investigating, identify malware, and work to remove it.

| **Classification Element** | **Your Answer** |
| --- | --- |
| Mission Type |  |
| Cyberspace Action |  |
| Rationale |  |

### Scenario C

Intelligence indicates an adversary group is targeting operations centers like yours. You implement additional monitoring and tighten firewall rules based on known adversary TTPs.

| **Classification Element** | **Your Answer** |
| --- | --- |
| Mission Type |  |
| Cyberspace Action |  |
| Rationale |  |

### Scenario D

The web application starts behaving erratically. You apply a vendor-released security patch and restart services.

| **Classification Element** | **Your Answer** |
| --- | --- |
| Mission Type |  |
| Cyberspace Action |  |
| Rationale |  |
- 💡 Click to reveal Mission Classification Answers
    
    ### Scenario A - Blocking Malicious IP
    
    | **Classification Element** | **Answer** |
    | --- | --- |
    | Mission Type | **DCO-IDM** (Defensive Cyberspace Operations - Internal Defensive Measures) |
    | Cyberspace Action | **Defense** |
    | Rationale | This is a defensive response to detected malicious activity within blue cyberspace. The action blocks a threat actor from continuing attempts against DODIN resources. It occurs within owned network space and is a protective measure. |
    
    ### Scenario B - Malware Investigation and Removal
    
    | **Classification Element** | **Answer** |
    | --- | --- |
    | Mission Type | **DCO-IDM** |
    | Cyberspace Action | **Defense** |
    | Rationale | This is an active defensive measure to defeat a specific threat (malware) that has penetrated blue cyberspace. The investigation and removal are internal defensive measures occurring within owned network space. |
    
    ### Scenario C - Proactive Hardening Based on Intelligence
    
    | **Classification Element** | **Answer** |
    | --- | --- |
    | Mission Type | **DODIN Operations** with **DCO-IDM** elements |
    | Cyberspace Action | **Security** |
    | Rationale | Implementing additional monitoring and hardening based on threat intelligence is primarily a security action (preventing unauthorized access). It falls under DODIN Operations (secure, configure) with DCO-IDM elements because it’s threat-informed defensive posturing. |
    
    ### Scenario D - Routine Patching
    
    | **Classification Element** | **Answer** |
    | --- | --- |
    | Mission Type | **DODIN Operations** |
    | Cyberspace Action | **Security** |
    | Rationale | Applying vendor patches and restarting services is routine maintenance that falls under DODIN Operations (maintain, sustain). This is a security action focused on reducing vulnerabilities rather than responding to an active threat. |

### Deliverable 4: Mission Classification Analysis

Submit your completed classification table with rationale for each scenario.

---

## Task 5: Practical Defense Implementation

**Estimated Time:** 60 minutes

### Objective

Implement baseline defensive measures on your lab infrastructure.

### Step 5.1: Configure Logging

**On Windows Domain Controller:**

1. Open Group Policy Management
2. Edit the Default Domain Controllers Policy
3. Navigate to: Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration
4. Enable the following audit policies:
    - Account Logon: Audit Credential Validation (Success, Failure)
    - Account Management: Audit User Account Management (Success, Failure)
    - Logon/Logoff: Audit Logon (Success, Failure)
    - Object Access: Audit File Share (Success, Failure)
    - System: Audit Security State Change (Success)
5. Apply the policy:
    
    ```bash
    gpupdate /force
    ```
    

**On Linux Application Server:**

1. Configure Apache logging:
    
    ```bash
    sudo nano /etc/apache2/apache2.conf
    ```
    
    Verify these logging settings exist:
    
    ```
    ErrorLog ${APACHE_LOG_DIR}/error.log
    LogLevelwarn
    LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
    CustomLog ${APACHE_LOG_DIR}/access.log combined
    ```
    
2. Install and configure auditd:
    
    ```bash
    sudo apt install auditd -y
    sudo systemctl enable auditd
    sudo systemctl start auditd
    
    # Add audit rules for web directory
    sudo auditctl -w /var/www/html -p wa -k webfiles
    
    # Make rules persistent
    sudo nano /etc/audit/rules.d/audit.rules
    # Add: -w /var/www/html -p wa -k webfiles
    ```
    

**On Ubuntu Router:**

1. Configure iptables logging (already done in Task 1):
    
    ```bash
    # Verify logging rule exists
    sudo iptables -L -v | grep LOG
    ```
    
2. Configure rsyslog to separate firewall logs:
    
    ```bash
    sudo nano /etc/rsyslog.d/iptables.conf
    ```
    
    Add:
    
    ```
    :msg, contains, "IPTables-Dropped:" /var/log/iptables.log
    & stop
    ```
    
    Restart rsyslog:
    
    ```bash
    sudo systemctl restart rsyslog
    ```
    

### Step 5.2: Implement Security Hardening

**On Windows Domain Controller:**

1. Configure password policy:
    - Open Group Policy Management
    - Edit Default Domain Policy
    - Navigate to: Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Password Policy
    - Configure:
        - Minimum password length: 14 characters
        - Password must meet complexity requirements: Enabled
        - Maximum password age: 60 days
2. Configure account lockout policy:
    - Navigate to: Account Policies → Account Lockout Policy
    - Configure:
        - Account lockout threshold: 5 invalid logon attempts
        - Account lockout duration: 30 minutes
        - Reset account lockout counter after: 30 minutes
3. Apply the policy:
    
    ```bash
    gpupdate /force
    ```
    

**On Linux Application Server:**

1. Configure SSH hardening:
    
    ```bash
    sudo nano /etc/ssh/sshd_config
    ```
    
    Ensure these settings:
    
    ```
    PermitRootLogin no
    PasswordAuthentication yes
    MaxAuthTries 3
    LoginGraceTime 60
    ```
    
    Restart SSH:
    
    ```bash
    sudo systemctl restart sshd
    ```
    
2. Configure UFW firewall:
    
    ```bash
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow from 192.168.20.0/24 to any port 22
    sudo ufw allow from 192.168.10.0/24 to any port 80
    sudo ufw allow from 192.168.20.0/24 to any port 80
    sudo ufw enable
    ```
    
3. Disable unnecessary services:
    
    ```bash
    # List enabled services
    sudo systemctl list-unit-files --state=enabled
    
    # Disable any unnecessary services (example)
    # sudo systemctl disable cups
    ```
    

**On Ubuntu Router:**

1. Secure SSH access:
    
    ```bash
    sudo nano /etc/ssh/sshd_config
    ```
    
    Add/modify:
    
    ```
    PermitRootLogin no
    MaxAuthTries 3
    AllowUsers youradminuser
    ```
    
    Restart SSH:
    
    ```bash
    sudo systemctl restart sshd
    ```
    

### Step 5.3: Document Security Configuration

Create a security baseline document by completing the following:

**Password Policy:**
| **Setting** | **Configured Value** |
|————-|———————|
| Minimum length | |
| Complexity required | |
| Maximum age | |
| Lockout threshold | |
| Lockout duration | |

**Firewall Configuration:**
| **System** | **Firewall Enabled** | **Key Rules** |
|————|———————|—————|
| Ubuntu Router | | |
| Windows DC | | |
| Linux App Server | | |

**Logging Configuration:**
| **System** | **Logs Enabled** | **Log Location** |
|————|—————–|——————|
| Ubuntu Router | | |
| Windows DC | | |
| Linux App Server | | |

### Step 5.4: Test and Validate

Perform the following validation tests:

| **Test** | **Procedure** | **Expected Result** | **Actual Result** | **Pass/Fail** |
| --- | --- | --- | --- | --- |
| Service access | Access web app from workstation | Login page displays |  |  |
| File share access | Map network drive to OPORDERS | Drive maps successfully |  |  |
| Failed login logging | Attempt 3 bad passwords on DC | Events in Security log |  |  |
| Firewall logging | Attempt blocked connection | Entry in iptables.log |  |  |
| Account lockout | Attempt 6 bad passwords | Account locks out |  |  |

### Deliverable 5: Security Configuration Document

Submit your completed security baseline documentation including:
- [ ] Password policy settings
- [ ] Firewall configurations
- [ ] Logging configurations
- [ ] Validation test results

---

## Lab Deliverables Summary

Submit the following for lab completion:

| **#** | **Deliverable** | **Completed** |
| --- | --- | --- |
| 1 | Network Configuration Documentation | ☐ |
| 2 | Three-Layer Analysis Table | ☐ |
| 3 | MRT-C Documentation Package | ☐ |
| 4 | Mission Classification Analysis | ☐ |
| 5 | Security Configuration Document | ☐ |

---

## Lab Completion Checklist

### Exercise Completion

- [ ]  Exercise 2.2: Organizational Role Analysis completed
- [ ]  Exercise 2.4: MRT-C Analysis completed

### Technical Tasks

- [ ]  Task 1: Lab network built and functional
- [ ]  Task 2: Three-layer cyberspace analysis documented
- [ ]  Task 3: MRT-C identification completed
- [ ]  Task 4: Mission classification scenarios analyzed
- [ ]  Task 5: Security baseline implemented and validated

### Functionality Verification

- [ ]  All VMs can communicate as designed
- [ ]  Web application accessible and functional
- [ ]  File share accessible from workstation
- [ ]  Domain authentication working
- [ ]  Firewall rules properly filtering traffic
- [ ]  Logging capturing expected events

### Documentation

- [ ]  Network diagrams completed
- [ ]  IP addressing documented
- [ ]  Firewall rules documented
- [ ]  Three-layer analysis table completed
- [ ]  MRT-C package completed
- [ ]  Impact statements written
- [ ]  Security baseline documented
- [ ]  Validation tests documented

---

## Self-Assessment Rubric

Rate your performance on each objective:

| **Objective** | **Exceeds (4)** | **Meets (3)** | **Approaching (2)** | **Beginning (1)** | **Score** |
| --- | --- | --- | --- | --- | --- |
| Organizational Role Analysis | Correctly identified all organizations with detailed rationale | Correctly identified most organizations | Identified some organizations correctly | Struggled to identify organizations |  |
| MRT-C Identification | Comprehensive MRT-C with all dependencies identified | Complete MRT-C for primary TCA | Partial MRT-C identification | Incomplete MRT-C understanding |  |
| Network Configuration | All systems configured correctly with documentation | Most systems configured correctly | Some configuration issues | Significant configuration problems |  |
| Three-Layer Analysis | Thorough analysis of all layers with dependencies | Complete analysis of all components | Partial analysis completed | Incomplete understanding of layers |  |
| Mission Classification | All scenarios correctly classified with doctrine references | Most scenarios correctly classified | Some classification errors | Significant classification confusion |  |
| Security Implementation | All security measures implemented and validated | Most security measures implemented | Some security measures implemented | Minimal security implementation |  |

**Total Score: _____ / 24**

**Performance Level:**
- 21-24: Exceeds Standards
- 16-20: Meets Standards

- 11-15: Approaching Standards
- 0-10: Needs Additional Practice

---

## Bridge to Next Lesson

This lab established foundational skills for understanding DoD cyberspace operations. The network environment you built will be used in future labs to:

- **Lesson 3 (Network Infrastructure):** Expand network analysis capabilities with traffic capture and protocol analysis
- **Lesson 4 (Network Security Architecture):** Implement additional security zones and defense-in-depth controls
- **Lesson 5 (MRT-C Deep Dive):** Conduct more detailed mission decomposition and asset prioritization
- **Lesson 7 (Sensing Capabilities):** Deploy IDS/IPS and logging solutions for threat detection

**Recommended:** Keep your lab environment running or document your configuration thoroughly for quick rebuild. Future labs will build upon this foundation.

---

## Appendix A: Troubleshooting Guide

### Common Issues and Solutions

| **Issue** | **Possible Cause** | **Solution** |
| --- | --- | --- |
| VMs cannot communicate | Virtual network misconfiguration | Verify all VMs on correct virtual switches/networks |
| No internet from UNCLASS | NAT not configured | Verify `iptables -t nat -L` shows MASQUERADE rule |
| Cannot join domain | DNS not resolving | Verify workstation DNS points to DC IP |
| Web app not accessible | Apache not running | Run `sudo systemctl status apache2` |
| File share access denied | Permissions issue | Verify NTFS and share permissions on DC |

### Useful Commands

**Ubuntu/Linux:**

```bash
# Check IP configuration
ip addr show

# Check routing table
ip route show

# Test DNS resolution
nslookup dc.yourlab.mil

# Check service status
sudo systemctl status apache2

# View firewall rules
sudo iptables -L -v -n

# View logs
sudo tail -f /var/log/apache2/access.log
```

**Windows:**

```bash
# Check IP configuration
ipconfig /all

# Test DNS resolution
nslookup dc.yourlab.mil

# Check domain membership
systeminfo | findstr Domain

# View security events
eventvwr.msc
```

---

## Appendix B: Glossary

| **Term** | **Definition** |
| --- | --- |
| CCMD | Combatant Command |
| CMT | Combat Mission Team |
| CPT | Cyber Protection Team |
| CSSP | Cybersecurity Service Provider |
| DACO | Directive Authority for Cyberspace Operations |
| DCA | Defense Critical Asset |
| DCO | Defensive Cyberspace Operations |
| DCO-IDM | DCO - Internal Defensive Measures |
| DCO-RA | DCO - Response Actions |
| DISA | Defense Information Systems Agency |
| DODIN | Department of Defense Information Network |
| JFHQ-DODIN | Joint Force Headquarters - DODIN |
| KT-C | Key Terrain in Cyberspace |
| MET | Mission Essential Task |
| MRT-C | Mission Relevant Terrain in Cyberspace |
| OCO | Offensive Cyberspace Operations |
| OPCON | Operational Control |
| TACON | Tactical Control |
| TCA | Task Critical Asset |
| TTP | Tactics, Techniques, and Procedures |

---

**End of Lab Document**

*UNCLASSIFIED // FOR TRAINING USE ONLY*