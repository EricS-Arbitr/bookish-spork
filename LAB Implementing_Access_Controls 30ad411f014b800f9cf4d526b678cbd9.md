# LAB: Implementing_Access_Controls

Owner: Eric Starace
Last edited by: Eric Starace

# Lab 5: Implementing Access Controls

## Cyber Defense Infrastructure Support Specialist Course

| **Estimated Completion Time** | 4–5 hours |
| --- | --- |
| **Prerequisites** | Lesson 6 Sections 6.1–6.3; Lesson 3 (Network Infrastructure and Protocols); Lesson 4 (Network Security Architecture); Basic familiarity with PowerShell |
| **Lab Type** | Hands-on technical implementation and configuration |
| **Classification** | UNCLASSIFIED // FOR TRAINING USE ONLY |

---

## Terminal Learning Objective

Implement and validate host-based and network-based access controls across a multi-zone network environment using firewall rules, NTFS permissions, and Group Policy to enforce least privilege and defense-in-depth principles.

## Enabling Learning Objectives

| ELO | Objective |
| --- | --- |
| 6A.1 | Document and implement network access control lists on a firewall to enforce traffic policies for a DMZ web server environment |
| 6A.2 | Configure Windows Firewall inbound rules using PowerShell to provide host-level defense-in-depth |
| 6A.3 | Create a secure folder structure with NTFS permissions using PowerShell, including inheritance management and security group assignments |
| 6A.4 | Configure Group Policy Objects to enforce user rights assignments, security options, and restricted group membership across domain workstations |
| 6A.5 | Verify and document all access control configurations and test results to ensure compliance with organizational security requirements |

## Tools Implemented / Required

| Tool | Purpose | Type |
| --- | --- | --- |
| Windows Firewall with Advanced Security | Host-based network access control | Host Firewall |
| PowerShell | Access control configuration and verification | Administration Tool |
| Active Directory Users and Computers | Security group and user management | Directory Service |
| Group Policy Management Console (GPMC) | Centralized policy enforcement | Policy Management |
| Windows Server 2019/2022 | Domain Controller and file server | Server OS |
| Windows 10/11 | Domain-joined workstation for testing | Client OS |

## KSAT Alignment

| KSAT ID | Type | Description |
| --- | --- | --- |
| K0049 | Knowledge (Core) | Knowledge of host/network access control mechanisms (e.g., access control list) |
| S0157 | Skill (Additional) | Skill in applying host/network access controls (e.g., access control list) |
| T0481A | Task (Additional) | Create, edit, and manage network access control lists on specialized cyber defense systems (e.g., firewalls and intrusion prevention systems) |
| K0063 | Knowledge (Core) | Knowledge of cybersecurity principles and organizational requirements (confidentiality, integrity, availability, authentication, non-repudiation) |
| T0393B | Task (Core) | Coordinate with system administrators to create cyber defense tools, test bed(s), and test and evaluate applications, hardware infrastructure, rules/signatures, access controls, and configurations |

---

## Lab Environment

### Required Systems

| System | Role | IP Address |
| --- | --- | --- |
| Windows Server 2019/2022 | Domain Controller (DC01) | 192.168.10.5 |
| Windows Server 2019/2022 | File/Web Server (SVR01) | 192.168.10.10 |
| Windows 10/11 Workstation | Domain-joined client (WS01) | 192.168.10.50 |
| Ubuntu Linux (optional) | Additional testing endpoint | 192.168.10.60 |

### Network Configuration

| Network | Subnet | Purpose |
| --- | --- | --- |
| LAN | 192.168.10.0/24 | Internal production network |
| DMZ | 192.168.100.0/24 | Demilitarized zone for externally-accessible services |
| Admin Network | 192.168.200.0/24 | Restricted management network |

### Assumptions

- The Windows Server acting as the Domain Controller is configured and running Active Directory Domain Services (AD DS).
- The Windows 10/11 workstation is joined to the domain.
- All systems can communicate on the LAN (192.168.10.0/24).
- You have administrative credentials for the domain.
- DNS is functional on the Domain Controller (192.168.10.5).

> **Note:** If your lab environment does not include separate DMZ or Admin network subnets, you can still complete this lab using Windows Firewall rules with remote address restrictions on the LAN. The concepts and skills are identical regardless of network topology.
> 

---

## Exercise 1: Network ACL Planning and Windows Firewall Implementation

**Estimated Time:** 75 minutes

**ELO Mapping:** 6A.1, 6A.2

**KSAT Mapping:** K0049, S0157, T0481A

### Background

Access control lists (ACLs) are the primary mechanism for controlling traffic flow on firewalls and network devices. Before implementing any rules, a Cyber Defense Infrastructure Support Specialist documents the intended rule set and obtains approval. This exercise walks through that planning and implementation process using Windows Firewall as the host-based enforcement point.

### Scenario

You are tasked with configuring access controls for a server (SVR01 at 192.168.10.10) that hosts a web application. The security requirements are:

- HTTP (TCP/80) and HTTPS (TCP/443) traffic is permitted from the LAN.
- SSH (TCP/22) is permitted only from the Admin network (192.168.200.0/24).
- DNS queries (UDP/53) from the server to the Domain Controller (192.168.10.5) are permitted.
- RDP (TCP/3389) is permitted only from the Admin network (192.168.200.0/24).
- All other inbound traffic is blocked by default.

### Step 1.1: Document the Planned Rules

Before touching any configuration, complete the following rule documentation table. Write the rules in order of specificity (most specific first, default deny last). This is your change request document.

| # | Action | Direction | Source | Destination | Protocol | Port | Description |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 |  |  |  |  |  |  |  |
| 2 |  |  |  |  |  |  |  |
| 3 |  |  |  |  |  |  |  |
| 4 |  |  |  |  |  |  |  |
| 5 |  |  |  |  |  |  |  |
| 6 |  |  |  |  |  |  |  |

> **Hint:** Remember the principle of first-match processing. Place specific allow rules before the general deny. Consider both inbound and outbound requirements.
> 

### Step 1.2: Verify Current Windows Firewall Status

Open an elevated PowerShell session on SVR01 and check the current firewall state.

```powershell
# Check firewall profile status
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
```

Record the output. Note which profiles are enabled and what the default actions are.

| Profile | Enabled | Default Inbound | Default Outbound |
| --- | --- | --- | --- |
| Domain |  |  |  |
| Private |  |  |  |
| Public |  |  |  |

### Step 1.3: Enable All Firewall Profiles

Ensure all three profiles are enabled. Run the following on SVR01:

```powershell
# Enable all firewall profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
```

Verify the change:

```powershell
Get-NetFirewallProfile | Select-Object Name, Enabled
```

### Step 1.4: Set Default Inbound Action to Block

Configure the firewall to deny all inbound traffic by default. This establishes the implicit deny baseline.

```powershell
# Set default inbound to block, outbound to allow
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow
```

> **Important:** Setting the default inbound action to Block means that any traffic without an explicit allow rule will be dropped. Ensure you have console access (not just RDP) to the server before making this change, or create the RDP allow rule first.
> 

### Step 1.5: Create Inbound Allow Rules

Create each firewall rule on SVR01. Run the following commands one at a time:

**Allow HTTP from LAN:**

```powershell
New-NetFirewallRule -DisplayName "Allow HTTP Inbound" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 80 `
    -RemoteAddress 192.168.10.0/24 `
    -Action Allow `
    -Description "Permit HTTP traffic from LAN to web server"
```

**Allow HTTPS from LAN:**

```powershell
New-NetFirewallRule -DisplayName "Allow HTTPS Inbound" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 443 `
    -RemoteAddress 192.168.10.0/24 `
    -Action Allow `
    -Description "Permit HTTPS traffic from LAN to web server"
```

**Allow SSH from Admin Network Only:**

```powershell
New-NetFirewallRule -DisplayName "Allow SSH from Admin" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 22 `
    -RemoteAddress 192.168.200.0/24 `
    -Action Allow `
    -Description "Permit SSH from Admin network only"
```

**Allow RDP from Admin Network Only:**

```powershell
New-NetFirewallRule -DisplayName "Allow RDP from Admin" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 3389 `
    -RemoteAddress 192.168.200.0/24 `
    -Action Allow `
    -Description "Permit RDP from Admin network only"
```

**Allow DNS Response Traffic (if needed):**

```powershell
New-NetFirewallRule -DisplayName "Allow DNS to DC" `
    -Direction Outbound `
    -Protocol UDP `
    -RemotePort 53 `
    -RemoteAddress 192.168.10.5 `
    -Action Allow `
    -Description "Permit DNS queries to Domain Controller"
```

### Step 1.6: Verify the Configuration

List all enabled firewall rules you created:

```powershell
Get-NetFirewallRule | Where-Object {
    $_.Enabled -eq "True" -and $_.DisplayName -like "Allow*"
} | Select-Object DisplayName, Direction, Action, Enabled | Format-Table -AutoSize
```

For more detail including port and address filters, use:

```powershell
Get-NetFirewallRule | Where-Object {
    $_.DisplayName -like "Allow*"
} | ForEach-Object {
    $rule = $_
    $port = $_ | Get-NetFirewallPortFilter
    $addr = $_ | Get-NetFirewallAddressFilter
    [PSCustomObject]@{
        DisplayName   = $rule.DisplayName
        Direction     = $rule.Direction
        Action        = $rule.Action
        Protocol      = $port.Protocol
        LocalPort     = $port.LocalPort
        RemoteAddress = $addr.RemoteAddress
    }
} | Format-Table -AutoSize
```

**Capture a screenshot of this output.**

### Step 1.7: Test the Configuration

From WS01 (the workstation on the LAN), test connectivity to SVR01:

```powershell
# Test HTTP (should succeed from LAN)
Test-NetConnection -ComputerName 192.168.10.10 -Port 80

# Test HTTPS (should succeed from LAN)
Test-NetConnection -ComputerName 192.168.10.10 -Port 443

# Test SSH (should FAIL from LAN - only allowed from Admin network)
Test-NetConnection -ComputerName 192.168.10.10 -Port 22

# Test RDP (should FAIL from LAN - only allowed from Admin network)
Test-NetConnection -ComputerName 192.168.10.10 -Port 3389
```

Record your test results:

| Test | Source | Destination Port | Expected Result | Actual Result | Pass/Fail |
| --- | --- | --- | --- | --- | --- |
| HTTP from LAN | WS01 | 80 | Success |  |  |
| HTTPS from LAN | WS01 | 443 | Success |  |  |
| SSH from LAN | WS01 | 22 | Fail |  |  |
| RDP from LAN | WS01 | 3389 | Fail |  |  |

**Capture a screenshot of your test results.**

> **Troubleshooting:** If HTTP/HTTPS tests fail, verify the web service is running on SVR01 and that you used the correct RemoteAddress value. If SSH/RDP tests succeed when they should fail, verify the RemoteAddress restriction on those rules.
> 

### Knowledge Check: Network Access Control Lists

1. A firewall processes rules using first-match logic. What happens if a “deny all” rule is placed at the top of the rule set?
    1. Only encrypted traffic is allowed through
    2. **All traffic is blocked regardless of subsequent allow rules**
    3. The firewall ignores the deny rule and checks the next one
    4. Only traffic from the Admin network is permitted
    
    💡
    Firewalls evaluate rules from top to bottom and stop processing at the first match. Placing a “deny all” rule first means every packet matches that rule immediately and is dropped. Specific allow rules must precede general deny rules.
    
2. Why is the SSH allow rule restricted to the Admin network (192.168.200.0/24) rather than allowing it from any source?
    1. SSH does not function across different subnets
    2. Windows Firewall cannot filter SSH traffic by source
    3. **Restricting SSH to the Admin network enforces least privilege by limiting management access to authorized administrators**
    4. SSH is always blocked on Windows servers regardless of firewall rules
    
    💡
    The principle of least privilege requires that access be limited to only what is necessary. SSH and RDP are management protocols that should only be accessible from designated management networks, reducing the attack surface and limiting who can attempt administrative connections.
    
3. You configured both the default inbound action (Block) and explicit allow rules. Which cybersecurity principle does this combination represent?
    1. Separation of duties
    2. Non-repudiation
    3. **Defense-in-depth with implicit deny**
    4. Mandatory access control
    
    💡
    Setting the default action to Block creates an implicit deny baseline, meaning anything not explicitly permitted is automatically denied. Combined with specific allow rules, this implements the defense-in-depth principle where multiple controls work together to protect the system.
    

---

## Exercise 2: NTFS Permission Implementation

**Estimated Time:** 60 minutes

**ELO Mapping:** 6A.3

**KSAT Mapping:** K0049, S0157

### Background

NTFS permissions are the primary mechanism for controlling access to files and folders on Windows systems. Effective NTFS permission management requires understanding inheritance, explicit versus inherited permissions, and the interaction between allow and deny entries. In this exercise, you create a secure project folder structure, configure security groups, and assign permissions using PowerShell.

### Scenario

Your organization is establishing a new project called “ProjectAlpha.” The following access requirements have been defined:

| Group | Permission Required | Scope |
| --- | --- | --- |
| Administrators | Full Control | ProjectAlpha folder and all subfolders |
| SYSTEM | Full Control | ProjectAlpha folder and all subfolders |
| ProjectAlpha_Managers | Modify | ProjectAlpha folder and all subfolders |
| ProjectAlpha_Members | Read & Execute | ProjectAlpha folder and all subfolders |
| ProjectAlpha_Editors | Modify | Documents subfolder only |
| All other users | No access | Entire structure |

### Step 2.1: Create Security Groups

On the Domain Controller (DC01), open an elevated PowerShell session and create the required security groups:

```powershell
# Create security groups for ProjectAlpha
New-ADGroup -Name "ProjectAlpha_Managers" `
    -GroupScope Global `
    -GroupCategory Security `
    -Description "Managers for Project Alpha with Modify access"

New-ADGroup -Name "ProjectAlpha_Members" `
    -GroupScope Global `
    -GroupCategory Security `
    -Description "Members of Project Alpha with Read access"

New-ADGroup -Name "ProjectAlpha_Editors" `
    -GroupScope Global `
    -GroupCategory Security `
    -Description "Editors for Project Alpha Documents subfolder"
```

Verify the groups were created:

```powershell
Get-ADGroup -Filter 'Name -like "ProjectAlpha*"' | Select-Object Name, GroupScope, GroupCategory
```

### Step 2.2: Add Test Users to Groups

If your domain does not already have test users, create them, then add them to the appropriate groups:

```powershell
# Create test users (skip if users already exist)
New-ADUser -Name "PA_Manager1" -SamAccountName "PA_Manager1" `
    -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
    -Enabled $true -Path "CN=Users,DC=yourdomain,DC=local"

New-ADUser -Name "PA_Member1" -SamAccountName "PA_Member1" `
    -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
    -Enabled $true -Path "CN=Users,DC=yourdomain,DC=local"

New-ADUser -Name "PA_Editor1" -SamAccountName "PA_Editor1" `
    -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
    -Enabled $true -Path "CN=Users,DC=yourdomain,DC=local"

# Add users to groups
Add-ADGroupMember -Identity "ProjectAlpha_Managers" -Members "PA_Manager1"
Add-ADGroupMember -Identity "ProjectAlpha_Members" -Members "PA_Member1"
Add-ADGroupMember -Identity "ProjectAlpha_Editors" -Members "PA_Editor1"
```

> **Note:** Replace `yourdomain.local` with your actual domain name throughout this exercise.
> 

### Step 2.3: Create the Folder Structure

On SVR01 (or DC01 if no separate file server is available), create the project folders:

```powershell
# Create the folder structure
New-Item -Path "C:\Projects" -ItemType Directory -Force
New-Item -Path "C:\Projects\ProjectAlpha" -ItemType Directory -Force
New-Item -Path "C:\Projects\ProjectAlpha\Documents" -ItemType Directory -Force
New-Item -Path "C:\Projects\ProjectAlpha\Reports" -ItemType Directory -Force
New-Item -Path "C:\Projects\ProjectAlpha\Archives" -ItemType Directory -Force
```

Verify the structure:

```powershell
Get-ChildItem -Path "C:\Projects\ProjectAlpha" -Directory | Select-Object Name, FullName
```

### Step 2.4: Disable Inheritance and Clear Inherited Permissions

By default, folders inherit permissions from their parent. To enforce a clean, explicit permission structure, disable inheritance on the ProjectAlpha root folder:

```powershell
$path = "C:\Projects\ProjectAlpha"
$acl = Get-Acl $path

# Disable inheritance and remove all inherited permissions
# First parameter: $true = protect (block inheritance)
# Second parameter: $false = do NOT copy inherited permissions as explicit
$acl.SetAccessRuleProtection($true, $false)
Set-Acl -Path $path -AclObject $acl
```

> **Important:** After running this command, the folder will have NO permissions until you add explicit entries in the next step. This is expected and correct — you are building the permission set from scratch.
> 

### Step 2.5: Assign Permissions to the ProjectAlpha Folder

Add each required permission entry:

```powershell
$path = "C:\Projects\ProjectAlpha"
$acl = Get-Acl $path

# SYSTEM - Full Control (required for OS operations)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "NT AUTHORITY\SYSTEM",
    "FullControl",
    "ContainerInherit,ObjectInherit",
    "None",
    "Allow"
)
$acl.AddAccessRule($rule)

# Administrators - Full Control
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Administrators",
    "FullControl",
    "ContainerInherit,ObjectInherit",
    "None",
    "Allow"
)
$acl.AddAccessRule($rule)

# ProjectAlpha_Managers - Modify
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "YOURDOMAIN\ProjectAlpha_Managers",
    "Modify",
    "ContainerInherit,ObjectInherit",
    "None",
    "Allow"
)
$acl.AddAccessRule($rule)

# ProjectAlpha_Members - Read & Execute
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "YOURDOMAIN\ProjectAlpha_Members",
    "ReadAndExecute",
    "ContainerInherit,ObjectInherit",
    "None",
    "Allow"
)
$acl.AddAccessRule($rule)

# Apply the ACL
Set-Acl -Path $path -AclObject $acl
```

> **Note:** Replace `YOURDOMAIN` with your actual domain name (e.g., `YOURLAB\ProjectAlpha_Managers`).
> 

### Step 2.6: Add Subfolder-Specific Permissions

The ProjectAlpha_Editors group needs Modify access to the Documents subfolder only. Because the Documents folder inherits from ProjectAlpha, you add an explicit entry on top of the inherited permissions:

```powershell
$docPath = "C:\Projects\ProjectAlpha\Documents"
$acl = Get-Acl $docPath

# ProjectAlpha_Editors - Modify on Documents subfolder
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "YOURDOMAIN\ProjectAlpha_Editors",
    "Modify",
    "ContainerInherit,ObjectInherit",
    "None",
    "Allow"
)
$acl.AddAccessRule($rule)

Set-Acl -Path $docPath -AclObject $acl
```

### Step 2.7: Verify Permissions

Review the effective permissions on each folder:

```powershell
# View ProjectAlpha root permissions
Write-Host "`n=== ProjectAlpha Root Permissions ===" -ForegroundColor Cyan
(Get-Acl "C:\Projects\ProjectAlpha").Access |
    Format-Table IdentityReference, FileSystemRights, AccessControlType, IsInherited -AutoSize

# View Documents subfolder permissions
Write-Host "`n=== Documents Subfolder Permissions ===" -ForegroundColor Cyan
(Get-Acl "C:\Projects\ProjectAlpha\Documents").Access |
    Format-Table IdentityReference, FileSystemRights, AccessControlType, IsInherited -AutoSize

# View Reports subfolder permissions (should inherit from root only)
Write-Host "`n=== Reports Subfolder Permissions ===" -ForegroundColor Cyan
(Get-Acl "C:\Projects\ProjectAlpha\Reports").Access |
    Format-Table IdentityReference, FileSystemRights, AccessControlType, IsInherited -AutoSize
```

Complete the verification table with your actual results:

| Folder | Identity | Rights | Inherited? |
| --- | --- | --- | --- |
| ProjectAlpha | SYSTEM | FullControl | No |
| ProjectAlpha | BUILTIN | FullControl | No |
| ProjectAlpha | YOURDOMAIN_Managers | Modify | No |
| ProjectAlpha | YOURDOMAIN_Members | ReadAndExecute | No |
| Documents | YOURDOMAIN_Editors | Modify | No |
| Documents | (inherited entries from ProjectAlpha) | (varies) | Yes |
| Reports | (inherited entries from ProjectAlpha) | (varies) | Yes |

**Capture a screenshot of the permission verification output.**

### Step 2.8: Test Permissions (Optional but Recommended)

If you created test users in Step 2.2, test access by creating files under each identity. On WS01, log in as each test user and attempt the following:

- **PA_Manager1:** Navigate to `\\SVR01\C$\Projects\ProjectAlpha` and create a file. (Should succeed.)
- **PA_Member1:** Navigate to the same path and try to create a file. (Should fail — Read & Execute only.) Try opening an existing file. (Should succeed.)
- **PA_Editor1:** Navigate to the Documents subfolder and create a file. (Should succeed.) Navigate to the Reports subfolder and try to create a file. (Should fail.)

> **Note:** Testing over the network requires a file share to be configured, or you can use the administrative share (`C$`) if the test user has appropriate admin rights. Alternatively, use `runas` on the local system: `runas /user:YOURDOMAIN\PA_Member1 "cmd.exe"`
> 

### Knowledge Check: NTFS Permissions

1. After disabling inheritance on the ProjectAlpha folder and removing inherited permissions, what is the immediate effect?
    1. All users retain their previous access through cached credentials
    2. **No users or groups have any access to the folder until explicit permissions are added**
    3. Only the folder owner retains access
    4. The folder reverts to default Everyone: Full Control
    
    💡
    When you disable inheritance with the second parameter set to $false, all inherited permission entries are removed. The folder’s access control list becomes empty, meaning no principal (user, group, or service) has access until you explicitly add new entries.
    
2. A user belongs to both ProjectAlpha_Managers (Modify) and a group with an explicit Deny Write entry. What is the user’s effective permission?
    1. Modify, because the allow entry was set first
    2. Modify, because group permissions are cumulative
    3. No access at all — the account is locked out
    4. **Read and Execute only — the Deny Write overrides the Write component of Modify, leaving Read and Execute intact**
    
    💡
    In Windows NTFS, Deny entries always take precedence over Allow entries. When a user has Modify (which includes Write) from one group and Deny Write from another, the Deny removes the Write capability. The remaining Read and Execute permissions from Modify still apply because they are not explicitly denied.
    
3. The ProjectAlpha_Editors group has Modify access to the Documents subfolder but not to the Reports subfolder. Which inheritance behavior makes this possible?
    1. Editors were given explicit Deny on Reports
    2. Reports has inheritance disabled
    3. **Editors’ Modify permission was applied explicitly to Documents only and does not exist in the parent folder’s inheritable ACL**
    4. Editors’ access is controlled by Group Policy, not NTFS
    
    💡
    The Editors group was given an explicit Modify entry only on the Documents subfolder. Because this entry does not exist on the ProjectAlpha root folder, it is not part of the inheritable permission set. Reports inherits only from ProjectAlpha, where Editors have no entry, so Editors receive no access to Reports through inheritance.
    

---

## Exercise 3: Group Policy Access Control Enforcement

**Estimated Time:** 60 minutes

**ELO Mapping:** 6A.4

**KSAT Mapping:** K0049, S0157, T0393B

### Background

Group Policy Objects (GPOs) provide centralized access control enforcement across domain-joined systems. Instead of configuring security settings on each workstation individually, GPOs push consistent policies from the Domain Controller. This exercise configures a GPO that enforces user rights assignments, security options, and restricted group membership on domain workstations.

### Scenario

You need to create and link a GPO named “Workstation Access Control Policy” that:

- Restricts who can log on locally and via RDP
- Prevents guest and local accounts from network access
- Renames the default Administrator and Guest accounts
- Hides the last logged-on username
- Controls local Administrators group membership

### Step 3.1: Create and Link the GPO

On DC01, open the Group Policy Management Console. You can launch it from PowerShell:

```powershell
gpmc.msc
```

Perform the following steps:

1. In the left pane, expand your domain.
2. Right-click the Organizational Unit (OU) containing your workstations (or create a “Workstations” OU if one does not exist).
3. Select **Create a GPO in this domain, and Link it here…**
4. Name the GPO: **Workstation Access Control Policy**
5. Click **OK**.

> **Note:** If you do not have a dedicated Workstations OU, you can link the GPO to an existing OU for testing purposes. Do not link test GPOs to the domain root in a production environment.
> 

### Step 3.2: Configure User Rights Assignment

Right-click the new GPO and select **Edit**. Navigate to:

**Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > User Rights Assignment**

Configure the following settings:

| Setting | Configure | Add/Set To |
| --- | --- | --- |
| Allow log on locally | Define this policy | Domain Users, Administrators |
| Deny log on locally | Define this policy | Guests |
| Deny access to this computer from the network | Define this policy | Guests, Local account |
| Allow log on through Remote Desktop Services | Define this policy | Remote Desktop Users, Administrators |
| Deny log on through Remote Desktop Services | Define this policy | Guests, Local account |

For each setting:

1. Double-click the setting name.
2. Check **Define these policy settings**.
3. Click **Add User or Group…** and add the appropriate entries.
4. Click **OK**.

**Capture a screenshot showing at least two of these configured settings.**

### Step 3.3: Configure Security Options

In the same GPO editor, navigate to:

**Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options**

Configure the following settings:

| Setting | Value |
| --- | --- |
| Accounts: Rename administrator account | LocalAdmin |
| Accounts: Rename guest account | NotInUse |
| Interactive logon: Do not display last user name | Enabled |
| Interactive logon: Message title for users attempting to log on | Authorized Use Only |
| Interactive logon: Message text for users attempting to log on | This system is for authorized users only. Activity is monitored. |
| Network access: Do not allow anonymous enumeration of SAM accounts | Enabled |
| Network access: Do not allow anonymous enumeration of SAM accounts and shares | Enabled |

For each setting, double-click it, check **Define this policy setting**, and enter the specified value.

### Step 3.4: Configure Restricted Groups

Restricted Groups ensures that only authorized accounts are members of the local Administrators group on workstations. Navigate to:

**Computer Configuration > Policies > Windows Settings > Security Settings > Restricted Groups**

1. Right-click **Restricted Groups** and select **Add Group…**
2. Type **Administrators** and click **OK**.
3. In the properties window, under **Members of this group**, click **Add…**
4. Add the following:
    - `YOURDOMAIN\Domain Admins`
    - `YOURDOMAIN\Workstation_Admins` (create this group first if it does not exist)
5. Click **OK**.

> **Important:** The Restricted Groups “Members of this group” setting is authoritative. It replaces the entire local group membership on each workstation with exactly the entries you specify. Any account not listed here will be removed from the local Administrators group at the next policy refresh.
> 

If the `Workstation_Admins` group does not exist, create it on DC01:

```powershell
New-ADGroup -Name "Workstation_Admins" `
    -GroupScope Global `
    -GroupCategory Security `
    -Description "Authorized workstation administrators"
```

### Step 3.5: Apply and Verify the GPO

On WS01 (the domain-joined workstation), force a Group Policy update:

```powershell
gpupdate /force
```

Wait for the command to complete, then verify the policy was applied:

```powershell
# Generate a policy results report
gpresult /r
```

Look for the “Workstation Access Control Policy” GPO in the output under **Applied Group Policy Objects**.

For a detailed HTML report:

```powershell
gpresult /h C:\GPOReport.html
Start-Process C:\GPOReport.html
```

**Capture a screenshot of the gpresult /r output showing the GPO is applied.**

### Step 3.6: Validate Specific Settings

Verify individual settings took effect on WS01:

**Check account renaming:**

```powershell
# Verify the local Administrator account was renamed
Get-LocalUser | Where-Object {$_.SID -like "*-500"} | Select-Object Name, SID
```

The account with SID ending in -500 should now show the name “LocalAdmin.”

**Check local Administrators group membership:**

```powershell
# Verify Restricted Groups enforcement
Get-LocalGroupMember -Group "Administrators"
```

Only the groups specified in Step 3.4 should appear.

**Capture a screenshot of both verification outputs.**

### Knowledge Check: Group Policy

1. You configure Restricted Groups to define the Administrators group with only Domain Admins and Workstation_Admins. A local user named “TechSupport” was previously added to the local Administrators group on a workstation. What happens at the next Group Policy refresh?
    1. TechSupport remains in the group because local changes take precedence
    2. The GPO fails because it cannot remove manually added users
    3. **TechSupport is automatically removed because Restricted Groups replaces the entire group membership with only the defined entries**
    4. TechSupport is moved to the Power Users group instead
    
    💡
    The “Members of this group” setting in Restricted Groups is authoritative. At each Group Policy refresh, the local group’s membership is replaced entirely with the entries defined in the GPO. Any account not listed — including manually added local users — is removed. This enforces least privilege consistently across all workstations.
    
2. Which of the following settings helps prevent an attacker from identifying valid usernames on a workstation? (Select TWO)
    1. Accounts: Rename administrator account
    2. **Interactive logon: Do not display last user name**
    3. Deny log on locally for Guests
    4. **Network access: Do not allow anonymous enumeration of SAM accounts**
    
    💡
    “Do not display last user name” prevents an attacker with physical or remote access to the logon screen from seeing which account was last used. “Do not allow anonymous enumeration of SAM accounts” blocks unauthenticated queries that could enumerate all user accounts on the system. Together, these settings make it harder for an attacker to discover valid account names for credential attacks.
    
3. A GPO is linked to the Workstations OU, but after running `gpupdate /force` on a workstation, the policy does not appear in `gpresult /r`. What is the most likely cause?
    1. The workstation’s firewall is blocking Group Policy
    2. **The workstation’s computer account is not in the OU where the GPO is linked**
    3. The GPO only applies after a full system restart
    4. User rights assignments require manual application
    
    💡
    A GPO applies to computer and user accounts that reside within the OU (or child OUs) where the GPO is linked. If the workstation’s computer object is in a different OU (such as the default “Computers” container), the GPO will not apply. Move the computer object to the correct OU and run `gpupdate /force` again.
    

---

## Exercise 4: Access Control Documentation and Validation

**Estimated Time:** 45 minutes

**ELO Mapping:** 6A.5

**KSAT Mapping:** K0049, T0393B

### Background

Documentation is a critical component of access control management. In operational environments, every access control change requires documentation that includes the rule or permission, its justification, and evidence that it was tested and validated. This exercise consolidates all configurations from Exercises 1–3 into a formal access control documentation package.

### Step 4.1: Network ACL Documentation

Complete the following table with the firewall rules you implemented in Exercise 1. Include the justification for each rule.

| Rule # | Name | Source | Destination | Protocol/Port | Action | Justification |
| --- | --- | --- | --- | --- | --- | --- |
| 1 |  |  |  |  |  |  |
| 2 |  |  |  |  |  |  |
| 3 |  |  |  |  |  |  |
| 4 |  |  |  |  |  |  |
| 5 |  |  |  |  |  |  |
| 6 | Default Deny | Any | Any | Any | Block | Implicit deny — all traffic not explicitly permitted is blocked |

### Step 4.2: NTFS Permission Matrix

Complete the following table documenting the permission structure from Exercise 2:

| Folder | Group/Identity | Permission | Inherited | Justification |
| --- | --- | --- | --- | --- |
| C: | SYSTEM | Full Control | No |  |
| C: | BUILTIN | Full Control | No |  |
| C: | ProjectAlpha_Managers | Modify | No |  |
| C: | ProjectAlpha_Members | ReadAndExecute | No |  |
| C: | ProjectAlpha_Editors | Modify | No |  |
| C: | (inherited only) | (inherited) | Yes |  |

### Step 4.3: GPO Settings Summary

Complete the following table documenting the Group Policy settings from Exercise 3:

| Setting Category | Setting | Value | Purpose |
| --- | --- | --- | --- |
| User Rights | Allow log on locally |  |  |
| User Rights | Deny log on locally |  |  |
| User Rights | Deny access from network |  |  |
| User Rights | Allow RDP logon |  |  |
| Security Options | Rename administrator account |  |  |
| Security Options | Rename guest account |  |  |
| Security Options | Do not display last user name |  |  |
| Security Options | Block anonymous SAM enumeration |  |  |
| Restricted Groups | Administrators members |  |  |

### Step 4.4: Defense-in-Depth Summary

Write a brief paragraph (4–6 sentences) explaining how the access controls you implemented across Exercises 1–3 work together to provide defense-in-depth. Address the following points:

- How do the network-level controls (firewall rules) complement the host-level controls (NTFS, GPO)?
- What happens if one layer of control fails or is misconfigured?
- How does least privilege apply across all three layers?

Use the space below for your response:

> *(Write your defense-in-depth summary here.)*
> 

### Knowledge Check: Access Control Documentation

1. During a routine audit, an inspector asks why you implemented firewall rules on both the network perimeter AND the host-based Windows Firewall. What is the correct justification?
    1. Network firewalls cannot filter traffic within the same subnet
    2. Windows Firewall provides better logging than network firewalls
    3. **Defense-in-depth requires multiple layers of controls so that if one layer is compromised or misconfigured, the other still provides protection**
    4. It is a DoD STIG requirement to have exactly two firewalls
    
    💡
    Defense-in-depth is the practice of implementing multiple independent layers of security controls. If a network firewall is misconfigured or bypassed (for example, through lateral movement within the LAN), the host-based firewall still enforces access restrictions. Each layer operates independently, providing redundant protection.
    
2. An administrator changes firewall rules on a server but does not update the access control documentation. What risk does this create?
    1. The firewall rules automatically revert after 24 hours
    2. Other administrators cannot view the firewall configuration
    3. **Undocumented changes create compliance gaps, make troubleshooting difficult, and may introduce unauthorized access that goes undetected during audits**
    4. The documentation system blocks unapproved changes
    
    💡
    Access control documentation serves as the authoritative record of what access is authorized and why. When changes are made without updating documentation, auditors cannot verify compliance, other team members cannot understand the intended configuration, and unauthorized or excessive access may persist undetected.
    

---

## Lab Completion Checklist

Before submitting this lab, verify:

- [ ]  Completed ACL planning table (Exercise 1, Step 1.1)
- [ ]  Windows Firewall profiles enabled with default inbound set to Block
- [ ]  All five inbound/outbound firewall rules created and verified
- [ ]  Connectivity tests completed and results recorded
- [ ]  Security groups created in Active Directory
- [ ]  Folder structure created with inheritance disabled on ProjectAlpha
- [ ]  NTFS permissions applied to ProjectAlpha root and Documents subfolder
- [ ]  Permission verification output captured
- [ ]  GPO created and linked to the Workstations OU
- [ ]  User Rights Assignment configured in GPO
- [ ]  Security Options configured in GPO
- [ ]  Restricted Groups configured in GPO
- [ ]  GPO applied and verified with gpresult
- [ ]  Account renaming and group membership validated
- [ ]  All documentation tables completed (Exercise 4)
- [ ]  Defense-in-depth summary written
- [ ]  All knowledge check questions answered
- [ ]  All required screenshots captured

### Screenshots Required

1. Windows Firewall rule verification output (Exercise 1, Step 1.6)
2. Connectivity test results (Exercise 1, Step 1.7)
3. NTFS permission verification output (Exercise 2, Step 2.7)
4. GPO User Rights Assignment or Security Options settings (Exercise 3, Step 3.2 or 3.3)
5. gpresult output showing applied GPO (Exercise 3, Step 3.5)
6. Account rename and Administrators group membership verification (Exercise 3, Step 3.6)

---

## Troubleshooting Guide

### Windows Firewall Rules Not Working

| Symptom | Possible Cause | Resolution |
| --- | --- | --- |
| All traffic blocked after setting default Block | Allow rules not created or not enabled | Verify rules exist: `Get-NetFirewallRule` |
| Traffic allowed despite Block rule | Rule order conflict or wrong profile | Check which profile is active: `Get-NetFirewallProfile` |
| Test-NetConnection shows fail for allowed port | Service not running on that port | Verify listener: `Get-NetTCPConnection -LocalPort <port>` |
| RemoteAddress filter not working | Incorrect CIDR notation | Verify format: `192.168.200.0/24` not `192.168.200.0/255.255.255.0` |

### NTFS Permission Issues

| Symptom | Possible Cause | Resolution |
| --- | --- | --- |
| Access denied after setting permissions | Domain name mismatch in ACL entry | Verify domain: `$env:USERDOMAIN` |
| User has more access than expected | Inheritance not disabled properly | Check: `(Get-Acl $path).AreAccessRulesProtected` should be True |
| Set-Acl fails with access denied | Not running as Administrator | Run PowerShell as Administrator |
| Group membership change not taking effect | User session caches old token | User must log off and log back on |

### Group Policy Issues

| Symptom | Possible Cause | Resolution |
| --- | --- | --- |
| GPO not appearing in gpresult | Computer not in target OU | Verify OU: `Get-ADComputer <name> \| Select DistinguishedName` |
| GPO applied but settings not effective | Conflicting GPO with higher precedence | Check precedence in GPMC |
| Restricted Groups not enforcing | GPO processing error | Check event log: `Get-WinEvent -LogName "Microsoft-Windows-GroupPolicy/Operational" -MaxEvents 10` |
| Account rename not applied | Security Options require restart | Restart the workstation |

---

## Extension Challenges (Optional)

If you complete the lab early, attempt these advanced tasks:

### Challenge 1: PowerShell Audit Script

Write a PowerShell script that audits the current system and reports:
- All enabled firewall rules with port and address filters
- NTFS permissions on a specified folder path
- Local Administrators group membership
- Whether the last-logged-on username is hidden

### Challenge 2: Effective Access Testing

Use the `Get-Acl` cmdlet and the `AccessChk` utility (from Sysinternals) to determine the effective permissions for each test user on every folder in the ProjectAlpha structure. Document any differences between expected and actual effective permissions.

### Challenge 3: Linux Comparison

On the Ubuntu system (192.168.10.60), implement equivalent access controls:
- Configure `ufw` or `iptables` to match the Windows Firewall rules from Exercise 1
- Create a similar folder structure and use `chmod` and `chown` with groups to match the NTFS permissions from Exercise 2
- Document the differences between Windows and Linux access control implementation

---

## Summary

In this lab, you implemented a multi-layered access control configuration by:

1. **Planning and documenting network ACLs** before implementation, establishing the discipline of change management for access control modifications
2. **Configuring host-based firewall rules** using PowerShell to enforce traffic restrictions at the server level, providing defense-in-depth alongside network perimeter controls
3. **Implementing NTFS permissions** with explicit access control entries, inheritance management, and security group-based assignments to enforce least privilege on file system resources
4. **Deploying Group Policy** to enforce consistent access control settings across domain workstations, including user rights restrictions, security hardening options, and controlled group membership
5. **Documenting all configurations** with justification and test evidence to support audit compliance and operational continuity

These skills directly support the Cyber Defense Infrastructure Support Specialist role in maintaining and administering access controls on cyber defense infrastructure per DCWF requirements.

---

*Document Version: 1.0*

*Classification: UNCLASSIFIED // FOR TRAINING USE ONLY*