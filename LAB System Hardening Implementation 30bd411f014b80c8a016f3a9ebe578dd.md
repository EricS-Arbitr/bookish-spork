# LAB: System Hardening Implementation

Owner: Eric Starace
Last edited by: Eric Starace

# LAB: System Hardening Implementation

## Cyber Defense Infrastructure Support Specialist Course

| **Estimated Completion Time** | 4–5 hours |
| --- | --- |
| **Prerequisites** | Lesson 9; Lab 6A (Implementing Access Controls); Basic PowerShell and Linux command line |
| **Lab Type** | Hands-on technical configuration |
| **Classification** | UNCLASSIFIED // FOR TRAINING USE ONLY |

---

## Terminal Learning Objective

Apply hardening measures to Windows Server, Ubuntu Linux, and network communications by configuring account policies, disabling unnecessary services and protocols, implementing host-based firewalls, hardening remote access, deploying TLS-secured services, and documenting all changes in accordance with the CPT Enable Hardening function.

## Enabling Learning Objectives

| ELO | Objective |
| --- | --- |
| 9A.1 | Configure STIG-aligned password policies, disable unnecessary services and protocols, and harden the Windows Firewall on a domain-joined server |
| 9A.2 | Harden SSH with key-based authentication, apply kernel tuning via sysctl, configure iptables with default-deny, and deploy auditd rules on Ubuntu |
| 9A.3 | Generate TLS certificates, configure a web server with hardened TLS settings, and implement chroot-restricted SFTP to replace insecure protocols |
| 9A.4 | Produce hardening documentation including a system inventory, applied-settings checklists, and deviation justifications |

## Tools Implemented / Required

| Tool | Purpose | Type |
| --- | --- | --- |
| PowerShell | Windows hardening and verification | Administration Tool |
| Group Policy Management Console | Centralized policy deployment | Policy Management |
| OpenSSL | TLS certificate generation | PKI Tool |
| Nginx | Web server for TLS configuration | Web Server |
| iptables | Linux host-based firewall | Firewall |
| auditd | Linux audit framework | Audit Tool |

## KSAT Alignment

| KSAT ID | Type | Description |
| --- | --- | --- |
| K3143 | Knowledge (Additional) | Knowledge of basic system, network, and OS hardening techniques |
| S6670 | Skill (Additional) | Skill in system, network, and OS hardening techniques |
| S0893 | Skill (Additional) | Skill in securing network communications |
| T2772 | Task (Core) | Build, install, configure, and test dedicated cyber defense hardware |

📋 **Doctrinal Reference — CWP 3-33.4:** This lab supports the CPT Enable Hardening function: *“Actions taken on specified terrain in cyberspace to reduce attack threat surfaces and increase difficulty of access and system exploitation by threat-specific unauthorized activities.”*

---

## Lab Environment

| System | Role | IP Address |
| --- | --- | --- |
| Windows Server 2019/2022 | Domain Controller (DC01) | 192.168.10.5 |
| Windows Server 2019/2022 | Member Server (SVR01) | 192.168.10.10 |
| Windows 10/11 Workstation | Admin Workstation (WS01) | 192.168.10.50 |
| Ubuntu Server 22.04 LTS | Linux Server (YOURSERVER) | 192.168.10.100 |

Active Directory must be operational on DC01. SVR01 and WS01 must be domain-joined. Elasticsearch/Kibana on the Ubuntu server is not required for this lab.

---

## Exercise 1: Windows Server Hardening

**Estimated Time:** 75 minutes

**ELO Mapping:** 9A.1

### Step 1.1: Configure Account and Password Policies

On DC01, open an elevated PowerShell session:

```powershell
# Configure STIG-aligned password policy
Set-ADDefaultDomainPasswordPolicy -Identity "yourdomain.local" `
    -MinPasswordLength 14 `
    -PasswordHistoryCount 24 `
    -MaxPasswordAge "60.00:00:00" `
    -MinPasswordAge "1.00:00:00" `
    -ComplexityEnabled $true `
    -LockoutThreshold 3 `
    -LockoutDuration "00:15:00" `
    -LockoutObservationWindow "00:15:00"

# Verify
Get-ADDefaultDomainPasswordPolicy | Format-List MinPasswordLength,
    PasswordHistoryCount, MaxPasswordAge, MinPasswordAge,
    ComplexityEnabled, LockoutThreshold, LockoutDuration
```

On SVR01, rename the built-in Administrator and disable the Guest account:

```powershell
Rename-LocalUser -Name "Administrator" -NewName "SvrLocalAdmin"
Disable-LocalUser -Name "Guest"

# Verify (Administrator SID always ends in -500)
Get-LocalUser | Select-Object Name, Enabled, SID | Format-Table
```

**Capture a screenshot of the password policy and account changes.**

### Step 1.2: Disable Unnecessary Services and Protocols

On SVR01:

```powershell
# Disable unnecessary services
$servicesToDisable = @("RemoteRegistry", "Spooler", "Fax")
foreach ($svc in $servicesToDisable) {
    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
    Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Host "Disabled:$svc" -ForegroundColor Green
}

# Disable SMBv1
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
```

Disable LLMNR via Group Policy on DC01:

1. Open `gpmc.msc`, create a GPO named **Server Hardening – Protocol Restrictions** and link it to the Servers OU.
2. Edit the GPO: **Computer Configuration > Policies > Administrative Templates > Network > DNS Client**
3. Set **Turn off multicast name resolution** to **Enabled**.

Disable NetBIOS on SVR01:

```powershell
# Disable NetBIOS on all adapters (Value 2 = Disable)
$adapters = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
foreach ($adapter in $adapters) {
    Set-ItemProperty -Path $adapter.PSPath -Name "NetbiosOptions" -Value 2
}
```

### Step 1.3: Harden Windows Firewall

On SVR01:

```powershell
# Enable firewall, default deny inbound, enable logging
Set-NetFirewallProfile -Profile Domain,Public,Private `
    -Enabled True `
    -DefaultInboundAction Block `
    -DefaultOutboundAction Allow `
    -LogAllowed True `
    -LogBlocked True `
    -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"

# Allow RDP from admin workstation only
New-NetFirewallRule -DisplayName "HARDENED - RDP from WS01" `
    -Direction Inbound -LocalPort 3389 -Protocol TCP `
    -RemoteAddress 192.168.10.50 -Action Allow

# Allow ICMP from LAN
New-NetFirewallRule -DisplayName "HARDENED - ICMP from LAN" `
    -Direction Inbound -Protocol ICMPv4 -IcmpType 8 `
    -RemoteAddress 192.168.10.0/24 -Action Allow

# Verify
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction | Format-Table
Get-NetFirewallRule -DisplayName "HARDENED*" | Select-Object DisplayName, Direction, Action | Format-Table
```

**Capture a screenshot of the firewall profile settings and custom rules.**

### Step 1.4: Configure Audit Policy

On SVR01:

```powershell
# Account and logon events
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Policy and privilege tracking
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

# Process creation (enables command-line logging when paired with GPO)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Verify
auditpol /get /category:* | Select-String "Success|Failure"
```

> **Note:** To capture full command lines in Event ID 4688 events, also enable **Include command line in process creation events** in the GPO under Computer Configuration > Administrative Templates > System > Audit Process Creation.
> 

### Knowledge Check: Windows Hardening

1. You disable LLMNR and NetBIOS on all servers. What specific attack technique does this mitigate?
    1. SQL injection against web applications
    2. **LLMNR/NBT-NS poisoning, where an attacker responds to broadcast name resolution requests to capture NTLMv2 hashes for offline cracking**
    3. Brute force attacks against the Administrator account
    4. Buffer overflow attacks against the SMB service
    
    💡
    When DNS fails, Windows falls back to LLMNR and NetBIOS broadcast queries. An attacker running tools like Responder can answer these broadcasts, impersonating the requested resource and capturing NTLMv2 authentication hashes. Disabling both protocols eliminates this attack vector.
    

---

## Exercise 2: Linux Server Hardening

**Estimated Time:** 75 minutes

**ELO Mapping:** 9A.2

### Step 2.1: Harden SSH

On the Ubuntu server (192.168.10.100):

```bash
# Back up original configuration
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
```

Generate an SSH key on the admin workstation and copy it to the server:

```bash
# On the admin workstation (Linux/Mac) or WS01 (Windows OpenSSH)
ssh-keygen -t ed25519 -a 100 -C "admin@cyberdefenselab"

# Copy the public key to the server
ssh-copy-id -i ~/.ssh/id_ed25519.pub admin@192.168.10.100
```

> **Important:** Verify key-based login works BEFORE disabling password authentication. If you disable passwords without a working key, you will be locked out.
> 

Apply the hardened configuration:

```bash
sudo nano /etc/ssh/sshd_config
```

Set the following values:

```
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
AllowTcpForwarding no
X11Forwarding no
AllowUsers admin
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
LogLevel VERBOSE
Banner /etc/issue.net
```

Create a login banner:

```bash
sudo tee /etc/issue.net << 'EOF'
***********************************************************************
WARNING: This system is for authorized use only. All activity is
monitored and recorded. Unauthorized access is prohibited.
***********************************************************************
EOF
```

Secure file permissions and restart:

```bash
sudo chmod 600 /etc/ssh/sshd_config
sudo sshd -t            # Validate before restarting
sudo systemctl restart sshd
```

Verify from the admin workstation:

```bash
# Should succeed (key-based)
ssh -i ~/.ssh/id_ed25519 admin@192.168.10.100

# Should FAIL (password disabled)
ssh -o PubkeyAuthentication=no admin@192.168.10.100
```

**Capture a screenshot of the successful key login and the failed password attempt.**

### Step 2.2: Kernel Hardening via sysctl

```bash
sudo nano /etc/sysctl.d/99-hardening.conf
```

```
# Anti-spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0

# SYN flood protection
net.ipv4.tcp_syncookies = 1

# Ignore broadcast pings (Smurf mitigation)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# ASLR
kernel.randomize_va_space = 2

# Disable IPv6 if not used
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
```

```bash
sudo sysctl --system

# Verify key settings
sysctl net.ipv4.conf.all.rp_filter net.ipv4.tcp_syncookies kernel.randomize_va_space
```

### Step 2.3: Configure iptables

```bash
# Flush existing rules
sudo iptables -F
sudo iptables -X

# Default policies
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow established/related connections
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH from admin workstation only
sudo iptables -A INPUT -p tcp -s 192.168.10.50 --dport 22 -j ACCEPT

# Allow Elasticsearch and Kibana from LAN (if applicable)
sudo iptables -A INPUT -p tcp -s 192.168.10.0/24 --dport 9200 -j ACCEPT
sudo iptables -A INPUT -p tcp -s 192.168.10.0/24 --dport 5601 -j ACCEPT

# Allow ICMP from LAN
sudo iptables -A INPUT -p icmp --icmp-type echo-request -s 192.168.10.0/24 -j ACCEPT

# Log and drop everything else
sudo iptables -A INPUT -j LOG --log-prefix "IPT-DROP: " --log-level 4
sudo iptables -A INPUT -j DROP

# Persist rules
sudo apt install -y iptables-persistent
sudo iptables-save | sudo tee /etc/iptables/rules.v4

# Verify
sudo iptables -L -v -n --line-numbers
```

**Capture a screenshot of the iptables rules.**

### Step 2.4: Configure auditd

```bash
sudo apt install -y auditd audispd-plugins
sudo nano /etc/audit/rules.d/hardening.rules
```

```
# Identity file changes
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity

# Sudoers changes
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# SSH configuration changes
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Privileged command execution
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Firewall rule changes
-w /etc/iptables/ -p wa -k firewall
```

```bash
sudo systemctl restart auditd
sudo auditctl -l   # Verify rules loaded
```

### Knowledge Check: Linux Hardening

1. The iptables configuration uses a default INPUT policy of DROP with explicit ACCEPT rules. This implements which security principle?
    1. Separation of duties
    2. Defense in depth
    3. **Least privilege — only explicitly permitted traffic is allowed; everything else is denied by default**
    4. Security through obscurity
    
    💡
    A default-deny firewall policy ensures that only traffic matching an explicit allow rule is permitted. Any new service, unexpected traffic, or attack attempt is automatically dropped without requiring a specific deny rule. This is the network equivalent of the principle of least privilege.
    

---

## Exercise 3: Securing Network Communications

**Estimated Time:** 60 minutes

**ELO Mapping:** 9A.3

### Step 3.1: Generate a TLS Certificate

On the Ubuntu server:

```bash
mkdir -p ~/tls-lab && cd ~/tls-lab

# Generate private key
openssl genrsa -out server.key 2048

# Generate CSR
openssl req -new -key server.key -out server.csr \
    -subj "/C=US/ST=Virginia/L=Fort Meade/O=Cyber Defense Lab/OU=Training/CN=server.cyberdefenselab.local"

# Create self-signed certificate (lab environment)
openssl req -x509 -nodes -days 365 -key server.key -in server.csr -out server.crt

# Verify certificate details
openssl x509 -text -noout -in server.crt | head -20

# Install to system locations
sudo cp server.crt /etc/ssl/certs/server.crt
sudo cp server.key /etc/ssl/private/server.key
sudo chmod 600 /etc/ssl/private/server.key
```

**Capture a screenshot of the certificate details.**

### Step 3.2: Configure Nginx with Hardened TLS

```bash
sudo apt install -y nginx
sudo nano /etc/nginx/sites-available/secure-site
```

```
# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name server.cyberdefenselab.local;
    return 301 https://$server_name$request_uri;
}

# HTTPS with hardened TLS
server {
    listen 443 ssl;
    server_name server.cyberdefenselab.local;

    ssl_certificate /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;

    # TLS 1.2 and 1.3 only
    ssl_protocols TLSv1.2 TLSv1.3;

    # Strong ciphers with forward secrecy
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_tickets off;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;

    root /var/www/secure-site;
    index index.html;
}
```

```bash
# Create test page
sudo mkdir -p /var/www/secure-site
echo "<h1>Secure Communications Verified</h1>" | sudo tee /var/www/secure-site/index.html

# Enable site
sudo ln -sf /etc/nginx/sites-available/secure-site /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl reload nginx

# Add HTTPS port to iptables
sudo iptables -I INPUT 6 -p tcp -s 192.168.10.0/24 --dport 443 -j ACCEPT
sudo iptables -I INPUT 7 -p tcp -s 192.168.10.0/24 --dport 80 -j ACCEPT
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

### Step 3.3: Verify TLS Configuration

```bash
# Verify TLS 1.2 works
openssl s_client -connect 192.168.10.100:443 -tls1_2 </dev/null 2>/dev/null | grep "Protocol\|Cipher is"

# Verify TLS 1.0 is REJECTED
openssl s_client -connect 192.168.10.100:443 -tls1 </dev/null 2>/dev/null | grep -E "Protocol|error"

# Verify TLS 1.1 is REJECTED
openssl s_client -connect 192.168.10.100:443 -tls1_1 </dev/null 2>/dev/null | grep -E "Protocol|error"

# Verify security headers and HTTP redirect
curl -kI https://192.168.10.100
curl -I http://192.168.10.100 2>/dev/null | head -3
```

Record results:

| Test | Expected | Actual |
| --- | --- | --- |
| TLS 1.2 connection | Success |  |
| TLS 1.0 connection | Rejected |  |
| TLS 1.1 connection | Rejected |  |
| HSTS header present | Yes |  |
| HTTP redirects to HTTPS | 301 redirect |  |

**Capture a screenshot of the TLS verification results and security headers.**

### Step 3.4: Configure Chroot-Restricted SFTP

```bash
# Create SFTP group and user
sudo groupadd sftpusers
sudo useradd -m -g sftpusers -s /usr/sbin/nologin sftpuser1
sudo passwd sftpuser1

# Create chroot directory structure
sudo mkdir -p /sftp/sftpuser1/uploads
sudo chown root:root /sftp/sftpuser1
sudo chmod 755 /sftp/sftpuser1
sudo chown sftpuser1:sftpusers /sftp/sftpuser1/uploads
sudo chmod 700 /sftp/sftpuser1/uploads
```

Add to the end of `/etc/ssh/sshd_config`:

```bash
sudo nano /etc/ssh/sshd_config
```

```
# SFTP - chroot restricted
Match Group sftpusers
    ChrootDirectory /sftp/%u
    ForceCommand internal-sftp
    AllowTcpForwarding no
    X11Forwarding no
```

```bash
sudo sshd -t
sudo systemctl restart sshd
```

Test from WS01 or another system:

```bash
sftp sftpuser1@192.168.10.100
# Once connected:
#   cd uploads        → should succeed
#   put testfile.txt  → should succeed
#   cd /etc           → should FAIL (chroot restricted)
#   exit

# Shell login should also fail
ssh sftpuser1@192.168.10.100   # should be denied
```

Confirm FTP is not running:

```bash
sudo ss -tlnp | grep ":21"   # Should return nothing
```

### Knowledge Check: Secure Communications

1. The Nginx configuration sets `ssl_protocols TLSv1.2 TLSv1.3` and the SFTP configuration uses `ForceCommand internal-sftp` with `ChrootDirectory`. What common security principle do both configurations implement?
    1. Defense in depth through redundant encryption
    2. Separation of duties between administrators
    3. **Reducing the attack surface by disabling insecure options and restricting users to only the capabilities they need**
    4. Security through obscurity by hiding service details
    
    💡
    Disabling TLS 1.0/1.1 removes known-vulnerable protocols, and chroot with ForceCommand restricts SFTP users to only file transfer within a confined directory. Both are examples of reducing the attack surface — eliminating capabilities that are not needed and could be exploited.
    

---

## Exercise 4: Hardening Documentation

**Estimated Time:** 30 minutes

**ELO Mapping:** 9A.4

Per CWP 3-33.4, hardening recommendations must be documented and reported to supported commanders, CSSPs, and local network defenders.

### Step 4.1: System Inventory

| System | Hostname | IP | OS | Hardening Applied |
| --- | --- | --- | --- | --- |
| Domain Controller | DC01 | 192.168.10.5 | Server 2019/2022 | Password policy, LLMNR GPO |
| Member Server | SVR01 | 192.168.10.10 | Server 2019/2022 | Services, protocols, firewall, audit |
| Linux Server | YOURSERVER | 192.168.10.100 | Ubuntu 22.04 | SSH, sysctl, iptables, auditd, TLS, SFTP |

### Step 4.2: Hardening Checklist

Complete the following, marking each item Y or N:

**Windows:**

| Measure | Applied | Verification Command |
| --- | --- | --- |
| Password policy (14+ chars, complexity, lockout) |  | `Get-ADDefaultDomainPasswordPolicy` |
| Administrator renamed, Guest disabled |  | `Get-LocalUser` |
| RemoteRegistry, Spooler, Fax disabled |  | `Get-Service RemoteRegistry,Spooler,Fax` |
| SMBv1 disabled |  | `Get-SmbServerConfiguration` |
| LLMNR disabled (GPO) |  | `gpresult /r` |
| NetBIOS disabled |  | Registry verification |
| Firewall enabled, default deny inbound |  | `Get-NetFirewallProfile` |
| RDP restricted to admin workstation |  | `Get-NetFirewallRule -DisplayName "HARDENED*"` |
| Audit policy configured |  | `auditpol /get /category:*` |

**Linux:**

| Measure | Applied | Verification Command |
| --- | --- | --- |
| SSH: root login disabled, key-only auth |  | `grep PermitRootLogin /etc/ssh/sshd_config` |
| SSH: strong ciphers, user restriction |  | `grep Ciphers /etc/ssh/sshd_config` |
| Kernel: rp_filter, SYN cookies, ASLR |  | `sysctl net.ipv4.tcp_syncookies` |
| iptables: default DROP, restricted SSH |  | `sudo iptables -L -n` |
| auditd: identity, sudoers, SSH monitoring |  | `sudo auditctl -l` |
| TLS 1.2+ only, strong ciphers, HSTS |  | `openssl s_client` test |
| SFTP: chroot restricted, no shell |  | SFTP test |
| FTP: not running |  | `ss -tlnp \| grep :21` |

### Step 4.3: Deviation Documentation

Document any measures that could not be applied:

| Measure | Reason Not Applied | Compensating Control |
| --- | --- | --- |
|  |  |  |

### Step 4.4: Defense-in-Depth Summary

Write 4–6 sentences explaining how the hardening measures in this lab create layered defenses. Address how account hardening, protocol restrictions, host-based firewalls, audit logging, and encrypted communications work together so that the failure of any single control does not compromise the system.

---

## Lab Completion Checklist

**Exercise 1 — Windows:**
- [ ] Password policy configured (14 char, complexity, lockout)
- [ ] Administrator renamed, Guest disabled
- [ ] Services disabled (RemoteRegistry, Spooler, Fax)
- [ ] SMBv1, LLMNR, NetBIOS disabled
- [ ] Firewall: default deny, RDP restricted, logging enabled
- [ ] Audit policy configured

**Exercise 2 — Linux:**
- [ ] SSH key-based auth working, passwords disabled
- [ ] SSH hardened (ciphers, root disabled, user restricted, banner)
- [ ] sysctl hardening applied
- [ ] iptables: default deny, restricted access, persistent
- [ ] auditd rules deployed and verified

**Exercise 3 — Secure Communications:**
- [ ] TLS certificate generated and installed
- [ ] Nginx configured with TLS 1.2+ and strong ciphers
- [ ] TLS 1.0/1.1 confirmed rejected
- [ ] Security headers present (HSTS, X-Content-Type-Options, X-Frame-Options)
- [ ] SFTP chroot working, shell login denied, FTP not running

**Exercise 4 — Documentation:**
- [ ] System inventory, checklists, deviations, and summary completed

### Screenshots Required

1. Windows password policy and renamed/disabled accounts (Exercise 1)
2. Windows Firewall profile and custom rules (Exercise 1)
3. SSH key login success and password login failure (Exercise 2)
4. iptables rules (Exercise 2)
5. TLS verification and security headers (Exercise 3)
6. Certificate details (Exercise 3)

---

## Troubleshooting Guide

| Symptom | Possible Cause | Resolution |
| --- | --- | --- |
| Locked out of SSH | Passwords disabled before key worked | Use console; restore sshd_config.bak |
| sshd won’t start | Config syntax error | Run `sudo sshd -t` for details |
| Cannot RDP to SVR01 | Firewall rule not matching WS01 | Verify RemoteAddress in rule |
| iptables blocking needed service | Missing allow rule | Add rule above LOG/DROP; save |
| TLS 1.0 test succeeds | ssl_protocols not applied | Verify directive; run `sudo nginx -t`; reload |
| SFTP chroot fails | Directory ownership wrong | Chroot parent must be root-owned, 755 |
| GPO not applying | Computer not in targeted OU | Run `gpresult /r` to check |

---

## Summary

In this lab you applied hardening measures across Windows, Linux, and network communications by:

1. Configuring STIG-aligned account policies, disabling attack-surface services and protocols (SMBv1, LLMNR, NetBIOS), hardening the Windows Firewall, and enabling audit logging
2. Hardening SSH with key-only authentication and restricted ciphers, applying kernel protections via sysctl, deploying a default-deny iptables firewall, and configuring auditd for critical file and command monitoring
3. Generating TLS certificates, deploying a web server with TLS 1.2+ and forward-secrecy ciphers, and implementing chroot-restricted SFTP as a secure replacement for FTP
4. Documenting all changes to support CPT Enable Hardening reporting and audit compliance

These measures address KSATs K3143 and S6670 (system, network, and OS hardening), S0893 (securing network communications), and T2772 (building and configuring cyber defense infrastructure).

---

*Document Version: 1.0*

*Classification: UNCLASSIFIED // FOR TRAINING USE ONLY*