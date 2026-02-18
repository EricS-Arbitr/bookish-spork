# LAB: VPN and Web Filtering Implementation

Owner: Eric Starace
Last edited by: Eric Starace

# Lab: VPN and Web Filtering Implementation

## Cyber Defense Infrastructure Support Specialist Course

| **Estimated Completion Time** | 3–4 hours |
| --- | --- |
| **Prerequisites** | Lesson 8 Sections 8.4 and 8.5; Lab 6A (Implementing Access Controls) recommended; Basic Linux administration |
| **Lab Type** | Hands-on technical deployment and configuration |
| **Classification** | UNCLASSIFIED // FOR TRAINING USE ONLY |

---

## Terminal Learning Objective

Deploy and configure a VPN service using OpenVPN and a web filtering proxy using Squid to provide encrypted communications and content-filtered web access for an enterprise network, with logging to support security monitoring.

## Enabling Learning Objectives

| ELO | Objective |
| --- | --- |
| 8D.1 | Install and configure an OpenVPN server on Ubuntu with certificate-based authentication |
| 8D.2 | Generate a PKI infrastructure including CA, server, and client certificates for VPN authentication |
| 8D.3 | Establish a VPN tunnel from a client and verify encrypted communications |
| 8D.4 | Install and configure Squid proxy with domain-based web filtering policies |
| 8D.5 | Create block lists and configure access control rules for web content filtering |
| 8D.6 | Test and verify web filtering enforcement by confirming permitted and blocked traffic |
| 8D.7 | Configure proxy logging and forward logs to support centralized security monitoring |

## Tools Implemented / Required

| Tool | Purpose | Type |
| --- | --- | --- |
| OpenVPN | Encrypted tunnel VPN service | VPN Server |
| Easy-RSA | Public Key Infrastructure management | PKI Tool |
| Squid | Web proxy and content filtering | Web Proxy |
| Ubuntu Server 22.04 LTS | Host for VPN and proxy services | Server OS |

## KSAT Alignment

| KSAT ID | Type | Description |
| --- | --- | --- |
| K0148 | Knowledge (Core) | Knowledge of Virtual Private Network (VPN) security |
| K0900 | Knowledge (Additional) | Knowledge of web filtering technologies |
| S0237 | Skill (Additional) | Skill in using Virtual Private Network (VPN) devices and encryption |
| T0769 | Task (Additional) | Perform system administration on specialized cyber defense applications and systems, to include installation, configuration, maintenance, backup and restoration |
| T2772 | Task (Core) | Build, install, configure, and test dedicated cyber defense hardware |

---

## Lab Environment

### Required Systems

| System | Role | IP Address |
| --- | --- | --- |
| Ubuntu Server 22.04 LTS | VPN Server + Web Proxy (YOURSERVER) | 192.168.10.100 |
| Windows 10/11 Workstation | VPN Client + Proxy Client (WS01) | 192.168.10.50 |
| Windows Server 2019/2022 | Domain Controller / DNS (DC01) | 192.168.10.5 |

### Network Configuration

| Network | Subnet | Purpose |
| --- | --- | --- |
| LAN | 192.168.10.0/24 | Production network |
| VPN Tunnel | 10.8.0.0/24 | VPN client address pool |

### Assumptions

- All systems are on the 192.168.10.0/24 LAN and can communicate.
- You have sudo access on the Ubuntu server.
- DNS is functional via DC01 (192.168.10.5).
- Internet access is available from the Ubuntu server for package installation.

---

## Exercise 1: OpenVPN Server Deployment

**Estimated Time:** 75 minutes

**ELO Mapping:** 8D.1, 8D.2, 8D.3

### Background

VPNs create encrypted tunnels that protect data in transit across untrusted networks. OpenVPN is a widely-used open-source VPN solution that supports SSL/TLS-based authentication and encryption. In DoD environments, VPNs protect communications between sites, remote users, and management networks. Per the DCWF, the Cyber Defense Infrastructure Support Specialist must be able to perform system administration on VPN devices, including installation, configuration, and maintenance (T0769).

### Step 1.1: Install OpenVPN and Easy-RSA

On the Ubuntu server (192.168.10.100):

```bash
sudo apt update
sudo apt install -y openvpn easy-rsa
```

### Step 1.2: Set Up the PKI Infrastructure

Create a dedicated directory for the Certificate Authority:

```bash
# Create the PKI directory
make-cadir ~/openvpn-ca
cd ~/openvpn-ca
```

Edit the `vars` file to set certificate parameters:

```bash
nano vars
```

Find and modify the following lines (uncomment them if needed and set values):

```bash
set_var EASYRSA_REQ_COUNTRY    "US"
set_var EASYRSA_REQ_PROVINCE   "Virginia"
set_var EASYRSA_REQ_CITY       "Fort Meade"
set_var EASYRSA_REQ_ORG        "Cyber Defense Lab"
set_var EASYRSA_REQ_EMAIL      "admin@cyberdefenselab.local"
set_var EASYRSA_REQ_OU         "Training"
set_var EASYRSA_KEY_SIZE       2048
set_var EASYRSA_CA_EXPIRE      3650
set_var EASYRSA_CERT_EXPIRE    365
```

### Step 1.3: Build the Certificate Authority

```bash
# Initialize the PKI
./easyrsa init-pki

# Build the CA (you will be prompted for a CA passphrase — remember it)
./easyrsa build-ca
```

When prompted for the Common Name, enter: `Cyber Defense Lab CA`

### Step 1.4: Generate Server Certificate and Key

```bash
# Generate server certificate request (nopass = no password on the key)
./easyrsa gen-req server nopass

# Sign the server certificate
./easyrsa sign-req server server
```

Type `yes` when prompted to confirm the signing, and enter the CA passphrase.

### Step 1.5: Generate Diffie-Hellman Parameters

```bash
# Generate DH parameters (this takes several minutes)
./easyrsa gen-dh
```

### Step 1.6: Generate Client Certificate

```bash
# Generate a client certificate for WS01
./easyrsa gen-req client1 nopass

# Sign the client certificate
./easyrsa sign-req client client1
```

### Step 1.7: Generate TLS Authentication Key

```bash
# Generate HMAC key for additional security
openvpn --genkey secret ~/openvpn-ca/ta.key
```

### Step 1.8: Copy Certificates to OpenVPN Directory

```bash
# Copy required files to OpenVPN config directory
sudo cp ~/openvpn-ca/pki/ca.crt /etc/openvpn/server/
sudo cp ~/openvpn-ca/pki/issued/server.crt /etc/openvpn/server/
sudo cp ~/openvpn-ca/pki/private/server.key /etc/openvpn/server/
sudo cp ~/openvpn-ca/pki/dh.pem /etc/openvpn/server/
sudo cp ~/openvpn-ca/ta.key /etc/openvpn/server/
```

### Step 1.9: Configure the OpenVPN Server

Create the server configuration file:

```bash
sudo nano /etc/openvpn/server/server.conf
```

Enter the following configuration:

```
# OpenVPN Server Configuration
port 1194
proto udp
dev tun

# Certificate paths
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0

# Network configuration
server 10.8.0.0 255.255.255.0
push "route 192.168.10.0 255.255.255.0"
push "dhcp-option DNS 192.168.10.5"

# Security settings
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2

# Connection settings
keepalive 10 120
max-clients 10

# Privilege reduction
user nobody
group nogroup
persist-key
persist-tun

# Logging
log-append /var/log/openvpn/server.log
verb 3
status /var/log/openvpn/status.log
```

Create the log directory:

```bash
sudo mkdir -p /var/log/openvpn
```

### Step 1.10: Enable IP Forwarding

For VPN clients to reach the LAN through the VPN server, IP forwarding must be enabled:

```bash
# Enable temporarily
sudo sysctl -w net.ipv4.ip_forward=1

# Enable permanently
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.d/99-openvpn.conf
sudo sysctl --system
```

### Step 1.11: Start the OpenVPN Service

```bash
sudo systemctl start openvpn-server@server
sudo systemctl enable openvpn-server@server

# Verify status
sudo systemctl status openvpn-server@server
```

Check that the tunnel interface was created:

```bash
ip addr show tun0
```

You should see the tun0 interface with the address 10.8.0.1/24.

**Capture a screenshot of the OpenVPN service running and the tun0 interface.**

### Step 1.12: Prepare Client Configuration

Create a client configuration file:

```bash
nano ~/client1.ovpn
```

```
client
dev tun
proto udp
remote 192.168.10.100 1194

# Security settings
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2
key-direction 1

# Connection settings
resolv-retry infinite
nobind
persist-key
persist-tun
verb 3

# Inline certificates (replace with actual certificate content)
<ca>
# Paste contents of ca.crt here
</ca>

<cert>
# Paste contents of client1.crt here
</cert>

<key>
# Paste contents of client1.key here
</key>

<tls-auth>
# Paste contents of ta.key here
</tls-auth>
```

Populate the inline certificates:

```bash
# Display certificates to copy into the .ovpn file
echo "=== CA Certificate ==="
cat ~/openvpn-ca/pki/ca.crt
echo "=== Client Certificate ==="
cat ~/openvpn-ca/pki/issued/client1.crt
echo "=== Client Key ==="
cat ~/openvpn-ca/pki/private/client1.key
echo "=== TLS Auth Key ==="
cat ~/openvpn-ca/ta.key
```

Copy the content of each certificate/key into the corresponding section of the .ovpn file.

> **Note:** Transfer the client1.ovpn file to WS01 securely. In a lab environment, you can use SCP, a shared folder, or a USB drive.
> 

### Step 1.13: Connect from the Client

On WS01, install the OpenVPN client (download from https://openvpn.net/community-downloads/) and import the client1.ovpn file.

1. Right-click the OpenVPN GUI icon in the system tray.
2. Select **Import > Import file…** and select client1.ovpn.
3. Right-click the OpenVPN icon again and select **Connect**.

Alternatively, if the OpenVPN client is installed at the command line:

```powershell
& "C:\Program Files\OpenVPN\bin\openvpn.exe" --config C:\path\to\client1.ovpn
```

### Step 1.14: Verify the VPN Tunnel

On WS01, verify the tunnel is established:

```powershell
# Check for the VPN adapter
ipconfig | Select-String "10.8.0"

# Ping the VPN server's tunnel address
ping 10.8.0.1

# Ping a LAN host through the tunnel
ping 192.168.10.5
```

On the Ubuntu server, verify the connection:

```bash
# Check connected clients
cat /var/log/openvpn/status.log

# Check server log for connection events
sudo tail -20 /var/log/openvpn/server.log
```

Record your verification results:

| Test | Result |
| --- | --- |
| Client received 10.8.0.x address |  |
| Ping to 10.8.0.1 (VPN server) |  |
| Ping to 192.168.10.5 (DC through tunnel) |  |
| Client listed in status.log |  |

**Capture a screenshot of the successful VPN connection and verification.**

### Knowledge Check: VPN Implementation

1. The OpenVPN server configuration specifies `cipher AES-256-GCM` and `auth SHA256`. What is the purpose of each setting?
    1. AES-256-GCM handles authentication; SHA256 handles encryption
    2. Both provide encryption; SHA256 is the fallback cipher
    3. **AES-256-GCM provides authenticated encryption for the data channel; SHA256 provides HMAC authentication for the control channel**
    4. AES-256-GCM compresses data; SHA256 verifies compression integrity
    
    💡
    AES-256-GCM is an authenticated encryption algorithm that provides both confidentiality (encryption) and integrity (authentication) for the data traveling through the tunnel. SHA256 is used as the HMAC algorithm for the control channel, which handles key exchange, session negotiation, and tunnel management. Together, they protect both the data and the control signaling.
    
2. Why does the server configuration include `tls-version-min 1.2`?
    1. TLS 1.2 is the only version OpenVPN supports
    2. Older TLS versions require more bandwidth
    3. **TLS versions earlier than 1.2 contain known vulnerabilities and should not be used for secure communications**
    4. TLS 1.2 enables compression for faster tunneling
    
    💡
    TLS 1.0 and 1.1 have known security weaknesses including susceptibility to BEAST, POODLE, and other attacks. Enforcing TLS 1.2 as the minimum version ensures that the VPN control channel negotiation uses only cryptographic protocols that meet current security standards. DoD environments typically require TLS 1.2 or higher.
    
3. The server configuration pushes `route 192.168.10.0 255.255.255.0` to clients. What does this accomplish?
    1. It blocks VPN clients from accessing the 192.168.10.0/24 network
    2. It changes the client’s default gateway to the VPN server
    3. **It adds a route on the client so that traffic destined for 192.168.10.0/24 is sent through the VPN tunnel instead of the client’s local gateway**
    4. It configures the VPN server to forward packets from the tunnel to the LAN
    
    💡
    The `push "route"` directive instructs connected VPN clients to add a routing table entry that directs traffic for the specified network through the VPN tunnel. Without this route, the client would attempt to reach 192.168.10.0/24 via its local gateway rather than through the encrypted tunnel, bypassing the VPN entirely.
    

---

## Exercise 2: Web Filtering with Squid Proxy

**Estimated Time:** 75 minutes

**ELO Mapping:** 8D.4, 8D.5, 8D.6, 8D.7

### Background

Web filtering proxies inspect and control web traffic based on policies. They provide several security functions: blocking access to malicious or unauthorized sites, logging all web activity for monitoring, and serving as a choke point for enforcing acceptable use policies. Per CWP 3-2.1, web proxies provide both **Security Alerting** and **Encrypted/Obfuscated Traffic Inspection** sensing capabilities.

### Step 2.1: Install Squid

On the Ubuntu server (192.168.10.100):

```bash
sudo apt update
sudo apt install -y squid
```

Verify the installation:

```bash
squid -v | head -3
sudo systemctl status squid
```

### Step 2.2: Back Up the Default Configuration

```bash
sudo cp /etc/squid/squid.conf /etc/squid/squid.conf.bak
```

### Step 2.3: Create Block Lists

Create domain block list files that Squid will reference:

```bash
# Create a directory for block lists
sudo mkdir -p /etc/squid/blocklists

# Create a malware domains block list
sudo tee /etc/squid/blocklists/malware.txt << 'EOF'
.malware-test.com
.malware-domain.net
.evil-download.com
.phishing-example.com
EOF

# Create a policy-restricted sites block list
sudo tee /etc/squid/blocklists/restricted.txt << 'EOF'
.gambling-site.com
.casino-example.com
.proxy-avoider.com
.anonymous-proxy.net
EOF

# Create an allowed domains list (for testing)
sudo tee /etc/squid/blocklists/allowed.txt << 'EOF'
.google.com
.microsoft.com
.ubuntu.com
EOF
```

### Step 2.4: Configure Squid

Replace the default Squid configuration with a security-focused configuration:

```bash
sudo nano /etc/squid/squid.conf
```

Enter the following configuration:

```
# ========================================
# Squid Proxy - Cyber Defense Lab Configuration
# ========================================

# Basic settings
http_port 3128
visible_hostname proxy.cyberdefenselab.local

# ----------------------------------------
# Access Control Lists (ACLs)
# ----------------------------------------

# Network ACLs
acl localnet src 192.168.10.0/24
acl vpn_clients src 10.8.0.0/24

# Port ACLs
acl SSL_ports port 443
acl Safe_ports port 80          # HTTP
acl Safe_ports port 443         # HTTPS
acl Safe_ports port 21          # FTP
acl Safe_ports port 70          # Gopher
acl Safe_ports port 210         # WAIS
acl Safe_ports port 1025-65535  # High ports
acl CONNECT method CONNECT

# Block list ACLs (load from external files)
acl malware_sites dstdomain "/etc/squid/blocklists/malware.txt"
acl restricted_sites dstdomain "/etc/squid/blocklists/restricted.txt"

# ----------------------------------------
# Access Rules (ORDER MATTERS - first match wins)
# ----------------------------------------

# Block malware domains first (highest priority)
http_access deny malware_sites

# Block policy-restricted domains
http_access deny restricted_sites

# Block unsafe ports
http_access deny !Safe_ports

# Block CONNECT to non-SSL ports
http_access deny CONNECT !SSL_ports

# Allow local network and VPN clients
http_access allow localnet
http_access allow vpn_clients

# Deny everything else
http_access deny all

# ----------------------------------------
# Logging Configuration
# ----------------------------------------

# Access log (who accessed what and when)
access_log /var/log/squid/access.log squid

# Cache log (proxy operational messages)
cache_log /var/log/squid/cache.log

# Log format customization for security monitoring
logformat security %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %un %Sh/%<a %mt "%{Referer}>h" "%{User-Agent}>h"

# ----------------------------------------
# Cache Settings (minimal for security focus)
# ----------------------------------------
cache_mem 64 MB
maximum_object_size 10 MB

# ----------------------------------------
# Privacy/Security Headers
# ----------------------------------------
via off
forwarded_for delete
```

### Step 2.5: Validate and Restart Squid

```bash
# Test configuration syntax
sudo squid -k parse

# If no errors, restart the service
sudo systemctl restart squid

# Verify status
sudo systemctl status squid
```

> **Troubleshooting:** If `squid -k parse` reports errors, check for typos in the configuration file. Common issues include missing quotes around file paths in ACL definitions and incorrect ACL names in access rules.
> 

**Capture a screenshot of the successful configuration parse and Squid running.**

### Step 2.6: Configure Client to Use Proxy

On WS01, configure the web browser or system proxy settings to use the Squid proxy:

**Option A: System-wide proxy via PowerShell:**

```powershell
# Set system proxy (Internet Explorer / Edge / Chrome will use this)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" `
    -Name ProxyEnable -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" `
    -Name ProxyServer -Value "192.168.10.100:3128"
```

**Option B: Test using curl from the Ubuntu server:**

```bash
# Test through the proxy from the local system
curl -x http://192.168.10.100:3128 http://www.google.com -I
```

### Step 2.7: Test Web Filtering

Test that the proxy correctly permits and blocks traffic:

**Test 1: Permitted traffic (should succeed):**

```bash
# From Ubuntu server or WS01 (through proxy)
curl -x http://192.168.10.100:3128 http://www.google.com -I -o /dev/null -w "%{http_code}\n"
curl -x http://192.168.10.100:3128 http://www.ubuntu.com -I -o /dev/null -w "%{http_code}\n"
```

**Test 2: Blocked malware domains (should return 403 Forbidden):**

```bash
curl -x http://192.168.10.100:3128 http://malware-test.com -I -o /dev/null -w "%{http_code}\n"
curl -x http://192.168.10.100:3128 http://evil-download.com -I -o /dev/null -w "%{http_code}\n"
```

**Test 3: Blocked restricted domains (should return 403 Forbidden):**

```bash
curl -x http://192.168.10.100:3128 http://gambling-site.com -I -o /dev/null -w "%{http_code}\n"
curl -x http://192.168.10.100:3128 http://proxy-avoider.com -I -o /dev/null -w "%{http_code}\n"
```

Record your test results:

| Test | Target | Expected Code | Actual Code | Pass/Fail |
| --- | --- | --- | --- | --- |
| Permitted: google.com | http://www.google.com | 200 |  |  |
| Permitted: ubuntu.com | http://www.ubuntu.com | 200 |  |  |
| Blocked: malware-test.com | http://malware-test.com | 403 |  |  |
| Blocked: evil-download.com | http://evil-download.com | 403 |  |  |
| Blocked: gambling-site.com | http://gambling-site.com | 403 |  |  |
| Blocked: proxy-avoider.com | http://proxy-avoider.com | 403 |  |  |

### Step 2.8: Review Proxy Logs

Examine the Squid access log to verify that both permitted and denied requests are logged:

```bash
# View recent access log entries
sudo tail -20 /var/log/squid/access.log

# Filter for denied requests
sudo grep "TCP_DENIED" /var/log/squid/access.log

# Filter for permitted requests
sudo grep "TCP_MISS\|TCP_HIT" /var/log/squid/access.log | tail -10
```

Each log entry includes the timestamp, response time, client IP, HTTP status code, URL, and access method. This data is critical for security monitoring and incident investigation.

**Capture a screenshot showing both permitted and denied entries in the access log.**

### Step 2.9: Configure Log Forwarding (Optional)

To forward Squid logs to Elasticsearch for centralized monitoring, configure Filebeat:

```bash
# Enable Filebeat's generic log input for Squid
sudo nano /etc/filebeat/filebeat.yml
```

Add a log input for Squid:

```yaml
filebeat.inputs:
-type: log
enabled:true
paths:
- /var/log/squid/access.log
tags:["squid","proxy"]
```

```bash
sudo systemctl restart filebeat
```

> **Note:** Filebeat does not include a dedicated Squid module by default. The log input method above forwards raw log lines. For field-level parsing, you can create an ingest pipeline in Elasticsearch or use Logstash.
> 

### Knowledge Check: Web Filtering

1. In the Squid configuration, the rule `http_access deny malware_sites` appears before `http_access allow localnet`. Why is this ordering important?
    1. Squid requires deny rules before allow rules due to a syntax requirement
    2. Allow rules cannot reference external file-based ACLs
    3. **Squid uses first-match processing, so placing deny rules before the allow rule ensures that malware domains are blocked even for internal users who would otherwise be permitted**
    4. The order does not matter; Squid evaluates all rules before making a decision
    
    💡
    Like firewall rules, Squid processes access rules from top to bottom and stops at the first match. If the `allow localnet` rule came first, all traffic from the local network would be permitted before the malware block rule is ever evaluated. Placing deny rules first ensures that security restrictions are enforced regardless of the source network.
    
2. The Squid configuration includes `forwarded_for delete` and `via off`. What security purpose do these settings serve?
    1. They improve proxy performance by reducing header processing
    2. They enable encrypted communication between the proxy and upstream servers
    3. **They prevent the proxy from revealing internal client IP addresses and the proxy’s existence to external web servers, reducing information disclosure**
    4. They block external servers from setting cookies on internal clients
    
    💡
    By default, proxies add `X-Forwarded-For` headers (revealing the client’s internal IP) and `Via` headers (revealing the proxy’s hostname) to outbound requests. Removing these headers prevents external servers from learning about your internal network structure, which is an information disclosure risk.
    
3. A user reports that they cannot access a website that should be permitted. Which log file do you check first, and what do you look for?
    1. /var/log/squid/cache.log for DNS resolution errors
    2. /var/log/syslog for Squid service failures
    3. **`/var/log/squid/access.log` for the specific request, checking the HTTP status code and whether it was tagged as TCP_DENIED or matched a block list**
    4. /etc/squid/squid.conf for syntax errors
    
    💡
    The access.log records every request processed by Squid, including the result code (TCP_DENIED, TCP_MISS, TCP_HIT). By searching for the user’s IP address and the target domain, you can determine if the request was blocked by a rule (and which one), denied due to authentication failure, or failed for another reason.
    

---

## Lab Completion Checklist

Before submitting this lab, verify:

**Exercise 1 (VPN):**
- [ ] OpenVPN and Easy-RSA installed
- [ ] PKI built: CA certificate, server certificate, client certificate, DH parameters, TLS auth key
- [ ] OpenVPN server configuration file created with AES-256-GCM and TLS 1.2 minimum
- [ ] IP forwarding enabled
- [ ] OpenVPN service running with tun0 interface active
- [ ] Client configuration file created with inline certificates
- [ ] VPN tunnel established from client
- [ ] Connectivity verified through tunnel (ping to VPN server and LAN hosts)
- [ ] Client visible in status.log

**Exercise 2 (Web Filtering):**
- [ ] Squid installed and default config backed up
- [ ] Block lists created (malware, restricted)
- [ ] Squid configuration written with ACLs and access rules
- [ ] Configuration validated (`squid -k parse`)
- [ ] Squid service running
- [ ] Client configured to use proxy
- [ ] Permitted traffic confirmed (HTTP 200)
- [ ] Blocked malware domains confirmed (HTTP 403)
- [ ] Blocked restricted domains confirmed (HTTP 403)
- [ ] Access log reviewed showing both permitted and denied entries
- [ ] All knowledge check questions answered
- [ ] All required screenshots captured

### Screenshots Required

1. OpenVPN service running and tun0 interface (Exercise 1, Step 1.11)
2. Successful VPN connection and tunnel verification (Exercise 1, Step 1.14)
3. Squid configuration parse success and service running (Exercise 2, Step 2.5)
4. Squid access log showing permitted and denied entries (Exercise 2, Step 2.8)

---

## Troubleshooting Guide

### VPN Issues

| Symptom | Possible Cause | Resolution |
| --- | --- | --- |
| OpenVPN service fails to start | Configuration syntax error | Check: `journalctl -u openvpn-server@server -n 50` |
| No tun0 interface | TUN device not available | Verify: `ls /dev/net/tun`; load module: `sudo modprobe tun` |
| Client cannot connect | Port 1194/UDP blocked | Check firewall: `sudo ufw status`; allow port: `sudo ufw allow 1194/udp` |
| Connected but cannot ping LAN | IP forwarding disabled | Verify: `sysctl net.ipv4.ip_forward` should be `1` |
| Certificate error on connection | CA/cert mismatch | Verify client cert was signed by the same CA as server cert |

### Web Filtering Issues

| Symptom | Possible Cause | Resolution |
| --- | --- | --- |
| Squid fails to start | Config syntax error | Run: `sudo squid -k parse` for details |
| All traffic blocked | ACL or access rule error | Verify `allow localnet` rule exists and `localnet` ACL matches client IP |
| Blocked sites still accessible | Client not using proxy | Verify proxy settings on client; test with `curl -x` |
| Block list not working | File path wrong in ACL | Verify: `ls -la /etc/squid/blocklists/malware.txt` |
| Log file empty | Permissions issue | Check: `ls -la /var/log/squid/`; fix: `sudo chown proxy:proxy /var/log/squid/` |

---

## Extension Challenges (Optional)

### Challenge 1: VPN Client Certificate Revocation

Revoke the client1 certificate using Easy-RSA and generate a Certificate Revocation List (CRL). Configure the OpenVPN server to check the CRL and verify that the revoked client can no longer connect.

```bash
cd ~/openvpn-ca
./easyrsa revoke client1
./easyrsa gen-crl
```

### Challenge 2: Transparent Proxy Configuration

Configure Squid as a transparent proxy using iptables to redirect HTTP traffic without requiring client proxy configuration:

```bash
sudo iptables -t nat -A PREROUTING -i ens33 -p tcp --dport 80 -j REDIRECT --to-port 3128
```

Document the advantages and disadvantages of transparent versus explicit proxy deployment.

### Challenge 3: Proxy Authentication

Configure Squid to require username/password authentication using the `basic_ncsa_auth` helper. Create test accounts and verify that unauthenticated requests are denied.

---

## Summary

In this lab, you deployed two critical cyber defense infrastructure components by:

1. **Building a PKI** using Easy-RSA, including a Certificate Authority, server certificate, and client certificate to support certificate-based VPN authentication
2. **Deploying an OpenVPN server** with AES-256-GCM encryption, SHA256 authentication, and TLS 1.2 minimum requirements that meet DoD cryptographic standards
3. **Establishing and verifying a VPN tunnel** from a Windows client, confirming encrypted communications and routing through the tunnel to LAN resources
4. **Deploying a Squid web filtering proxy** with domain-based block lists for malware and policy-restricted sites
5. **Configuring and testing access control rules** that enforce web filtering policies using first-match processing, consistent with firewall rule ordering principles
6. **Verifying logging** to ensure both permitted and denied web requests are recorded for security monitoring and audit compliance

These skills support the Cyber Defense Infrastructure Support Specialist role in deploying and maintaining VPN and web filtering infrastructure per DCWF requirements. The VPN implementation addresses K0148 (VPN security) and S0237 (VPN device usage), while the web filtering implementation addresses K0900 (web filtering technologies) and aligns with CWP 3-2.1 Security Alerting and Encrypted/Obfuscated Traffic Inspection sensing capabilities.

---

*Document Version: 1.0*

*Classification: UNCLASSIFIED // FOR TRAINING USE ONLY*