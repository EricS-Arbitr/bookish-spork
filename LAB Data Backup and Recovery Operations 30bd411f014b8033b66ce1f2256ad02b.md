# LAB: Data Backup and Recovery Operations

Owner: Eric Starace
Last edited by: Eric Starace

# LAB: Data Backup and Recovery Operations

## Cyber Defense Infrastructure Support Specialist Course

| **Estimated Completion Time** | 3–4 hours |
| --- | --- |
| **Prerequisites** | Lesson 10; Lab 9A (System and Network Hardening); Windows Server administration; Basic Linux command line |
| **Lab Type** | Hands-on technical configuration |
| **Classification** | UNCLASSIFIED // FOR TRAINING USE ONLY |

---

## Terminal Learning Objective

Implement backup and recovery operations for Windows and Linux cyber defense systems by configuring scheduled backups, validating backup integrity, performing file and configuration recovery, executing a timed recovery drill, and documenting backup procedures with RTO/RPO targets.

## Enabling Learning Objectives

| ELO | Objective |
| --- | --- |
| 10A.1 | Install Windows Server Backup, configure a backup policy with system state and volume targets, perform a manual backup, and recover a deleted file |
| 10A.2 | Create and schedule a Linux backup script using tar with integrity verification, then test recovery to an alternate location |
| 10A.3 | Execute a timed recovery drill against a simulated configuration corruption and document backup procedures with RTO/RPO targets |

## KSAT Alignment

| KSAT ID | Type | Description |
| --- | --- | --- |
| K0029 | Knowledge (Additional) | Knowledge of data backup, types of backups (e.g., full, incremental), and recovery concepts and tools |
| T0769 | Task (Additional) | Perform system administration on specialized cyber defense applications and systems, to include backup and restoration |

---

## Lab Environment

| System | Role | IP Address |
| --- | --- | --- |
| Windows Server 2019/2022 | Member Server (SVR01) | 192.168.10.10 |
| Ubuntu Server 22.04 LTS | Linux Server (YOURSERVER) | 192.168.10.100 |

### Assumptions

- SVR01 has a secondary volume (D:) or available disk for backup storage. If no secondary volume exists, a network share or local directory can substitute.
- You have administrator access on SVR01 and sudo access on the Ubuntu server.
- Critical services (Elastic Stack, Zeek, Suricata, etc.) from previous labs may or may not be installed — the backup procedures apply regardless.

---

## Exercise 1: Windows Server Backup

**Estimated Time:** 60 minutes

**ELO Mapping:** 10A.1

### Step 1.1: Install Windows Server Backup

On SVR01, open an elevated PowerShell session:

```powershell
# Install the Windows Server Backup feature
Install-WindowsFeature Windows-Server-Backup -IncludeManagementTools

# Verify installation
Get-WindowsFeature Windows-Server-Backup
```

Confirm the Install State shows **Installed**.

### Step 1.2: Create a Test File for Recovery Verification

Create a known file that you will back up, delete, and then recover:

```powershell
# Create test directory and file
New-Item -Path "C:\CyberDefenseData" -ItemType Directory -Force
"Critical configuration data - backup verification test" | Out-File "C:\CyberDefenseData\config-baseline.txt"
"Sensor tuning parameters: threshold=500, window=60s" | Out-File "C:\CyberDefenseData\sensor-tuning.txt"

# Verify
Get-ChildItem C:\CyberDefenseData
```

### Step 1.3: Configure and Execute a Backup Policy

```powershell
# Create a new backup policy
$policy = New-WBPolicy

# Add system state
Add-WBSystemState -Policy $policy

# Add the C: volume
$volume = Get-WBVolume -VolumePath "C:"
Add-WBVolume -Policy $policy -Volume $volume

# Set backup target (D: volume — adjust if using a different target)
$target = New-WBBackupTarget -VolumePath "D:"
Add-WBBackupTarget -Policy $policy -Target $target

# Set schedule (daily at 21:00)
Set-WBSchedule -Policy $policy -Schedule 21:00

# Enable VSS full backup
Set-WBVssBackupOption -Policy $policy -VssFullBackup

# Apply the policy
Set-WBPolicy -Policy $policy

# Verify the policy
Get-WBPolicy | Format-List
```

Execute a manual backup now:

```powershell
# Start an immediate backup
Start-WBBackup -Policy (Get-WBPolicy)
```

> **Note:** The backup may take several minutes depending on the volume size. Monitor progress:
> 
> 
> ```powershell
> Get-WBJob -Previous 1
> ```
> 

After completion, verify the backup set:

```powershell
Get-WBBackupSet | Format-Table BackupTime, SnapshotId
```

**Capture a screenshot of the completed backup set.**

### Step 1.4: Perform File Recovery

Simulate a data loss and recover from backup:

```powershell
# Delete the test files
Remove-Item "C:\CyberDefenseData\config-baseline.txt" -Force
Remove-Item "C:\CyberDefenseData\sensor-tuning.txt" -Force

# Verify files are gone
Get-ChildItem C:\CyberDefenseData
```

Recover the files:

```powershell
# Get the most recent backup set
$backup = Get-WBBackupSet | Sort-Object BackupTime -Descending | Select-Object -First 1

# Recover the files to an alternate location
New-Item -Path "C:\Restored" -ItemType Directory -Force
Start-WBFileRecovery -BackupSet $backup `
    -SourcePath "C:\CyberDefenseData" `
    -TargetPath "C:\Restored\" -Recursive

# Verify recovery
Get-ChildItem C:\Restored\CyberDefenseData
Get-Content C:\Restored\CyberDefenseData\config-baseline.txt
```

Confirm the file content matches the original.

**Capture a screenshot showing the restored files and their content.**

### Knowledge Check: Windows Backup

1. The backup policy uses `Set-WBVssBackupOption -VssFullBackup`. What does VSS (Volume Shadow Copy Service) provide during backup?
    1. It compresses the backup data to reduce storage requirements
    2. It encrypts the backup to protect data at rest
    3. **It creates a point-in-time snapshot of the volume so files can be backed up consistently even if they are open or in use**
    4. It replicates the backup to a secondary location automatically
    
    💡
    VSS creates a consistent snapshot of the volume at the moment the backup begins. Without VSS, backing up files that are currently open by applications (such as databases, logs, or Active Directory) could result in corrupted or incomplete copies. The shadow copy captures the state of all files as they existed at the snapshot time, ensuring a reliable backup.
    

---

## Exercise 2: Linux Backup and Recovery

**Estimated Time:** 60 minutes

**ELO Mapping:** 10A.2

### Step 2.1: Create the Backup Infrastructure

On the Ubuntu server (192.168.10.100):

```bash
sudo mkdir -p /backup/{scripts,data,logs}
```

### Step 2.2: Create the Backup Script

```bash
sudo nano /backup/scripts/backup.sh
```

```bash
#!/bin/bash
# Cyber Defense Appliance Backup Script
# Backs up critical configuration, logs, and application data

# Variables
BACKUP_DIR="/backup/data"
DATE=$(date +%Y%m%d_%H%M%S)
HOSTNAME=$(hostname)
RETENTION_DAYS=30
LOG_FILE="/backup/logs/backup_${DATE}.log"

# Directories to back up
BACKUP_DIRS="/etc /home /opt /var/log"

# Start logging
exec > >(tee -a "$LOG_FILE") 2>&1
echo "======================================"
echo "Backup Started:$(date)"
echo "======================================"

# Create full backup
BACKUP_FILE="${BACKUP_DIR}/${HOSTNAME}_full_${DATE}.tar.gz"
echo "Creating backup:$BACKUP_FILE"
tar -czf "$BACKUP_FILE" $BACKUP_DIRS 2>&1

# Verify and create checksum
if [ $? -eq 0 ]; then
    echo "Backup completed successfully"
    ls -lh "$BACKUP_FILE"
    sha256sum "$BACKUP_FILE" > "${BACKUP_FILE}.sha256"
    echo "Checksum created:$(cat ${BACKUP_FILE}.sha256)"
else
    echo "ERROR: Backup failed!"
    exit 1
fi

# Remove backups older than retention period
echo "Cleaning up backups older than$RETENTION_DAYS days..."
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete
find "$BACKUP_DIR" -name "*.sha256" -mtime +$RETENTION_DAYS -delete

echo "======================================"
echo "Backup Completed:$(date)"
echo "======================================"
```

```bash
sudo chmod +x /backup/scripts/backup.sh
```

### Step 2.3: Execute and Verify the Backup

```bash
# Run the backup
sudo /backup/scripts/backup.sh

# Verify the backup file exists
ls -lh /backup/data/

# Verify integrity
sudo sha256sum -c /backup/data/*.sha256
```

**Capture a screenshot of the backup completion output and checksum verification.**

### Step 2.4: Schedule the Backup with Cron

```bash
# Edit root's crontab
sudo crontab -e
```

Add the following line:

```
# Daily backup at 02:00
0 2 * * * /backup/scripts/backup.sh
```

Verify the cron entry:

```bash
sudo crontab -l
```

### Step 2.5: Create a Restore Script

```bash
sudo nano /backup/scripts/restore.sh
```

```bash
#!/bin/bash
# Cyber Defense Appliance Restore Script

if [ -z "$1" ]; then
    echo "Usage:$0 <backup_file> [target_directory]"
    echo ""
    echo "Available backups:"
    ls -lh /backup/data/*.tar.gz 2>/dev/null
    exit 1
fi

BACKUP_FILE=$1
TARGET_DIR=${2:-"/restore"}

# Verify checksum before restoring
echo "Verifying backup integrity..."
if [ -f "${BACKUP_FILE}.sha256" ]; then
    sha256sum -c "${BACKUP_FILE}.sha256"
    if [ $? -ne 0 ]; then
        echo "ERROR: Checksum verification failed! Backup may be corrupted."
        exit 1
    fi
    echo "Integrity verified."
else
    echo "WARNING: No checksum file found. Proceeding without verification."
fi

# Create target directory and extract
mkdir -p "$TARGET_DIR"
echo "Extracting to$TARGET_DIR..."
tar -xzf "$BACKUP_FILE" -C "$TARGET_DIR"

echo "Restore completed to:$TARGET_DIR"
ls -la "$TARGET_DIR"
```

```bash
sudo chmod +x /backup/scripts/restore.sh
```

### Step 2.6: Test Recovery

Simulate a data loss and recover:

```bash
# Create a test configuration file
echo "detection_threshold: 500" | sudo tee /etc/sensor-config.conf
echo "alert_email: admin@cyberdefenselab.local" | sudo tee -a /etc/sensor-config.conf

# Run a fresh backup
sudo /backup/scripts/backup.sh

# Delete the test file (simulate loss)
sudo rm /etc/sensor-config.conf

# Identify the latest backup
LATEST=$(ls -t /backup/data/*.tar.gz | head -1)

# Restore to an alternate location
sudo /backup/scripts/restore.sh "$LATEST" /tmp/restore_test

# Verify the recovered file
cat /tmp/restore_test/etc/sensor-config.conf
```

Confirm the content matches the original.

**Capture a screenshot of the restore verification.**

### Knowledge Check: Linux Backup

1. The backup script creates a SHA-256 checksum and the restore script verifies it before extracting. Why is this step critical for cyber defense systems?
    1. It speeds up the restore process by indexing the archive contents
    2. It compresses the backup more efficiently
    3. **It confirms the backup has not been corrupted or tampered with since creation, ensuring that a restore does not introduce compromised data into the environment**
    4. It converts the tar archive to a more portable format
    
    💡
    In a cyber defense environment, a corrupted or tampered backup is worse than no backup at all — restoring compromised data could reintroduce malware or attacker modifications. The SHA-256 checksum verifies that the backup file is bit-for-bit identical to when it was created. If an attacker modifies the backup (or storage corruption occurs), the checksum will not match, alerting the administrator before the compromised data is restored.
    

---

## Exercise 3: Recovery Drill and Documentation

**Estimated Time:** 60 minutes

**ELO Mapping:** 10A.3

### Part 3A: Timed Recovery Drill

This drill simulates recovering a corrupted SSH configuration from backup, the type of recovery a Cyber Defense Infrastructure Support Specialist would perform after an incident or accidental misconfiguration.

**Scenario:** The Linux server’s `/etc/ssh/sshd_config` has been corrupted. SSH connections are failing. Recover the configuration from the most recent backup and restore service.

**Step 1: Simulate the corruption:**

```bash
# Save the real config (safety net)
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.safety

# Corrupt the config
echo "CORRUPTED - invalid configuration" | sudo tee /etc/ssh/sshd_config
```

**Step 2: Begin the timed drill:**

```bash
START_TIME=$(date +%s)
echo "Recovery drill started:$(date)"
```

**Step 3: Identify the latest backup:**

```bash
BACKUP=$(ls -t /backup/data/*.tar.gz | head -1)
echo "Using backup:$BACKUP"
```

**Step 4: Verify backup integrity:**

```bash
sudo sha256sum -c "${BACKUP}.sha256"
```

**Step 5: Extract the specific file from the backup:**

```bash
# Extract only sshd_config to a temporary location
sudo tar -xzf "$BACKUP" -C /tmp/drill_restore ./etc/ssh/sshd_config
```

> **Note:** You can extract a single file from a tar archive by specifying its path. This is faster than extracting the entire backup.
> 

**Step 6: Restore the file and restart the service:**

```bash
# Restore the config
sudo cp /tmp/drill_restore/etc/ssh/sshd_config /etc/ssh/sshd_config

# Validate config syntax
sudo sshd -t

# Restart SSH
sudo systemctl restart sshd
```

**Step 7: Verify recovery:**

```bash
# Confirm SSH is running
sudo systemctl status sshd | head -5

# End timer
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
echo "Recovery drill completed:$(date)"
echo "Total recovery time:${ELAPSED} seconds"
```

Record your drill results:

| Metric | Value |
| --- | --- |
| Start time |  |
| End time |  |
| Total recovery time (seconds) |  |
| Backup integrity verified | Y / N |
| Service restored successfully | Y / N |

**Step 8: Clean up:**

```bash
# Restore the safety copy (if the drill config was from a lab backup without real SSH hardening)
sudo cp /etc/ssh/sshd_config.safety /etc/ssh/sshd_config
sudo systemctl restart sshd
rm -rf /tmp/drill_restore
```

**Capture a screenshot of the recovery time and service verification.**

### Part 3B: Backup Documentation

Complete the following documentation. This format supports operational accountability and the mission assurance construct by recording what is backed up, how quickly it can be recovered, and whether current capabilities meet recovery objectives.

**Backup Inventory:**

| System | IP Address | Backup Tool | Backup Type | Schedule | Location | Retention |
| --- | --- | --- | --- | --- | --- | --- |
| SVR01 (Windows) | 192.168.10.10 | Windows Server Backup | Full + System State | Daily 21:00 | D:\ | 30 days |
| YOURSERVER (Linux) | 192.168.10.100 | tar/cron script | Full (tar.gz) | Daily 02:00 | /backup/data | 30 days |

**Recovery Procedures Quick Reference:**

| Scenario | System | Command / Steps | Estimated Time |
| --- | --- | --- | --- |
| File recovery | Windows | `Start-WBFileRecovery -BackupSet $backup -SourcePath "path" -TargetPath "dest" -Recursive` | 15 min |
| System state recovery | Windows | Boot to recovery media > Troubleshoot > System Image Recovery | 1–2 hours |
| Single file recovery | Linux | `tar -xzf backup.tar.gz -C /target ./path/to/file` | 5 min |
| Full system recovery | Linux | Boot live media > restore tar > reinstall GRUB | 1–2 hours |

**RTO/RPO Assessment:**

| System | RTO Target | RPO Target | Current RTO Capability | Current RPO Capability | Meets Target? |
| --- | --- | --- | --- | --- | --- |
| SVR01 | 2 hours | 24 hours |  | 24 hours (daily backup) |  |
| YOURSERVER | 2 hours | 24 hours | (your drill time) | 24 hours (daily backup) |  |

> Fill in “Current RTO Capability” using your recovery drill time for the Linux server, and your estimate for the Windows server based on the file recovery exercise.
> 

### Knowledge Check: Recovery Operations

1. Your recovery drill took 90 seconds to restore a single configuration file from backup. The system’s RTO target is 2 hours. Does this mean the RTO is comfortably met?
    1. Yes — 90 seconds is well under 2 hours, so no further testing is needed
    2. **Restoring a single file is much faster than a full system recovery; meeting the RTO requires testing the worst-case scenario (full system restore with OS reinstallation, application reconfiguration, and data restoration)**
    3. No — RTO is measured in business hours, not elapsed time
    4. Yes — if one file can be restored in 90 seconds, the full system can be restored in proportional time
    
    💡
    RTO measures the maximum acceptable downtime for the entire system, not a single file. A single-file restore from a tar archive is fast because it skips most of the archive. A full system recovery involves booting from recovery media, reinstalling the OS (or restoring a system image), extracting the complete backup, reconfiguring services, and verifying functionality. Each step adds time. Regular drill testing at multiple recovery scenarios (single file, single service, full system) provides realistic RTO data.
    

---

## Lab Completion Checklist

**Exercise 1 — Windows Backup:**
- [ ] Windows Server Backup feature installed
- [ ] Test files created in C:
- [ ] Backup policy configured (system state + C: volume, daily schedule, VSS)
- [ ] Manual backup completed successfully
- [ ] Backup set verified with `Get-WBBackupSet`
- [ ] Test files deleted and recovered to C:
- [ ] Recovered file content verified

**Exercise 2 — Linux Backup:**
- [ ] Backup directory structure created
- [ ] Backup script created and executable
- [ ] Backup executed successfully
- [ ] SHA-256 checksum created and verified
- [ ] Cron job scheduled for daily 02:00
- [ ] Restore script created and executable
- [ ] Test file backed up, deleted, and successfully recovered
- [ ] Recovered file content verified

**Exercise 3 — Recovery Drill and Documentation:**
- [ ] SSH config corruption simulated
- [ ] Backup integrity verified before restore
- [ ] Single file extracted from tar archive
- [ ] SSH service restored and verified
- [ ] Recovery time recorded
- [ ] Backup inventory completed
- [ ] Recovery procedures documented
- [ ] RTO/RPO assessment completed
- [ ] All knowledge check questions answered

### Screenshots Required

1. Windows backup set showing completed backup (Exercise 1)
2. Windows file recovery — restored files and content (Exercise 1)
3. Linux backup completion and checksum verification (Exercise 2)
4. Linux restore verification — recovered file content (Exercise 2)
5. Recovery drill — total time and service status (Exercise 3)

---

## Troubleshooting Guide

| Symptom | Possible Cause | Resolution |
| --- | --- | --- |
| `Install-WindowsFeature` fails | Missing admin rights | Run PowerShell as Administrator |
| WSB backup fails — no target | D: volume not available | Use a network share: `New-WBBackupTarget -NetworkPath "\\server\share"` |
| `Start-WBFileRecovery` not finding files | Wrong SourcePath | Use exact path from backup; check with `Get-WBBackupVolumeBrowsePath` |
| Linux backup script fails | Permission denied | Verify script has `+x` permission; run with `sudo` |
| sha256sum verification fails | Backup file corrupted or modified | Re-run the backup; check disk health with `smartctl` |
| tar extraction fails for single file | Wrong path format | Path must match archive structure (e.g., `./etc/ssh/sshd_config` with leading `./`) |
| Cron job not running | Syntax error or wrong crontab | Verify with `sudo crontab -l`; check syslog: `grep CRON /var/log/syslog` |

---

## Summary

In this lab you implemented backup and recovery operations for cyber defense systems by:

1. **Configuring Windows Server Backup** with a scheduled policy covering system state and data volumes, executing a manual backup, and recovering deleted files from the backup set
2. **Creating a Linux backup solution** using a shell script with tar compression, SHA-256 integrity verification, automated scheduling via cron, and a restore script with checksum validation
3. **Executing a timed recovery drill** to restore a corrupted SSH configuration from backup, and documenting backup procedures with RTO/RPO targets to support mission assurance

These capabilities address KSAT K0029 (knowledge of data backup types and recovery concepts) and T0769 (system administration including backup and restoration of cyber defense systems).

---

*Document Version: 1.0*

*Classification: UNCLASSIFIED // FOR TRAINING USE ONLY*