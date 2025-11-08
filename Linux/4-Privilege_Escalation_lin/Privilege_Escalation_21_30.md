## 🛡️ Privilege Escalation (Machines 21–30)

```bash
# General Enumeration
sudo -l                                 # Check sudo rights
find / -perm -4000 -type f 2>/dev/null # Look for SUID binaries
getcap -r / 2>/dev/null                # Check for Linux capabilities
ps aux                                 # Check for processes with unusual privileges
cat /etc/passwd                        # Look for unusual users
env                                    # Check environment variables

# Kernel Exploit Check
uname -r                               # Get kernel version
searchsploit linux kernel <version>   # Look for matching exploits

# Exploitation Vectors

## Machine: Tabby
- LXD group membership → privilege escalation using LXD container escape

## Machine: OpenAdmin
- User 'jimmy' had permission to execute /usr/bin/git as root → leveraged for GTFOBin git privesc

## Machine: Irked
- Hidden file in user's home contained a base64 encoded password → reused for root escalation

## Machine: Popcorn
- Exploitable sudo permission: user can run /bin/bash as root without password

## Machine: Nibbles
- User had sudo access to a script with world-write permission → edited script to spawn root shell

## Machine: CozyHosting
- 'backup.sh' cron job run as root and writable by low-priv user → replaced to escalate

## Machine: Broker
- Redis misconfiguration → RCE → root shell through cron persistence

## Machine: Magic
- Abused Python capabilities set on /usr/bin/python3.7m to escalate

## Machine: Pandora
- Service running as root accessible via user → reverse shell opened from it to escalate

## Machine: SwagShop
- Reused password found in Magento config to log in as root via SSH
```

### 📋 CVE Reference Table

```markdown
| Software       | CVE ID         | Vulnerability                                | Exploit Link        |
|----------------|----------------|----------------------------------------------|---------------------|
| LXD            | N/A            | LXD container privilege escalation           | GTFOBins            |
| Git            | N/A            | Sudo + git privilege escalation              | GTFOBins            |
| Python         | N/A            | Capabilities-based escalation via interpreter| GTFOBins            |
```

### 🗒️ Example Notes

```markdown
- Tabby: Escalated via LXD container mounting /root
- Nibbles: Writable script in sudo path → inserted reverse shell → root shell gained
- Popcorn: Used `sudo /bin/bash` as allowed command for root access
- Broker: Redis to cron escalation via writable /var/spool/cron
```
