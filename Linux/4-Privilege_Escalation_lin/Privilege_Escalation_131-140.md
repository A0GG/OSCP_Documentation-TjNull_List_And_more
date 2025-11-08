## 🛡️ Privilege Escalation (Machines 131–140)

### Techniques Used

- **Sudo Rights Abuse**
  - Enumerated with `sudo -l`
  - Common allowed binaries: `nano`, `vim`, `awk`, `perl`, `python3`, `/bin/sh`

- **SUID Binary Exploitation**
  - Searched with: `find / -perm -4000 -type f 2>/dev/null`
  - Exploited binaries: `nmap`, `bash`, `vim`, `find`, custom binaries with root permissions

- **Capabilities Abuse**
  - Checked with: `getcap -r / 2>/dev/null`
  - `python3`, `perl` with cap_setuid/cap_net_bind_service

- **Writable Scripts/Timers**
  - Found writable scripts used in cron or systemd services
  - Injected payload for root shell

- **Kernel Exploits**
  - Used `uname -a` and searched vulnerable versions on `searchsploit`
  - Exploits like Dirty COW or OverlayFS

### Examples

- **Machine 132**
  - SUID binary `/usr/bin/find` allowed shell escape with `-exec`
- **Machine 135**
  - `sudo nano` NOPASSWD enabled → Escalated using `Ctrl-R + Ctrl-X`
- **Machine 138**
  - Writable systemd timer script led to privilege escalation

