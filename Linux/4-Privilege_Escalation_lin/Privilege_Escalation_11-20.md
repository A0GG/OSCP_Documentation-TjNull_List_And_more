## 🛡️ Privilege Escalation (Machines 11–20)

```bash
# SUID/SGID Enumeration
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# Capabilities Enumeration
getcap -r / 2>/dev/null

# Sudo Permissions
sudo -l

# Kernel Version
uname -a
searchsploit linux kernel <version>

# Interesting files
ls -la /root/
ls -la /home/

# Cron Jobs
cat /etc/crontab
ls -la /etc/cron*

# Environment variables
env

# PATH misconfiguration
echo $PATH
```

---

### Techniques & Findings:

- **GTFOBins**: Used for binaries found with SUID or sudo permissions.
- **Writable Scripts in Cron**: Overwritten scheduled jobs.
- **Kernel Exploits**: Kernel versions below 4.4 and 5.8.0 commonly targeted using public exploits.
- **Password Reuse**: Found in user shell history and config files.
- **Docker Privileges**: Users in docker group allowed to escape containers.
- **Capabilities**: `cap_setuid` and `cap_net_bind_service` often abused.
- **Sudo Misconfigurations**:
  - `awk`, `vim`, `less`, `tar`, `python`, `perl` with NOPASSWD
  - Exploited via GTFOBins

---

### Tools Used:

- `linpeas.sh`, `pspy64`, `les.sh`
- `GTFOBins`, `exploit-db`, `searchsploit`
- `gdb`, `gcc`, `python3`, `tar`, `find`, `awk`

---

### Notes:

- Most machines contained a custom binary or script with elevated permissions.
- Some boxes reused weak passwords across users.
- Multiple machines had writable `/etc/passwd` or `shadow` under container escapes.
