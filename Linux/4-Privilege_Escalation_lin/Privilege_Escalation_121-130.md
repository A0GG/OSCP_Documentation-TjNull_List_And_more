## 🛡️ Privilege Escalation (Machines 121–130)

```bash
# Sudo Checks
sudo -l
# SUID binaries
find / -perm -4000 -type f 2>/dev/null
# Capabilities
getcap -r / 2>/dev/null
# Kernel Exploits
uname -a
searchsploit linux kernel 5.x.x
# Interesting Cron Jobs
cat /etc/crontab
ls -la /etc/cron*
# PATH variable abuse
echo $PATH
```

### Observations from Machines:

- Machine 121: SUID binary `/usr/bin/find` allowed arbitrary command execution as root.
- Machine 122: User had sudo rights on `/usr/bin/python3`, leveraged for root shell.
- Machine 123: `cap_setuid+ep` on `/home/user/backup`, used to escalate privileges.
- Machine 124: Cron job running a writable script every minute → Replaced with reverse shell.
- Machine 125: Kernel 4.15.0 vulnerable to CVE-2022-0847 ("Dirty Pipe") → Local root.
- Machine 126: Misconfigured sudo allowed `awk` to run shell: `sudo awk 'BEGIN {system("/bin/bash")}'`.
- Machine 127: Docker group membership → Escaped to host.
- Machine 128: Exploitable SUID binary `/opt/customapp` allowed command injection.
- Machine 129: PATH hijacking via a script run by sudo without full paths.
- Machine 130: Password reuse on a privileged user account via SSH.

```
# Tip: Always re-check sudo privileges and SUID binaries after initial access!
```
