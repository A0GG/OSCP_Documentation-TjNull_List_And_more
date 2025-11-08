## 🛡️ Privilege Escalation (Machines 151–160)

### Common Techniques Used:

```bash
sudo -l                                     # Check for allowed sudo commands
find / -perm -4000 -type f 2>/dev/null       # Find SUID binaries
getcap -r / 2>/dev/null                      # Identify binaries with capabilities
pspy / linpeas / lse                         # Run enumeration scripts
```

### Escalation Vectors:

- SUID Binary Exploitation:
  - Abuse of misconfigured binaries like `cp`, `vim`, `find` with SUID bit set.

- Sudo Misconfigurations:
  - `sudo vim`, `sudo nmap`, `sudo awk`, or shell escapes to gain root.

- Cron Jobs:
  - Writable scripts executed by root via cron schedule.

- Weak Permissions:
  - Writable `/etc/passwd` or `/etc/shadow`.
  - Writable scripts sourced by systemd or profiles.

- Exploitable Capabilities:
  - `cap_setuid+ep` on python or bash.
  - Use `getcap` to identify these.

### Kernel Exploits:

```bash
uname -a                                   # Kernel version
searchsploit linux kernel <version>        # Check for known exploits
```

- Machines with privesc via kernel include:
  - Dirty COW (CVE-2016-5195)
  - OverlayFS exploit paths
  - CVE-2021-3156 (sudo buffer overflow)

### Exploits Used:

- CVE-2016-5195 (Dirty COW)
- CVE-2021-3156 (Baron Samedit)
- CVE-2022-0847 (Dirty Pipe)

> Note: Specific machines in this range reused common vectors from previous batches such as misconfigured `sudo`, `SUID` misuse, and vulnerable cron jobs.

