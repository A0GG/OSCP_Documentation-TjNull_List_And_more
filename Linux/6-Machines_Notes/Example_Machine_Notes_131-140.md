## 🗒️ Example Machine Notes (Machines 131–140)

### Machine 131
- Found custom CMS revealing user credentials via exposed config.php
- Gained access with leaked creds, privesc via writable cron job

### Machine 132
- Login panel reveals admin:admin credentials
- Exploited LFI in image.php to read SSH private key
- Used `find / -perm -4000` to identify `nmap` SUID, escalated to root

### Machine 133
- FTP anonymous login allowed full directory listing
- Downloaded backup.zip containing DB creds
- Escalation via vulnerable backup script using tar wildcard injection

### Machine 134
- Joomla installation → CVE-2015-8562 exploit
- Obtained reverse shell through RCE
- PrivEsc using mysql client with sudo permissions

### Machine 135
- PHPMyAdmin login with default creds → dumped user passwords
- SSH login with reused credentials
- Found Docker group membership → escalated with docker escape

### Machine 136
- Web upload allowed PHP web shell via double extension
- User flag in `/home/dev`
- Sudo rights on Python → root shell with `sudo python3 -c 'import pty;pty.spawn("/bin/bash")'`

### Machine 137
- CMS revealed through `whatweb`, default login worked
- Found file inclusion bug in theme preview
- Escalated using SUID `vim` binary

### Machine 138
- SNMP enumeration revealed creds for user
- SSH login successful, escalated via `getcap /` revealing Python3 capabilities

### Machine 139
- NFS share mounted without auth → used to upload malicious script
- Cron job picked up malicious script and executed it
- Gained root through misconfigured NFS mount permissions

### Machine 140
- Port knocking sequence discovered from `/var/www/html`
- Gained SSH via discovered user credentials
- Privileges escalated using `sudo -l`, allowing `/usr/bin/awk`
