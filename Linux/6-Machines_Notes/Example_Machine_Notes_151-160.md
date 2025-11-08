## 🗒️ Example Machine Notes (Machines 151–160)

### Machine 151
- Found open ports 80 and 22.
- Web service revealed a CMS with an outdated plugin.
- Exploited vulnerable plugin to gain initial access.
- Privilege escalation through writable cron job.

### Machine 152
- FTP anonymous login allowed file upload.
- Uploaded PHP shell and gained access.
- Used `sudo -l` to find accessible script for root escalation.

### Machine 153
- Nmap revealed HTTP and MySQL services.
- SQLi vulnerability in login page exploited.
- Retrieved DB credentials, reused for SSH.
- Root via binary with SUID bit set.

### Machine 154
- Custom web app exposed via port 8080.
- LFI vulnerability allowed reading /etc/passwd.
- Used LFI + log poisoning for RCE.
- Escalated with `cap_setuid+ep` binary.

### Machine 155
- SMB enumeration exposed sensitive file with credentials.
- Used creds to SSH in.
- `sudo` misconfiguration allowed execution of nmap.

### Machine 156
- Discovered old Joomla installation.
- Exploited known RCE to get shell.
- Rooted via kernel exploit due to outdated kernel.

### Machine 157
- SNMP enumeration revealed usernames.
- Bruteforced SSH and logged in.
- Used writable script owned by root to gain privilege.

### Machine 158
- WordPress admin panel exposed.
- Used default creds to log in.
- Uploaded PHP shell plugin.
- Rooted using sudo access to python.

### Machine 159
- Port 25 open; SMTP allowed VRFY commands.
- Found usernames, bruteforced SSH.
- Gained access, escalated via SUID vim binary.

### Machine 160
- HTTP service leaked credentials via robots.txt.
- SSH access using found creds.
- Escalated via Docker socket access.

