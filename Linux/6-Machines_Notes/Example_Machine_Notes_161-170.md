## 🗒️ Example Machine Notes (Machines 161–170)

### Machine 161 – Recon
- Nmap revealed ports 21, 22, and 80.
- Found /backup directory via Gobuster.
- Logged in with FTP anonymous access and downloaded a zip file.

### Machine 162 – Web Enum
- /test.php found via dirb.
- File upload feature present but filters extensions.
- Uploaded shell using double extension bypass.

### Machine 163 – Initial Access
- CMS Made Simple identified.
- Used known exploit for CMS Made Simple to get shell.

### Machine 164 – Privilege Escalation
- User can run `less` with sudo.
- Used `!sh` inside less to escalate to root.

### Machine 165 – Recon
- Port 25 open and allows VRFY command.
- Found valid usernames using SMTP enumeration.

### Machine 166 – Web Enum
- Web application using outdated Joomla version.
- Exploited known RCE vulnerability.

### Machine 167 – Initial Access
- MySQL credentials leaked in PHP file.
- Logged into MySQL and executed UDF-based shell.

### Machine 168 – Privilege Escalation
- Found SUID binary for `vim`.
- Used `vim -c '!sh'` as root.

### Machine 169 – Recon
- SNMP enumeration revealed system info.
- Extracted running processes and user info.

### Machine 170 – Full Path
- Found sensitive backup in web root.
- Gained shell and escalated using kernel exploit.
