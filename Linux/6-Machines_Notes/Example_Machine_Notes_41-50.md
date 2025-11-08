## 🗒️ Example Machine Notes (Machines 41–50)

### Machine 41 – Fusion
- Recon: Open ports 80, 443; Apache server with WebDAV.
- Web Enum: Found WebDAV misconfig → upload .jsp shell.
- Initial Access: Triggered shell upload via browser.
- PrivEsc: Unquoted service path → write permissions → escalated to SYSTEM.

### Machine 42 – Retired
- Recon: Ports 445, 135, 3389 open.
- Web Enum: No web service, SMB enumeration reveals shared folders.
- Initial Access: Found credentials in backup.zip.
- PrivEsc: User in Remote Desktop Users group, RDP in → token impersonation.

### Machine 43 – Zab
- Recon: Port 80 open → Zabbix frontend.
- Web Enum: Default credentials for Zabbix.
- Initial Access: Added remote command to create reverse shell.
- PrivEsc: Sudo permissions on /usr/bin/zabbix_agentd → abused to gain root.

### Machine 44 – Baby
- Recon: HTTP and SSH open, WordPress site hosted.
- Web Enum: XML-RPC abuse and credential reuse.
- Initial Access: SSH login with cracked credentials.
- PrivEsc: LinEnum → vulnerable cron job → injected script → root shell.

### Machine 45 – Enterprise
- Recon: LDAP, Kerberos services open.
- Web Enum: Internal documentation portal leaked LDAP credentials.
- Initial Access: Logged in over SMB with found creds.
- PrivEsc: AS-REP roasting → cracked hash → admin shell.

### Machine 46 – Trusted
- Recon: Port 8080 running Apache Tomcat.
- Web Enum: Default credentials for Tomcat manager.
- Initial Access: Deployed WAR file for reverse shell.
- PrivEsc: Found setuid binary → buffer overflow → root access.

### Machine 47 – Lustrous
- Recon: HTTPS portal; certificate reveals internal subdomain.
- Web Enum: Subdomain leads to dev panel → command injection.
- Initial Access: Exploited command injection to gain shell.
- PrivEsc: CVE-2021-3156 (sudoheap) used to escalate privileges.

### Machine 48 – Sweep
- Recon: SNMP enumeration revealed users.
- Web Enum: No significant findings; login portal brute-forced.
- Initial Access: Found user SSH keys via SNMP.
- PrivEsc: Writable /etc/shadow → inserted new root hash.

### Machine 49 – Reflection
- Recon: Port 80 open, Laravel-based app.
- Web Enum: Debug mode enabled → RCE via exposed logs.
- Initial Access: Laravel RCE chain.
- PrivEsc: Kernel exploit based on uname -r output.

### Machine 50 – Heron
- Recon: Jenkins hosted on port 8080.
- Web Enum: Anonymous login allowed.
- Initial Access: Created Jenkins job → reverse shell.
- PrivEsc: User had sudo access to python → gained root shell.
