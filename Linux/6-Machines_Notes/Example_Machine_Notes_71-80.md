## 🗒️ Example Machine Notes (Machines 71–80)

---

### Machine 71
- Nmap revealed ports 80 and 22.
- Webpage hosted a vulnerable file upload form.
- Gained shell via PHP reverse shell.
- Privilege escalation via writable /etc/passwd.

---

### Machine 72
- Found Jenkins dashboard on port 8080.
- Gained initial access through anonymous login.
- Jenkins script console used for RCE.
- Root via CVE-2018-1000861.

---

### Machine 73
- Apache running with exposed server-status.
- Discovered admin panel via Gobuster.
- Command injection in backup script.
- Escalated via SUID binary /usr/bin/ht.

---

### Machine 74
- PHP application vulnerable to LFI.
- Log poisoning led to shell execution.
- Enumerated users via /etc/passwd.
- Root via CVE-2021-4034 (pwnkit).

---

### Machine 75
- CMS system found on port 80.
- Default creds worked: admin:admin.
- Plugin upload allowed web shell.
- Privilege escalation via misconfigured sudoers.

---

### Machine 76
- Subdomain pointing to dev panel.
- SSRF discovered via PDF preview.
- Accessed metadata endpoint → credentials leaked.
- Rooted via abusing systemctl privileges.

---

### Machine 77
- Exposed Samba shares allowed null access.
- Downloaded sensitive configs.
- Shell via user credential reuse on SSH.
- Escalated through cronjob script injection.

---

### Machine 78
- Found outdated Apache Tomcat manager.
- Bypassed authentication with default creds.
- Deployed WAR shell via manager app.
- Root access using dirty pipe exploit.

---

### Machine 79
- Port 3306 open → weak MySQL credentials.
- Gained shell through user-owned PHPMyAdmin interface.
- Used .bashrc persistence.
- Rooted using writable sudo Python script.

---

### Machine 80
- HTTP login page vulnerable to SQLi.
- Dumped user credentials using sqlmap.
- Logged in and uploaded reverse shell.
- Root via GTFOBin ‘vim’.

