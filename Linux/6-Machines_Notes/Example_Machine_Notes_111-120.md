# 🗒️ Example Machine Notes (Machines 111–120)

---

### Machine 111
- Discovered open ports 80, 443.
- Found default WordPress installation on port 80.
- Used CVE-2021-29447 to get RCE via vulnerable plugin.
- PrivEsc via writable `/etc/passwd`.

---

### Machine 112
- Found login panel on port 8080.
- Brute-forced password with Hydra, gained access.
- Uploaded PHP reverse shell.
- PrivEsc via `sudo` misconfiguration with `vim`.

---

### Machine 113
- Port 21 open, anonymous FTP login enabled.
- Downloaded backup file with credentials.
- Used creds to SSH into system.
- PrivEsc via kernel exploit (dirtycow).

---

### Machine 114
- Open ports: 80, 3306.
- SQLi vulnerability in login form.
- Extracted hashes from database.
- Cracked and reused credentials via SSH.
- PrivEsc: SUID binary `/usr/bin/find`.

---

### Machine 115
- Apache Tomcat Manager exposed.
- Default creds worked: tomcat:tomcat.
- Deployed WAR file with web shell.
- PrivEsc via Docker escape.

---

### Machine 116
- NFS share misconfigured.
- Mounted share and wrote SSH key to `authorized_keys`.
- Gained shell as local user.
- Escalated to root via CVE-2021-4034 (PwnKit).

---

### Machine 117
- CMS Made Simple exposed.
- Exploited with CVE-2019-9053 for SQLi.
- Dumped user hash and cracked it.
- SSH access and escalation with `sudo nmap`.

---

### Machine 118
- LFI discovered in `download.php`.
- Used log poisoning to get RCE.
- Got user shell, escalated via PATH hijacking.

---

### Machine 119
- Samba service exposed.
- Used smbclient to list and retrieve sensitive config.
- Extracted credentials and used them for login.
- PrivEsc: Abused cron job writing to root-owned script.

---

### Machine 120
- Discovered vulnerable Jenkins instance.
- Exploited with script console to get reverse shell.
- PrivEsc via `cap_setuid` binary.