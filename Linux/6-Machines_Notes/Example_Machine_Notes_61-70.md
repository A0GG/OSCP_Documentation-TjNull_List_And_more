## 🗒️ Example Machine Notes (Machines 61–70)

> These are summarized findings from machines 61–70 during the CTF/PG/THM challenges. Each note is generalized and sanitized for reusable knowledge in Obsidian vaults.

---

### 💻 Machine A (Generalized from PG/HTB)
- Discovered `/dev_notes` directory via gobuster.
- Found leaked SSH private key in `dev_notes.txt`.
- Logged in via SSH using `ssh -i id_rsa user@<ip>`.
- PrivEsc: sudo rights on `/opt/script.py` which was writable — modified to spawn shell.

---

### 💻 Machine B
- CMS login panel found: `/cms/login.php`
- Used SQL injection on login form to bypass authentication.
- Extracted `config.php` for DB credentials.
- PrivEsc: Cron job overwriting script in `/etc/cron.hourly`.

---

### 💻 Machine C
- Samba enum revealed shared folder: `\targetackups`
- Recovered `.bak` file with base64-encoded credentials.
- Logged in with SMB creds, reused for SSH access.
- PrivEsc via writable `/usr/bin/mount` binary with NOPASSWD.

---

### 💻 Machine D
- Apache Tomcat Manager exposed at `/manager/html`.
- Default creds (`tomcat:s3cret`) worked.
- Deployed WAR reverse shell.
- Root via CVE-2016-3427 exploiting vulnerable kernel.

---

### 💻 Machine E
- Detected custom HTTP service running on port 5000.
- Performed fuzzing using ffuf, identified `/debug` endpoint.
- SSRF allowed internal service access → escalated to config leak.
- PrivEsc: `journalctl` trick using sudo access with environment variable injection.

---

### 💻 Machine F
- Webmin service on port 10000.
- Bruteforced login with hydra, accessed dashboard.
- Discovered file manager plugin enabled — uploaded shell.
- Rooted via CVE-2019-15107 exploit.

---

### 💻 Machine G
- Joomla site exposed on port 8080.
- CVE-2015-8562 (object injection) led to RCE.
- Lateral movement using stolen SSH key from `/var/www/config_backup/`.
- PrivEsc: SUID binary `backup_exec` with hardcoded root command.

---

### 💻 Machine H
- Nginx misconfigured reverse proxy exposed internal admin panel.
- Gained admin access using leaked session cookie.
- Modified system crontab to execute payload.
- Root access through misconfigured `rsync` job with root privileges.

---

### 💻 Machine I
- Wordpress plugin vulnerable to file upload bypass.
- Uploaded `.php5` shell and triggered with POST request.
- Dumped WP DB via `wp-config.php`.
- PrivEsc: Exploited Docker socket (`/var/run/docker.sock`) to spawn root container.

---

### 💻 Machine J
- OpenLDAP service with anonymous bind.
- Dumped user info and password hashes.
- Cracked LDAP password using hashcat.
- Rooted via exploit chaining sudo misconfiguration with `less` binary.

---

*Tags: #linux #ctf #walkthrough #examples #observation-notes #machines-61-70*
