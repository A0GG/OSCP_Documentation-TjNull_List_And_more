## 🗒️ Example Machine Notes (Machines 11–20)

### Machine 11: Tartarsauce
- Found /wordpress → Enumerated using wpscan.
- Exploited vulnerable Wordpress plugin to get shell.
- PrivEsc via custom script in `/etc/init.d/`.

### Machine 12: Jarvis
- Exposed /admin.php → SQL injection → Dumped credentials.
- Gained access to admin panel → RCE via command injection.
- Sudo access to `/bin/systemctl` allowed privilege escalation.

### Machine 13: Tabby
- Discovered LFI via Tomcat logs.
- Retrieved archived credentials and reused them for login.
- PrivEsc via lxd group membership.

### Machine 14: Usage
- Web enum revealed dashboard using outdated PHPMyAdmin.
- SQLi allowed DB dump of credentials.
- Docker socket abuse for root escalation.

### Machine 15: Mentor
- Web server hosted vulnerable upload portal.
- Uploaded PHP web shell bypassing filters.
- Sudo access to a Python script for privesc.

### Machine 16: Devvortex
- Identified outdated GitLab instance.
- Used known GitLab RCE to get shell.
- Rooted via abusing custom backup script with writable config.

### Machine 17: Irked
- Enumerated IRC port (6697) open.
- Exploited Irked backdoor via custom script.
- Used SUID binary to escalate privileges.

### Machine 18: Popcorn
- Found upload page that accepted .rar files.
- Unpacked payload via server-side extraction flaw.
- PrivEsc by exploiting old kernel vulnerability (dirtycow).

### Machine 19: Bashed
- Found developer’s shell scripts in web root.
- Used reverse shell via one of the scripts.
- Escalated via writable cron job running as root.

### Machine 20: Broker
- Web panel exposed on port 8080, default creds used.
- Discovered RCE via form input handling.
- Rooted by overwriting a script executed by root via sudo.