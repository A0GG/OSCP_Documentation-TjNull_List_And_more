
# Example Machine Notes (Machines 191–200)

### Example Machine 191:
- **Found:** /admin.php → Possible admin panel → Further enumeration needed.
- **Exploitation:** XSS vulnerability found on the admin page.
- **Privilege Escalation:** Exploited Sudoers file with NOPASSWD to escalate to root.

### Example Machine 192:
- **Found:** /config.php → Exposed configuration file.
- **Exploitation:** Used SQL injection on login page to gain access.
- **Privilege Escalation:** Discovered an SSH key in user directory, escalated privileges.

### Example Machine 193:
- **Found:** /uploads → Exposed upload directory with malicious file.
- **Exploitation:** Exploited directory traversal vulnerability to execute shell.
- **Privilege Escalation:** Found writable sudo script → Replaced with /bin/bash.

### Example Machine 194:
- **Found:** /backup → Backup files exposed.
- **Exploitation:** Cracked password hash found in config file.
- **Privilege Escalation:** Privileges escalated by modifying sudo configuration.

### Example Machine 195:
- **Found:** /robots.txt → Discovered sensitive paths.
- **Exploitation:** Exploited SSRF vulnerability to internal services.
- **Privilege Escalation:** SSH key found in exposed file, escalated to root.

### Example Machine 196:
- **Found:** /cgi-bin/test.cgi → Vulnerable CGI script.
- **Exploitation:** Command injection found in test.cgi.
- **Privilege Escalation:** Sudoers file misconfiguration → Privileges escalated.

### Example Machine 197:
- **Found:** /admin → Admin page accessible without authentication.
- **Exploitation:** Bypass authentication with default credentials.
- **Privilege Escalation:** Exploited weak sudo permissions to gain root access.

### Example Machine 198:
- **Found:** /api → Sensitive API exposed.
- **Exploitation:** Brute-forced API credentials for access.
- **Privilege Escalation:** Found writable cron job → Executed arbitrary code.

### Example Machine 199:
- **Found:** /wp-login.php → WordPress login page exposed.
- **Exploitation:** Exploited weak password on admin account.
- **Privilege Escalation:** Modified wp-config.php to escalate privileges.

### Example Machine 200:
- **Found:** /admin_area → Administrative panel.
- **Exploitation:** Found XSS vulnerability, executed payload.
- **Privilege Escalation:** Modified user permissions via panel to escalate privileges.

