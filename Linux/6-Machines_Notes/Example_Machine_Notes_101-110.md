## 🗒️ Example Machine Notes (Machines 101–110)

### Machine 101
- Found exposed `/info.php`, led to PHP info leak and potential RCE.
- Exploited command injection via vulnerable API endpoint.
- Privilege escalation through misconfigured Docker group membership.

### Machine 102
- Directory brute-force revealed `/config_backup/` with DB creds.
- Used credentials to access admin panel and gain shell.
- SUDO access on `python3` allowed root escalation.

### Machine 103
- Discovered LFI vulnerability on `/logviewer.php`.
- Log poisoning used to gain initial access.
- Cronjob abuse allowed privilege escalation.

### Machine 104
- FTP anonymous login enabled, leaked website backup.
- Discovered hardcoded database credentials in backup.
- Root access gained via SUID binary exploitation.

### Machine 105
- Wordpress with vulnerable plugin (CVE-2021-24284).
- Reverse shell through plugin edit.
- Root via writable systemd service file.

### Machine 106
- Port 8080 served Jenkins, default creds worked.
- Reverse shell through Jenkins Script Console.
- Privilege escalation via vulnerable kernel exploit.

### Machine 107
- Web app had insecure deserialization vulnerability.
- Gained shell using crafted serialized payload.
- Escalated via `sudo -l` with `vim` allowed as root.

### Machine 108
- Open Redis port without authentication.
- Wrote SSH key to authorized_keys.
- Root through PATH variable manipulation.

### Machine 109
- CMS identified as vulnerable Joomla version.
- Exploited SQLi to extract credentials and gain access.
- Root escalation through NFS misconfiguration.

### Machine 110
- Mail server misconfiguration exposed admin credentials.
- Reverse shell via webmail plugin.
- Privilege escalation through SUID `nmap`.
