## 🗒️ Example Machine Notes (Machines 121–130)

### Machine 121
- Discovered exposed WordPress login at `/wp-login.php`
- Exploited vulnerable plugin to get RCE
- Privilege escalation via writable script in `/etc/init.d`

### Machine 122
- Found open Redis instance on port 6379
- Loaded SSH key via Redis exploitation
- Escalated via vulnerable SUID binary

### Machine 123
- Nginx misconfiguration led to LFI
- Retrieved `/etc/passwd` and enumerated users
- Privilege escalation through PATH variable manipulation

### Machine 124
- Drupal CMS vulnerable to CVE-2018-7600
- Initial access with web shell
- Used logrotate binary for privilege escalation

### Machine 125
- Exposed `.git` directory revealed admin creds
- SSH login using recovered password
- Used `sudo -l` to find unrestricted `nmap` binary

### Machine 126
- Found FTP credentials in `robots.txt`
- Logged into FTP and uploaded PHP shell
- Root access via cronjob script in `/var/backups`

### Machine 127
- Exploited LFI and log poisoning to execute code
- Created reverse shell via poisoned logs
- Escalated via kernel exploit found via `searchsploit`

### Machine 128
- Enumerated subdomain with gobuster
- Found Node.js app with insecure deserialization
- Got root by abusing Docker socket

### Machine 129
- File upload bypass on `/upload.php`
- Uploaded web shell and gained reverse shell
- Rooted via writable `/etc/shadow` permissions

### Machine 130
- Found default MySQL creds, dumped database
- Reused password for SSH login
- Escalated with `LD_PRELOAD` bypass on custom binary
