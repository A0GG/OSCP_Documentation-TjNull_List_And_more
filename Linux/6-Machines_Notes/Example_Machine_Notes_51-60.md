# 🗒️ Example Machine Notes (Machines 51–60)

```
Machine: Bratarina
- Recon: Found /login endpoint with error-based SQLi.
- Exploit: Used SQLmap to extract user credentials from database.
- Initial Access: Logged in with dumped creds → Admin panel → RCE via command injection.
- PrivEsc: Found writable script in /etc/cron.d executing with root → Added reverse shell.

Machine: Pebbles
- Recon: Identified vulnerable CMS with default creds.
- Exploit: Used file upload bypass to upload web shell.
- PrivEsc: Kernel exploit based on outdated version.

Machine: Nibbles (PG)
- Recon: Nibbleblog with exposed admin panel.
- Exploit: Default creds admin:nibbles → Upload malicious plugin.
- PrivEsc: Sudo permission on /home/nibbler/monitor.sh → Replaced with bash shell.

Machine: Hetemit
- Recon: Directory brute force reveals backup.zip.
- Exploit: Extracted passwords from backup → SSH access.
- PrivEsc: Found binary with SUID and buffer overflow vulnerability.

Machine: ZenPhoto
- Recon: ZenPhoto version outdated.
- Exploit: Authenticated RCE via image upload bypass.
- PrivEsc: Writable /etc/passwd → Added root user.

Machine: Nukem
- Recon: Found webmin panel on port 10000.
- Exploit: Webmin RCE using Metasploit.
- PrivEsc: Found credentials in config → SSH root login.

Machine: Cockpit
- Recon: Open port 9090 running Cockpit service.
- Exploit: RCE via command injection in dashboard.
- PrivEsc: Abused SUID binary cockpit-root for privilege escalation.

Machine: Clue
- Recon: Apache server leaks .git directory.
- Exploit: Recovered credentials from commit history.
- PrivEsc: Used leaked credentials to access root cron job file.

Machine: Extplorer
- Recon: File management app found on web root.
- Exploit: Directory traversal vulnerability → Retrieved sensitive configs.
- PrivEsc: Sudo access to /usr/bin/php → Spawned shell via PHP script.

Machine: Postfish
- Recon: Found exposed admin interface via gobuster.
- Exploit: SSRF leading to internal API → Gained JWT.
- PrivEsc: Used JWT to impersonate root via API → SSH access.
```