## 🗒️ Example Machine Notes (Machines 31–40)

- **Magic (HTB)**:
  - Found a file upload form with weak validation → Uploaded PHP shell.
  - Used `sudo -l` → Discovered user can run `/usr/bin/python` as root → Got root.

- **Help (HTB)**:
  - Open HelpDeskZ installation → CVE-2016-9482 exploited via file upload.
  - PrivEsc: SUID binary abuse with `cp` → Copied bash and gained root shell.

- **Editorial (HTB)**:
  - Discovered Gitea exposed admin panel → Used default credentials.
  - Enumeration revealed reused SSH credentials → Accessed user shell.
  - PrivEsc via weak permissions on `docker.sock`.

- **Builder (HTB)**:
  - Upload feature with RCE via `.phar` → Achieved RCE.
  - Used `linpeas.sh` → Found misconfigured cron jobs → Replaced script and escalated.

- **LinkVortex (HTB)**:
  - SSRF in link preview functionality → Accessed internal admin panel.
  - Extracted AWS metadata → Gained user credentials → SSH access.
  - Escalated using exposed AWS keys in environment variables.

- **Dog (PG)**:
  - Port 8000 running Werkzeug debugger → Remote code execution.
  - Discovered Docker environment → Used Docker breakout for root.

- **Underpass (PG)**:
  - Found hardcoded credentials in `.env` file.
  - Gained web shell and enumerated system users.
  - PrivEsc via writable `systemctl` service file.

- **ClamAV (PG)**:
  - Outdated ClamAV version → Used public exploit for LPE.
  - Access gained via weak web login credentials.

- **Pelican (PG)**:
  - CMS vulnerable to SQL Injection → Dumped credentials.
  - Reused password for SSH → Root via vulnerable script with sudo.

- **Payday (PG)**:
  - Apache Struts 2 RCE → Reverse shell.
  - `sudo -l` showed unrestricted Python → Escalated to root.
