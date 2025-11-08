## 🔓 Initial Access (Machines 81–90)

```bash
# Web Shell Uploads
- Attempted to upload `.php` or `.jsp` reverse shells via exposed file upload endpoints.
- Tested content-type bypasses and filename tricks (e.g., `shell.php.jpg`, `shell.pHp`, `.htaccess` rewriting).

# Exploits
- Used CVE-2018-7600 (Drupalgeddon2) on machines running Drupal.
- WordPress REST API (CVE-2017-1001000) for unauthenticated post injection.
- PHPMailer RCE on outdated systems with CVE-2016-10033.

# Exposed Configuration Files
- Retrieved database credentials from `/config.php`, `.env`, and `wp-config.php`.
- Looked for saved backups like `database.sql.bak`, `config.old`, etc.

# Authentication Bypass
- Tried common SQL injection payloads like `' OR 1=1--` on login forms.
- Forced browsing to `/admin` or `/dashboard` pages without auth.

# SSH Credential Reuse
- Used cracked credentials to log into SSH on open port 22.
- Enumerated for password reuse between web apps and system users.

# CMS Admin Panels
- Default creds: `admin:admin`, `admin:password`
- Exploited misconfigured plugins/themes to gain access.

# Common Tools Used
wpscan --url http://<target> --enumerate u,vp,vt
droopescan scan drupal -u http://<target>
```
